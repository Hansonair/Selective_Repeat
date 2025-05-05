/* sr.c */
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include "emulator.h"
#include "sr.h"

/* ******************************************************************
   Selective Repeat (SR) protocol implementation with cumulative ACKs.
********************************************************************/

/* Constants (as per assignment) */
#define RTT  16.0       /* round trip time for timer */
#define WINDOWSIZE 6    /* sender/receiver window size */
#define SEQSPACE 7      /* sequence number space (>= WINDOWSIZE+1) */
#define NOTINUSE (-1)   /* acknum for data packets */

/* Compute checksum of a packet */
int ComputeChecksum(struct pkt packet) {
    int checksum = 0;
    checksum += packet.seqnum;
    checksum += packet.acknum;
    for (int i = 0; i < 20; i++)
        checksum += (int)packet.payload[i];
    return checksum;
}

/* Check if a packet is corrupted */
bool IsCorrupted(struct pkt packet) {
    return (packet.checksum != ComputeChecksum(packet));
}

/* Sender (A) state */
static struct pkt buffer[WINDOWSIZE];
static int windowbase;      /* index of window’s base (first unACKed) in buffer */
static int windowcount;     /* number of outstanding (unACKed) packets */
static int A_nextseqnum;    /* next sequence number to use */
static bool timer_running;  /* is timer active? */

/* A_output: called when layer 5 has data for A to send */
void A_output(struct msg message) {
    if (windowcount < WINDOWSIZE) {
        /* Construct packet */
        struct pkt sendpkt;
        sendpkt.seqnum = A_nextseqnum;
        sendpkt.acknum = NOTINUSE;
        for (int i = 0; i < 20; i++)
            sendpkt.payload[i] = message.data[i];
        sendpkt.checksum = ComputeChecksum(sendpkt);

        /* Buffer the packet at tail of window */
        int index = (windowbase + windowcount) % WINDOWSIZE;
        buffer[index] = sendpkt;
        windowcount++;

        /* Send packet */
        if (TRACE > 0)
            printf("----A: Sending packet %d\n", sendpkt.seqnum);
        tolayer3(A, sendpkt);

        /* (Re)start timer for window */
        if (timer_running)
            stoptimer(A);
        starttimer(A, RTT);
        timer_running = true;

        /* Advance sequence number */
        A_nextseqnum = (A_nextseqnum + 1) % SEQSPACE;
    } else {
        /* Window full: drop message */
        if (TRACE > 0)
            printf("----A: Window full, dropping message\n");
        window_full++;
    }
}

/* A_input: called when A receives an ACK from layer 3 */
void A_input(struct pkt packet) {
    /* Ignore corrupted ACKs */
    if (IsCorrupted(packet)) {
        if (TRACE > 0) printf("----A: Corrupted ACK received, ignoring\n");
        return;
    }
    if (TRACE > 0) printf("----A: Received ACK %d\n", packet.acknum);

    /* If there are outstanding packets */
    if (windowcount > 0) {
        /* Determine if ACK is within the window range (cumulative) */
        int seqfirst = buffer[windowbase].seqnum;
        int seqlast = buffer[(windowbase + windowcount - 1) % WINDOWSIZE].seqnum;
        bool inWindow;
        if (seqfirst <= seqlast) {
            inWindow = (packet.acknum >= seqfirst && packet.acknum <= seqlast);
        } else {
            /* wrap-around case */
            inWindow = (packet.acknum >= seqfirst || packet.acknum <= seqlast);
        }

        if (inWindow) {
            /* Cumulative ACK: compute how many packets are ACKed */
            int ackedCount;
            if (packet.acknum >= seqfirst) {
                ackedCount = packet.acknum - seqfirst + 1;
            } else {
                /* wrapped around */
                ackedCount = (SEQSPACE - seqfirst) + (packet.acknum + 1);
            }
            /* Slide window */
            windowbase = (windowbase + ackedCount) % WINDOWSIZE;
            windowcount -= ackedCount;
            new_ACKs += ackedCount;
            if (TRACE > 0)
                printf("----A: Sliding window forward by %d, new base at %d\n",
                       ackedCount, buffer[windowbase].seqnum);

            /* Restart or stop timer */
            if (windowcount > 0) {
                stoptimer(A);
                starttimer(A, RTT);
                timer_running = true;
            } else {
                stoptimer(A);
                timer_running = false;
            }
        } else {
            /* Duplicate ACK: retransmit first unacked packet */
            if (TRACE > 0)
                printf("----A: Duplicate ACK %d (not in window), retransmitting base %d\n",
                       packet.acknum, buffer[windowbase].seqnum);
            tolayer3(A, buffer[windowbase]);
            packets_resent++;
            /* Restart timer */
            stoptimer(A);
            starttimer(A, RTT);
            timer_running = true;
        }
    }
}

/* A_timerinterrupt: called when A's timer expires */
void A_timerinterrupt(void) {
    if (windowcount > 0) {
        /* Retransmit only the base packet */
        int seq = buffer[windowbase].seqnum;
        if (TRACE > 0) printf("----A: Timeout, resending packet %d\n", seq);
        tolayer3(A, buffer[windowbase]);
        packets_resent++;
        /* Restart timer */
        starttimer(A, RTT);
        timer_running = true;
    }
}

/* A_init: initialize A's state */
void A_init(void) {
    A_nextseqnum = 0;
    windowbase = 0;
    windowcount = 0;
    timer_running = false;
}

/* Receiver (B) state */
static struct pkt recv_buffer[SEQSPACE];
static bool recv_buffered[SEQSPACE];
static int expectedseqnum;
static int B_nextseqnum;

/* B_input: called when B receives a data packet from layer 3 */
void B_input(struct pkt packet) {
    struct pkt ackpkt;
    /* Prepare ACK packet skeleton */
    ackpkt.seqnum = B_nextseqnum;
    B_nextseqnum = (B_nextseqnum + 1) % 2;
    for (int i = 0; i < 20; i++)
        ackpkt.payload[i] = '0';

    if (!IsCorrupted(packet)) {
        int seq = packet.seqnum;
        int diff = (seq - expectedseqnum + SEQSPACE) % SEQSPACE;
        /* Check if seq is within receiver window */
        if (diff < WINDOWSIZE) {
            if (seq == expectedseqnum) {
                /* In-order: deliver and advance expected */
                if (TRACE > 0) printf("----B: In-order packet %d, delivering\n", seq);
                tolayer5(B, packet.payload);
                expectedseqnum = (expectedseqnum + 1) % SEQSPACE;
                /* Deliver any buffered next packets */
                while (recv_buffered[expectedseqnum]) {
                    if (TRACE > 0)
                        printf("----B: Delivering buffered packet %d\n", expectedseqnum);
                    tolayer5(B, recv_buffer[expectedseqnum].payload);
                    recv_buffered[expectedseqnum] = false;
                    expectedseqnum = (expectedseqnum + 1) % SEQSPACE;
                }
                /* ACK last delivered (expected-1) */
                ackpkt.acknum = (expectedseqnum + SEQSPACE - 1) % SEQSPACE;
            } else {
                /* Out-of-order but within window: buffer it */
                if (!recv_buffered[seq]) {
                    recv_buffered[seq] = true;
                    recv_buffer[seq] = packet;
                    if (TRACE > 0)
                        printf("----B: Out-of-order packet %d buffered\n", seq);
                }
                /* ACK last delivered (expected-1) */
                ackpkt.acknum = (expectedseqnum + SEQSPACE - 1) % SEQSPACE;
            }
        } else {
            /* Outside window (duplicate or stale): ignore */
            if (TRACE > 0)
                printf("----B: Packet %d outside window, ignoring\n", seq);
            ackpkt.acknum = (expectedseqnum + SEQSPACE - 1) % SEQSPACE;
        }
    } else {
        /* Corrupted packet: ignore and ACK last in-order */
        if (TRACE > 0)
            printf("----B: Packet corrupted, re-ACKing %d\n",
                   (expectedseqnum + SEQSPACE - 1) % SEQSPACE);
        ackpkt.acknum = (expectedseqnum + SEQSPACE - 1) % SEQSPACE;
    }

    /* Send ACK */
    ackpkt.checksum = ComputeChecksum(ackpkt);
    if (TRACE > 0)
        printf("----B: Sending ACK %d\n", ackpkt.acknum);
    tolayer3(B, ackpkt);
}

/* B_output: not used (simplex A->B) */
void B_output(struct msg message) {
    /* No action */
}

/* B_init: initialize B's state */
void B_init(void) {
    expectedseqnum = 0;
    B_nextseqnum = 1;
    for (int i = 0; i < SEQSPACE; i++)
        recv_buffered[i] = false;
}

/* B_timerinterrupt: not used in SR */
void B_timerinterrupt(void) { }
