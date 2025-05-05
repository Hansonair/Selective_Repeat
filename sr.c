#include <stdlib.h>
#include <stdio.h>
/* Avoid C99 features for compatibility: use int instead of bool */
#include "emulator.h"
#include "gbn.h"

/* External variables from emulator (for statistics and tracing) */
extern int total_ACKs_received;
extern int packets_resent;
extern int new_ACKs;
extern int packets_received;
extern int window_full;
extern int TRACE;

/* Additional statistic: total data delivered to layer 5 at B */
extern int total_data_received_at_B;
int total_data_received_at_B = 0;

/* Constants for protocol */
#define RTT 16.0           /* round trip time (must be 16.0 for submission) */
#define WINDOWSIZE 6       /* sender/receiver window size (must be 6 for submission) */
#define SEQSPACE 7         /* sequence number space size (at least WINDOWSIZE+1) */
#define NOTINUSE (-1)      /* value for unused fields (e.g., acknum in data packets) */

/* Compute checksum of a packet (same as in GBN) */
int ComputeChecksum(struct pkt packet) {
    int checksum = 0;
    int i;
    checksum = packet.seqnum;
    checksum += packet.acknum;
    for (i = 0; i < 20; i++) {
        checksum += (int) packet.payload[i];
    }
    return checksum;
}

/* Check if packet is corrupted by comparing checksums */
int IsCorrupted(struct pkt packet) {
    if (packet.checksum == ComputeChecksum(packet))
        return 0;
    else
        return 1;
}

/********* Sender (A) variables and functions ************/

/* Sender A's window buffer structure */
struct SR_sender_packet {
    struct pkt packet;
    int acked;   /* 1 if ACK received for this packet, 0 otherwise */
    int sent;    /* 1 if this packet has been sent and is awaiting ACK */
    /* Note: send_time could be tracked for per-packet timers if needed */
    float send_time;
};

/* Sender A static variables */
static struct SR_sender_packet A_buffer[SEQSPACE];
static int A_base;      /* base of A's send window (lowest outstanding seq) */
static int A_nextseq;   /* next sequence number to assign to new packet */

/* called from layer 5 (application layer), passed the message to be sent to other side */
void A_output(struct msg message) {
    /* If window is not full, send the new packet; otherwise, drop it due to window overflow */
    if (((A_nextseq + SEQSPACE - A_base) % SEQSPACE) < WINDOWSIZE) {
        struct pkt sendpkt;
        int i;
        /* Create packet with current next sequence number */
        sendpkt.seqnum = A_nextseq;
        sendpkt.acknum = NOTINUSE;
        for (i = 0; i < 20; i++) {
            sendpkt.payload[i] = message.data[i];
        }
        sendpkt.checksum = ComputeChecksum(sendpkt);
        /* Buffer the packet and mark it as sent (awaiting ACK) */
        A_buffer[A_nextseq].packet = sendpkt;
        A_buffer[A_nextseq].acked = 0;
        A_buffer[A_nextseq].sent = 1;
        A_buffer[A_nextseq].send_time = 0.0;
        /* Log packet send event (trace level > 1) */
        if (TRACE > 1)
            printf("----A: New message arrives, send window is not full, send new messge to layer3!\n");
        if (TRACE > 0)
            printf("Sending packet %d to layer 3\n", sendpkt.seqnum);
        tolayer3(A, sendpkt);
        /* Start the timer when the first packet in window is sent */
        if (A_base == A_nextseq) {
            starttimer(A, RTT);
        }
        /* Advance next sequence number */
        A_nextseq = (A_nextseq + 1) % SEQSPACE;
    } else {
        /* Window is full: cannot send new packet */
        if (TRACE > 0)
            printf("----A: New message arrives, send window is full\n");
        /* Window is full: count this drop for statistics */
        window_full++;
    }
}

/* called from layer 3, when a packet arrives for layer 4 at A (should be an ACK for this unidirectional protocol) */
void A_input(struct pkt packet) {
    int acknum, i, has_unacked;
    /* Received an ACK packet at A */
    if (!IsCorrupted(packet)) {
        /* ACK is valid (not corrupted) */
        if (TRACE > 0)
            printf("----A: uncorrupted ACK %d is received\n", packet.acknum);
        total_ACKs_received++;
        acknum = packet.acknum;
        /* Only process the ACK if it corresponds to an outstanding packet that is not yet acknowledged */
        if (A_buffer[acknum].sent && !A_buffer[acknum].acked) {
            /* Mark this packet as now acknowledged */
            A_buffer[acknum].acked = 1;
            if (TRACE > 0)
                printf("----A: ACK %d is not a duplicate\n", acknum);
            new_ACKs++;
            /* Slide the sender window forward for each consecutive ACKed packet at the base */
            while (A_buffer[A_base].sent && A_buffer[A_base].acked) {
                /* Free the packet at A_base and advance base */
                A_buffer[A_base].sent = 0;
                A_buffer[A_base].acked = 0;
                A_base = (A_base + 1) % SEQSPACE;
            }
            /* Check if any packets remain unACKed in window */
            has_unacked = 0;
            for (i = 0; i < WINDOWSIZE; i++) {
                int seq = (A_base + i) % SEQSPACE;
                if (A_buffer[seq].sent && !A_buffer[seq].acked) {
                    has_unacked = 1;
                    break;
                }
            }
            /* If there are no more unACKed packets, stop the timer */
            if (!has_unacked) {
                stoptimer(A);
            }
        } else {
            /* Duplicate ACK (already received before) - ignore */
            if (TRACE > 0)
                printf("----A: duplicate ACK received, do nothing!\n");
        }
    } else {
        /* ACK was corrupted - ignore it (sender will timeout and retransmit if needed) */
        if (TRACE > 0)
            printf("----A: corrupted ACK is received, do nothing!\n");
    }
}

/* called when A's timer goes off */
void A_timerinterrupt(void) {
    int i;
    /* Timer interrupt: timeout for at least one packet */
    if (TRACE > 0)
        printf("----A: time out,resend packets!\n");
    /* Timeout occurred: retransmit all unacked packets in the window */
    for (i = 0; i < WINDOWSIZE; i++) {
        int seq = (A_base + i) % SEQSPACE;
        if (A_buffer[seq].sent && !A_buffer[seq].acked) {
            /* Retransmit this packet (likely lost or ACK lost) */
            if (TRACE > 0)
                printf("---A: resending packet %d\n", seq);
            tolayer3(A, A_buffer[seq].packet);
            packets_resent++;
        }
    }
    /* Restart timer for next round of potential timeouts */
    starttimer(A, RTT);
}

/* the following routine will be called once (only) before any other entity A routines are called */
void A_init(void) {
    int i;
    A_base = 0;
    A_nextseq = 0;
    /* Initialize the sender buffer */
    for (i = 0; i < SEQSPACE; i++) {
        A_buffer[i].sent = 0;
        A_buffer[i].acked = 0;
        A_buffer[i].send_time = 0.0;
    }
    /* No timer started until a packet is sent */
}

/********* Receiver (B)  variables and procedures ************/

static struct pkt B_buffer[SEQSPACE];   /* buffer for out-of-order packets */
static int B_received[SEQSPACE];        /* flags for which seq numbers have been received (and not delivered yet) */
static int B_expectedseq;               /* next expected sequence number to deliver */
static int B_nextAckNum;                /* next sequence number to use for ACK packet (for checksum purposes) */

/* called from layer 3, when a packet arrives for layer 4 at B */
void B_input(struct pkt packet) {
    /* Packet arrives at receiver B */
    int seq;
    struct pkt ackpkt;
    int i;
    /* Extract sequence number of received packet and set default ACK number to that seq */
    seq = packet.seqnum;
    ackpkt.acknum = packet.seqnum;
    /* Prepare ACK packet header (seqnum used only to help compute checksum) */
    ackpkt.seqnum = B_nextAckNum;
    B_nextAckNum = (B_nextAckNum + 1) % 2;
    /* Fill ACK packet payload with '0's (not used for data) */
    for (i = 0; i < 20; i++) {
        ackpkt.payload[i] = '0';
    }
    /* Packet is not corrupted */
    if (!IsCorrupted(packet)) {
        /* Compute the upper edge of the receive window */
        int upperWindow = (B_expectedseq + WINDOWSIZE) % SEQSPACE;
        int in_window = 0;
        /* Check if seq is within [B_expectedseq, B_expectedseq + WINDOWSIZE - 1] (consider wraparound) */
        if (B_expectedseq < upperWindow) {
            if (seq >= B_expectedseq && seq < upperWindow)
                in_window = 1;
        } else {
            /* Window wraps around zero */
            if (seq >= B_expectedseq || seq < upperWindow)
                in_window = 1;
        }
        if (in_window) {
            /* The packet's sequence number is within the receiver's window */
            if (!B_received[seq]) {
                /* New packet (not seen before) within window: buffer it */
                B_received[seq] = 1;
                B_buffer[seq] = packet;
                if (TRACE > 0)
                    printf("----B: packet %d received and buffered\n", seq);
            } else {
                /* Duplicate packet (already buffered or delivered) */
                if (TRACE > 0)
                    printf("----B: duplicate packet %d received\n", seq);
            }
            /* Deliver all in-order packets that have now been received */
            while (B_received[B_expectedseq]) {
                /* Pass packet data up to layer 5 (application) */
                tolayer5(B, B_buffer[B_expectedseq].payload);
                /* Update receiver delivered packet count */
                packets_received++;
                total_data_received_at_B++;
                /* Log delivery of packet to layer5 */
                if (TRACE > 0)
                    printf("----B: packet %d delivered to layer5\n", B_expectedseq);
                /* Mark as delivered and advance expected sequence */
                B_received[B_expectedseq] = 0;
                B_expectedseq = (B_expectedseq + 1) % SEQSPACE;
            }
            /* Set ACK number to the seq we just received (acknowledge this packet) */
            ackpkt.acknum = seq;
        } else {
            /* Packet is outside the receiver's window (either already delivered or not expected yet) */
            if (TRACE > 0)
                printf("----B: packet %d out of window, ignored\n", seq);
            /* ACK the last delivered packet (repeat last ACK) */
            ackpkt.acknum = (B_expectedseq + SEQSPACE - 1) % SEQSPACE;
        }
    } else {
        /* Packet is corrupted: discard data, but send duplicate ACK for last delivered packet */
        if (TRACE > 0)
            printf("----B: corrupted packet received, ignore data but send ACK %d\n", (B_expectedseq + SEQSPACE - 1) % SEQSPACE);
        /* ACK the last correctly delivered packet (resend last ACK) */
        ackpkt.acknum = (B_expectedseq + SEQSPACE - 1) % SEQSPACE;
    }
    /* Compute checksum for ACK and send it */
    ackpkt.checksum = ComputeChecksum(ackpkt);
    tolayer3(B, ackpkt);
    /* Send ACK for the received packet (or last delivered packet if necessary) */
    if (TRACE > 0)
        printf("----B: ACK %d sent\n", ackpkt.acknum);
}

/* the following routine will be called once (only) before any other entity B routines are called */
void B_init(void) {
    int i;
    B_expectedseq = 0;
    B_nextAckNum = 1;
    for (i = 0; i < SEQSPACE; i++) {
        B_received[i] = 0;
    }
}

/* Note that with simplex transfer from A-to-B, there is no B_output() */
void B_output(struct msg message) {
    /* not applicable for simplex communication */
}
void B_timerinterrupt(void) {
    /* not used */
}
