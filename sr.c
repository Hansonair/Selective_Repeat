
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include "emulator.h"
#include "gbn.h"

#define RTT  16.0
#define WINDOWSIZE 6
#define SEQSPACE 12
#define NOTINUSE (-1)

struct SR_packet {
    struct pkt packet;
    bool used;
    bool acked;
    bool delivered;
};

static struct SR_packet sender_buffer[SEQSPACE];
static struct SR_packet receiver_buffer[SEQSPACE];

static int base = 0;
static int nextseqnum = 0;
static bool timer_running = false;

static int expectedseqnum = 0;

/* Utility functions */
int ComputeChecksum(struct pkt packet) {
    int checksum = packet.seqnum + packet.acknum;
    for (int i = 0; i < 20; i++) {
        checksum += (int)packet.payload[i];
    }
    return checksum;
}

bool IsCorrupted(struct pkt packet) {
    return packet.checksum != ComputeChecksum(packet);
}

void startTimer() {
    if (!timer_running) {
        starttimer(0, RTT);
        timer_running = true;
    }
}

void stopTimer() {
    if (timer_running) {
        stoptimer(0);
        timer_running = false;
    }
}

void resendTimedOutPackets(float current_time) {
    for (int i = 0; i < SEQSPACE; i++) {
        if (sender_buffer[i].used && !sender_buffer[i].acked && 
            (current_time - sender_buffer[i].packet.send_time >= RTT)) {
            tolayer3(0, sender_buffer[i].packet);
            sender_buffer[i].packet.send_time = current_time;
        }
    }
}


void A_output(struct msg message) {
    if (((nextseqnum - base + SEQSPACE) % SEQSPACE) >= WINDOWSIZE) {
        printf("----A: Window is full, message dropped\n");
        return;
    }

    struct pkt packet;
    packet.seqnum = nextseqnum;
    packet.acknum = -1;
    memcpy(packet.payload, message.data, 20);
    packet.checksum = ComputeChecksum(packet);
    packet.send_time = get_sim_time();

    sender_buffer[nextseqnum].packet = packet;
    sender_buffer[nextseqnum].used = true;
    sender_buffer[nextseqnum].acked = false;

    printf("----A: New message arrives, send window is not full, send new messge to layer3!\n");
    printf("Sending packet %d to layer 3\n", packet.seqnum);
    tolayer3(0, packet);
    startTimer();

    nextseqnum = (nextseqnum + 1) % SEQSPACE;
}

void A_input(struct pkt packet) {
    if (IsCorrupted(packet)) {
        printf("----A: received corrupted ACK, ignored\n");
        return;
    }

    int seq = packet.acknum;
    if (sender_buffer[seq].used && !sender_buffer[seq].acked) {
        printf("----A: uncorrupted ACK %d is received\n", seq);
        printf("----A: ACK %d is not a duplicate\n", seq);
        sender_buffer[seq].acked = true;

        while (sender_buffer[base].acked && base != nextseqnum) {
            sender_buffer[base].used = false;
            base = (base + 1) % SEQSPACE;
        }

        bool all_acked = true;
        for (int i = base; i != nextseqnum; i = (i + 1) % SEQSPACE) {
            if (sender_buffer[i].used && !sender_buffer[i].acked) {
                all_acked = false;
                break;
            }
        }

        if (all_acked) {
            stopTimer();
        }
    }
}

void A_timerinterrupt() {
    printf("----A: Timer interrupt, retransmit all unacked packets\n");

    for (int i = base; i != nextseqnum; i = (i + 1) % SEQSPACE) {
        if (sender_buffer[i].used && !sender_buffer[i].acked) {
            tolayer3(0, sender_buffer[i].packet);
            sender_buffer[i].packet.send_time = get_sim_time();
        }
    }

    startTimer();
}

void A_init() {
    base = 0;
    nextseqnum = 0;
    timer_running = false;
    for (int i = 0; i < SEQSPACE; i++) {
        sender_buffer[i].used = false;
        sender_buffer[i].acked = false;
    }
}


void B_input(struct pkt packet) {
    if (IsCorrupted(packet)) {
        printf("----B: received corrupted packet, ignored\n");
        return;
    }

    int seq = packet.seqnum;
    struct pkt ack;
    ack.acknum = seq;
    ack.seqnum = 0;
    ack.checksum = ComputeChecksum(ack);
    memcpy(ack.payload, "ACK", 4);

    if ((seq >= expectedseqnum && seq < expectedseqnum + WINDOWSIZE) ||
        (expectedseqnum + WINDOWSIZE >= SEQSPACE && seq < (expectedseqnum + WINDOWSIZE) % SEQSPACE)) {

        if (!receiver_buffer[seq].used) {
            receiver_buffer[seq].packet = packet;
            receiver_buffer[seq].used = true;

            printf("----B: packet %d is correctly received, send ACK!\n", seq);

            if (seq == expectedseqnum) {
                while (receiver_buffer[expectedseqnum].used) {
                    tolayer5(1, receiver_buffer[expectedseqnum].packet.payload);
                    receiver_buffer[expectedseqnum].used = false;
                    expectedseqnum = (expectedseqnum + 1) % SEQSPACE;
                }
            }
        } else {
            printf("----B: duplicate packet %d received, resend ACK\n", seq);
        }
        tolayer3(1, ack);
    } else {
        printf("----B: packet %d out of window, ignored\n", seq);
    }
}

void B_init() {
    expectedseqnum = 0;
    for (int i = 0; i < SEQSPACE; i++) {
        receiver_buffer[i].used = false;
    }
}
