#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include "emulator.h"
#include "gbn.h"

extern int total_data_received_at_B;
int total_data_received_at_B = 0;



float global_time = 0.0;



/* ******************************************************************
   Go Back N protocol.  Adapted from J.F.Kurose
   ALTERNATING BIT AND GO-BACK-N NETWORK EMULATOR: VERSION 1.2

   Network properties:
   - one way network delay averages five time units (longer if there
   are other messages in the channel for GBN), but can be larger
   - packets can be corrupted (either the header or the data portion)
   or lost, according to user-defined probabilities
   - packets will be delivered in the order in which they were sent
   (although some can be lost).

   Modifications:
   - removed bidirectional GBN code and other code not used by prac.
   - fixed C style to adhere to current programming style
   - added GBN implementation
**********************************************************************/

#define RTT  16.0       /* round trip time.  MUST BE SET TO 16.0 when submitting assignment */
#define WINDOWSIZE 6    /* the maximum number of buffered unacked packet
                          MUST BE SET TO 6 when submitting assignment */
#define SEQSPACE 7      /* the min sequence space for GBN must be at least windowsize + 1 */
#define NOTINUSE (-1)   /* used to fill header fields that are not being used */

/* generic procedure to compute the checksum of a packet.  Used by both sender and receiver
   the simulator will overwrite part of your packet with 'z's.  It will not overwrite your
   original checksum.  This procedure must generate a different checksum to the original if
   the packet is corrupted.
*/
struct SR_packet {
    struct pkt packet;
    bool used;
    bool acked;
    float send_time;
};

static struct SR_packet sender_buffer[SEQSPACE];  
static int base = 0;
static int nextseqnum = 0;




int ComputeChecksum(struct pkt packet)
{
  int checksum = 0;
  int i;

  checksum = packet.seqnum;
  checksum += packet.acknum;
  for ( i=0; i<20; i++ )
    checksum += (int)(packet.payload[i]);

  return checksum;
}

bool IsCorrupted(struct pkt packet)
{
  if (packet.checksum == ComputeChecksum(packet))
    return (false);
  else
    return (true);
}


/********* Sender (A) variables and functions ************/




/* called from layer 5 (application layer), passed the message to be sent to other side */
void A_output(struct msg message) {
    if ((nextseqnum + SEQSPACE - base) % SEQSPACE < WINDOWSIZE) {
        struct pkt sendpkt;
        int i;

        sendpkt.seqnum = nextseqnum;
        sendpkt.acknum = -1;  
        for (i = 0; i < 20; i++)
            sendpkt.payload[i] = message.data[i];
        sendpkt.checksum = ComputeChecksum(sendpkt);

        sender_buffer[nextseqnum].packet = sendpkt;
        sender_buffer[nextseqnum].used = true;
        sender_buffer[nextseqnum].acked = false;
        sender_buffer[nextseqnum].send_time = global_time;

        tolayer3(A, sendpkt);

        if (TRACE > 0)
            printf("A_output: packet %d sent\n", sendpkt.seqnum);

        if (base == nextseqnum) {
            starttimer(A, RTT / 2);
        }

        nextseqnum = (nextseqnum + 1) % SEQSPACE;
    } else {
        if (TRACE > 0)
            printf("A_output: window full, message dropped\n");
        window_full++;
    }
}




/* called from layer 3, when a packet arrives for layer 4
   In this practical this will always be an ACK as B never sends data.
*/
void A_input(struct pkt packet) {
    if (!IsCorrupted(packet)) {
        if (TRACE > 0)
            printf("----A: uncorrupted ACK %d is received\n", packet.acknum);

        total_ACKs_received++;

        int acknum;
        acknum = packet.acknum;  

        if (sender_buffer[acknum].used && !sender_buffer[acknum].acked) {
            sender_buffer[acknum].acked = true;

            if (TRACE > 0)
                printf("----A: ACK %d is not a duplicate\n", acknum);

            new_ACKs++;

            while (sender_buffer[base].acked) {
                sender_buffer[base].used = false;
                base = (base + 1) % SEQSPACE;
            }
        } else {
            if (TRACE > 0)
                printf("----A: duplicate ACK received, do nothing!\n");
        }

        int i;
        bool has_unacked = false;
        for (i = 0; i < SEQSPACE; i++) {
            if (sender_buffer[i].used && !sender_buffer[i].acked) {
                has_unacked = true;
                break;
            }
        }

        if (!has_unacked) {
            if (TRACE > 0)
                printf("----A: All packets ACKed, stopping timer\n");
            stoptimer(A);
        }

    } else {
        if (TRACE > 0)
            printf("----A: corrupted ACK is received, do nothing!\n");
    }
}


/* called when A's timer goes off */
void A_timerinterrupt(void) {
    if (TRACE > 0)
        printf("----A: timer interrupt, checking for timeouts...\n");

    int i;
    bool has_unacked = false;  

    for (i = 0; i < SEQSPACE; i++) {
        if (sender_buffer[i].used && !sender_buffer[i].acked) {
            float elapsed = global_time - sender_buffer[i].send_time;

            if (elapsed >= RTT) {
                tolayer3(A, sender_buffer[i].packet);
                sender_buffer[i].send_time = global_time;

                if (TRACE > 0)
                    printf("----A: timeout for packet %d, retransmitted\n", sender_buffer[i].packet.seqnum);

                packets_resent++;
            }

            has_unacked = true; 
        }
    }

    if (has_unacked) {
        starttimer(A, RTT / 2);
    } else {
        if (TRACE > 0)
            printf("----A: no unacked packets left, timer stopped\n");
    }
}





/* the following routine will be called once (only) before any other */
/* entity A routines are called. You can use it to do any initialization */
void A_init(void) {
    base = 0;
    nextseqnum = 0;

    int i;
    for (i = 0; i < SEQSPACE; i++) {

        sender_buffer[i].used = false;
        sender_buffer[i].acked = false;
        sender_buffer[i].send_time = 0.0;
    }

   
    starttimer(A, RTT / 2);
}




/********* Receiver (B)  variables and procedures ************/

static int expectedseqnum; /* the sequence number expected next by the receiver */
static int B_nextseqnum;   /* the sequence number for the next packets sent by B */
static struct pkt receiver_buffer[SEQSPACE];
static bool received[SEQSPACE];




/* called from layer 3, when a packet arrives for layer 4 at B*/
void B_input(struct pkt packet) {
    struct pkt ackpkt;
    int i;

    ackpkt.acknum = packet.seqnum;

    if (!IsCorrupted(packet)) {
        int seq = packet.seqnum;

        int upper_edge = (expectedseqnum + WINDOWSIZE) % SEQSPACE;
        bool in_window = (
            (expectedseqnum < upper_edge && seq >= expectedseqnum && seq < upper_edge) ||
            (expectedseqnum > upper_edge && (seq >= expectedseqnum || seq < upper_edge))
        );

        if (in_window) {
            if (!received[seq]) {
                received[seq] = true;
                receiver_buffer[seq] = packet;

                if (TRACE > 0)
                    printf("----B: packet %d received and buffered\n", seq);
            } else {
                if (TRACE > 0)
                    printf("----B: duplicate packet %d received\n", seq);
            }

            while (received[expectedseqnum]) {
                tolayer5(B, receiver_buffer[expectedseqnum].payload);
                total_data_received_at_B++;

               

                if (TRACE > 0)
                    printf("----B: packet %d delivered to layer5\n", expectedseqnum);
                received[expectedseqnum] = false;
                expectedseqnum = (expectedseqnum + 1) % SEQSPACE;
            }
        } else {
            if (TRACE > 0)
                printf("----B: packet %d out of window, ignored\n", seq);
        }

    } else {
        
        ackpkt.acknum = (expectedseqnum + SEQSPACE - 1) % SEQSPACE;

        if (TRACE > 0)
            printf("----B: corrupted packet received, ignore data but send ACK %d\n", ackpkt.acknum);
    }

    ackpkt.seqnum = B_nextseqnum;
    B_nextseqnum = (B_nextseqnum + 1) % 2;

    for (i = 0; i < 20; i++)
        ackpkt.payload[i] = '0';

    ackpkt.checksum = ComputeChecksum(ackpkt);
    tolayer3(B, ackpkt);

    if (TRACE > 0)
        printf("----B: ACK %d sent\n", ackpkt.acknum);
}



/* the following routine will be called once (only) before any other */
/* entity B routines are called. You can use it to do any initialization */
void B_init(void) {
    expectedseqnum = 0;
    B_nextseqnum = 0;

    int i;
    for (i = 0; i < SEQSPACE; i++) {

        received[i] = false;
    }
}


/******************************************************************************
 * The following functions need be completed only for bi-directional messages *
 *****************************************************************************/

/* Note that with simplex transfer from a-to-B, there is no B_output() */
void B_output(struct msg message)
{
}

/* called when B's timer goes off */
void B_timerinterrupt(void)
{
}
