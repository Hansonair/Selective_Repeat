#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "emulator.h"
#include "sr.h"
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
/* Sender (A) variables */
static struct pkt buffer[WINDOWSIZE]; /* Buffer for storing packets awaiting ACK */
static int windowfirst; /* Index of the first unacked packet in the buffer */
static int windowcount; /* Number of packets currently awaiting an ACK */
static int A_nextseqnum; /* Next sequence number to be used by the sender */

/* Receiver (B) variables */
static struct pkt recv_buffer[WINDOWSIZE]; /* Buffer for storing received packets at B */
static int expectedseqnum; /* Sequence number of the next expected in-order packet */

/* Compute the checksum of a packet for integrity verification */
int ComputeChecksum(struct pkt packet)
{
  int checksum = 0;
  int i;

  checksum = packet.seqnum;
  checksum += packet.acknum;
  for (i = 0; i < 20; i++)
    checksum += (int)(packet.payload[i]);

  return checksum;
}

/* Check if a packet is corrupted by comparing checksums */
int IsCorrupted(struct pkt packet)
{
  if (packet.checksum == ComputeChecksum(packet))
    return -1; /* Uncorrupted */
  else
    return 0; /* Corrupted */
}


/* Called from layer 5: Send a new message to the network */
void A_output(struct msg message)
{
  struct pkt sendpkt;
  int i;
  int index;
  /* Compute the sequence number range of the current window */
  int seqfirst = windowfirst;
  int seqlast = (windowfirst + WINDOWSIZE - 1) % SEQSPACE;

  /* Check if A_nextseqnum is within the current window */
  if (((seqfirst <= seqlast) && (A_nextseqnum >= seqfirst && A_nextseqnum <= seqlast)) ||
      ((seqfirst > seqlast) && (A_nextseqnum >= seqfirst || A_nextseqnum <= seqlast)))
  {
    if (TRACE > 1)
      printf("----A: New message arrives, send window is not full, send new messge to layer3!\n");

    /* Create a new packet with the given message */
    sendpkt.seqnum = A_nextseqnum;
    sendpkt.acknum = NOTINUSE;
    for (i = 0; i < 20; i++)
      sendpkt.payload[i] = message.data[i];
    sendpkt.checksum = ComputeChecksum(sendpkt);

    /* Calculate the buffer index based on the sequence number */
    if (A_nextseqnum >= seqfirst)
      index = A_nextseqnum - seqfirst;
    else
      index = WINDOWSIZE - seqfirst + A_nextseqnum;
    buffer[index] = sendpkt;
    windowcount++;

    /* Send the packet to layer 3 */
    if (TRACE > 0)
      printf("Sending packet %d to layer 3\n", sendpkt.seqnum);
    tolayer3(A, sendpkt);

    /* Start the timer if this is the first packet in the window */
    if (A_nextseqnum == seqfirst)
      starttimer(A, RTT);

    /* Increment the next sequence number */
    A_nextseqnum = (A_nextseqnum + 1) % SEQSPACE;
  }
  else
  {
    if (TRACE > 0)
      printf("----A: New message arrives, send window is full\n");
    window_full++;
  }
}

/* Called from layer 3: Process an incoming ACK packet */
void A_input(struct pkt packet)
{
  int ackcount = 0;
  int i;
  int seqfirst;
  int seqlast;
  int index;

  /* Check if the received ACK is not corrupted */
  if (IsCorrupted(packet) == -1)
  {
    if (TRACE > 0)
      printf("----A: uncorrupted ACK %d is received\n", packet.acknum);
    total_ACKs_received++;

    /* Compute the current window's sequence number range */
    seqfirst = windowfirst;
    seqlast = (windowfirst + WINDOWSIZE - 1) % SEQSPACE;

    /* Check if the ACK is within the current window */
    if (((seqfirst <= seqlast) && (packet.acknum >= seqfirst && packet.acknum <= seqlast)) ||
        ((seqfirst > seqlast) && (packet.acknum >= seqfirst || packet.acknum <= seqlast)))
    {
      /* Calculate the buffer index for the ACK */
      if (packet.acknum >= seqfirst)
        index = packet.acknum - seqfirst;
      else
        index = WINDOWSIZE - seqfirst + packet.acknum;

      /* Check if this is a new ACK */
      if (buffer[index].acknum == NOTINUSE)
      {
        if (TRACE > 0)
          printf("----A: ACK %d is not a duplicate\n", packet.acknum);
        new_ACKs++;
        windowcount--;
        buffer[index].acknum = packet.acknum;
      }
      else
      {
        if (TRACE > 0)
          printf("----A: duplicate ACK received, do nothing!\n");
      }

      /* If the ACK is for the first packet in the window, slide the window */
      if (packet.acknum == seqfirst)
      {
        /* Count consecutive ACKs starting from the window's base */
        for (i = 0; i < WINDOWSIZE; i++)
        {
          if (buffer[i].acknum != NOTINUSE && buffer[i].seqnum >= 0)
            ackcount++;
          else
            break;
        }

        /* Slide the window by updating windowfirst */
        windowfirst = (windowfirst + ackcount) % SEQSPACE;

        /* Shift the buffer to remove ACKed packets */
        for (i = 0; i < WINDOWSIZE; i++)
        {
          if (buffer[i + ackcount].acknum == NOTINUSE || (buffer[i].seqnum + ackcount) % SEQSPACE == A_nextseqnum)
            buffer[i] = buffer[i + ackcount];
        }

        stoptimer(A);
        if (windowcount > 0)
          starttimer(A, RTT);
      }
      else
      {
        buffer[index].acknum = packet.acknum;
      }
    }
  }
  else
  {
    if (TRACE > 0)
      printf("----A: corrupted ACK is received, do nothing!\n");
  }
}

/* Called when the timer expires: Resend the oldest unacknowledged packet */
void A_timerinterrupt(void)
{
  if (TRACE > 0)
  {
    printf("----A: time out,resend packets!\n");
    printf("---A: resending packet %d\n", buffer[0].seqnum);
  }
  tolayer3(A, buffer[0]);
  packets_resent++;
  starttimer(A, RTT);
}

/* Initialize sender's state variables */
void A_init(void)
{
  A_nextseqnum = 0;
  windowfirst = 0;
  windowcount = 0;
}


/* Called from layer 3: Process an incoming packet at B */
void B_input(struct pkt packet)
{
  int pckcount = 0;
  struct pkt sendpkt;
  int i;
  int seqfirst;
  int seqlast;
  int index;

  /* Check if the received packet is not corrupted */
  if (IsCorrupted(packet) == -1)
  {
    if (TRACE > 0)
      printf("----B: packet %d is correctly received, send ACK!\n", packet.seqnum);
    packets_received++;

    /* Send an ACK for the received packet */
    sendpkt.acknum = packet.seqnum;
    sendpkt.seqnum = NOTINUSE;
    for (i = 0; i < 20; i++)
      sendpkt.payload[i] = '0';
    sendpkt.checksum = ComputeChecksum(sendpkt);
    tolayer3(B, sendpkt);

    /* Compute the receiver's window range */
    seqfirst = expectedseqnum;
    seqlast = (expectedseqnum + WINDOWSIZE - 1) % SEQSPACE;

    /* Check if the packet is within the receiver's window */
    if (((seqfirst <= seqlast) && (packet.seqnum >= seqfirst && packet.seqnum <= seqlast)) ||
        ((seqfirst > seqlast) && (packet.seqnum >= seqfirst || packet.seqnum <= seqlast)))
    {
      /* Calculate the buffer index for the packet */
      if (packet.seqnum >= seqfirst)
        index = packet.seqnum - seqfirst;
      else
        index = WINDOWSIZE - seqfirst + packet.seqnum;

      /* If not a duplicate (compare payloads), store the packet */
      if (strcmp(recv_buffer[index].payload, packet.payload) != 0)
      {
        packet.acknum = packet.seqnum;
        recv_buffer[index] = packet;

        /* If the packet is the expected one, slide the window */
        if (packet.seqnum == seqfirst)
        {
          for (i = 0; i < WINDOWSIZE; i++)
          {
            if (recv_buffer[i].acknum >= 0 && strcmp(recv_buffer[i].payload, "") != 0)
              pckcount++;
            else
              break;
          }

          /* Update the expected sequence number */
          expectedseqnum = (expectedseqnum + pckcount) % SEQSPACE;

          /* Shift the buffer to remove delivered packets */
          for (i = 0; i < WINDOWSIZE; i++)
          {
            if (i + pckcount < WINDOWSIZE)
              recv_buffer[i] = recv_buffer[i + pckcount];
          }
        }

        /* Deliver the packet to the application */
        tolayer5(B, packet.payload);
      }
    }
  }
}

/* the following routine will be called once (only) before any other */
/* entity B routines are called. You can use it to do any initialization */
void B_init(void)
{
  expectedseqnum = 0;
}

void B_output(struct msg message)
{
}

void B_timerinterrupt(void)
{
}