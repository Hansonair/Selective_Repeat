#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "emulator.h"
#include "sr.h"

#define RTT 16.0
#define WINDOWSIZE 6
#define MAX_SEQ 16 /* SR needs larger sequence space (at least 2*WINDOWSIZE) */
#define NOTINUSE (-1)

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

/********* Sender (A) functions ************/

/* Called from layer 5: Send a new message to the network */
void A_output(struct msg message)
{
  struct pkt sendpkt;
  int i;
  int index;
  /* Compute the sequence number range of the current window */
  int seqfirst = windowfirst;
  int seqlast = (windowfirst + WINDOWSIZE - 1) % MAX_SEQ;

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
    A_nextseqnum = (A_nextseqnum + 1) % MAX_SEQ;
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
    seqlast = (windowfirst + WINDOWSIZE - 1) % MAX_SEQ;

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
        windowfirst = (windowfirst + ackcount) % MAX_SEQ;

        /* Shift the buffer to remove ACKed packets */
        for (i = 0; i < WINDOWSIZE; i++)
        {
          if (buffer[i + ackcount].acknum == NOTINUSE || (buffer[i].seqnum + ackcount) % MAX_SEQ == A_nextseqnum)
            buffer[i] = buffer[i + ackcount];
        }

        /* Restart the timer if there are still unacked packets */
        stoptimer(A);
        if (windowcount > 0)
          starttimer(A, RTT);
      }
      else
      {
        /* Update buffer with the ACK */
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

/********* Receiver (B) functions ************/

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
    seqlast = (expectedseqnum + WINDOWSIZE - 1) % MAX_SEQ;

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
          expectedseqnum = (expectedseqnum + pckcount) % MAX_SEQ;

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

/* Initialize receiver's state variables */
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