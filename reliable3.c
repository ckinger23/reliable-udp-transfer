/*
 * Lab3: Reliable Data Transfer a.k.a The Coronavirus Project
 * reliable.c 
 * Carter King
 * Comp315: Computer Networks
 * 27 March 2020
 *
 * This program attempt to create five functions that allow for reliable data
 * transfer on top of the unreliable UDP. I gave this a valiant effort, but I 
 * don't think my best work is produced when I haven't left my house in a 
 * week. :)
 *
 */

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <poll.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <netinet/in.h>

#include "rlib.h"

#define DATA_HDRLEN 12
#define ACK_HDRLEN   8


/*
 * reliable connection state information
 */
struct reliable_state {
  rdt_t *next;			         // this is a linked list of active connections
  rdt_t **prev;
  conn_t *c;			           // rlib connection object
  int sentSeqno;
  int recvdSeqno;
  struct timespec * ackTimestamp;
  struct timespec * dataTimestamp;
  int sentAckno;
  int recvdAckno;
  packet_t * lastDataPktSent;
  packet_t * lastAckPktSent;
  packet_t * lastDataPktRecvd;
  packet_t * overflowBuf;
};


/*
 * global variables
 */
rdt_t *rdt_list;



/**
 * rdt_create - creates a new reliable protocol session.
 * @param c  - connection object (when running in single-connection mode, NULL otherwise)
 * @param ss - sockaddr info (when running in multi-connection mode, NULL otherwise)
 * @param cc - global configuration information
 * @returns new reliable state structure, NULL on failure
 */
rdt_t *rdt_create(conn_t *c, const struct sockaddr_storage *ss, const struct config_common *cc) {
  rdt_t *r;

  r = xmalloc (sizeof (*r));
  memset (r, 0, sizeof (*r));

  if (!c) {
    c = conn_create (r, ss);
    if (!c) {
      free (r);
      return NULL;
    }
  }

  r->c = c;
  r->next = rdt_list;
  r->prev = &rdt_list;
  if (rdt_list)
    rdt_list->prev = &r->next;
  rdt_list = r;

  // add additional initialization code here
  r->sentSeqno = 1;
  r->recvdSeqno = 0;
  r->sentAckno = 0;
  r->recvdAckno = 0;
  r->dataTimestamp = NULL;
  r->ackTimestamp = NULL;
  r->lastDataPktSent = NULL;
  r->lastDataPktRecvd = NULL;
  r->lastAckPktSent = NULL;
  r->overflowBuf = NULL;
  return r;
}



/**
 * rdt_destroy - shutdown a reliable protocol session
 * @param r - reliable connection to close
 */
void rdt_destroy(rdt_t *r) {
  if (r->next)
    r->next->prev = r->prev;
  *r->prev = r->next;
  conn_destroy (r->c);
  // free any other allocated memory here
  free(r->overflowBuf);
  free(r);
}



/**
 * rdt_recvpkt - receive a packet from the unreliable network layer
 * @param r - reliable connection state information
 * @param pkt - received packet
 * @param n - size of received data in the packet
 */
void rdt_recvpkt(rdt_t *r, packet_t *pkt, size_t n) {
  uint16_t retCsumValue;
  ntohs(pkt->len);
  ntohl(pkt->ackno);

  //if ack packet
  if (pkt->len == 8){
    fprintf(stderr, "receiving ack");
    //check if ack packet corrupted
    retCsumValue = cksum(pkt, n);
    if (retCsumValue != pkt->cksum){
      conn_sendpkt(r->c, lastDataPktSent, lastDataPktSent->len);
      clock_gettime(CLOCK_MONOTONIC, r->dataTimestamp); 
      fprintf(stderr, "resending due to corrupt ack packet");
    }
    //if acknowledging earlier seqno
    //never recv curr dataPacket
    if (pkt->ackno < r->sentSeqno){
      conn_sendpkt(r->c, lastDataPktSent, lastDataPktSent->len);
      clock_gettime(CLOCK_MONOTONIC, r->dataTimestamp);
      fprintf(stderr, "resending due to earlier ack packet");
    }
    else{
      r->recvdAckno = pkt->ackno;
    }
  }
  //data packet
  else{
    fprintf(stderr, "received a data packet");
    ntohl(pkt->seqno);
    ntohl(pkt->data);
    //corrupted packet, resend previous ack
    retCsumValue = cksum(pkt, n);
    if (retCsumValue != pkt->cksum){
      //if not the first packet sent, resend last AckPacket
      if (lastAckPktSent != NULL){
        conn_sendpkt(r->c, lastAckPktSent, lastAckPktSent->len);
        clock_gettime(CLOCK_MONOTONIC, r->ackTimestamp);
        fprintf(stderr, "corrupt data packet, resending last ack sent");
      }
    }
    //receiving duplicate packet
    if (pkt->seqno < r->RecvdSeqno){
      if (lastAckPktSent != NULL) {
        conn_sendpkt(r->c, lastAckPktSent, lastAckPktSent->len);
        clock_gettime(CLOCK_MONOTONIC, r->ackTimestamp);
        fprintf(stderr, "duplicate data packet, resending last ack sent");
      }
    }
    //correct seqno
    else{
      fprintf(stderr, "received a quality data packet");
      lastDataPktRecvd = pkt;
      r->recvdSeqno = pkt->seqno;
      //attempt conn_bufspace
      if (n < conn_bufspace(r->c)){
        fprintf(stderr, "enough bufspace to send ack in recv_packet()");
        conn_output(r->c, pkt->data, n);
        packet_t * newAck;
        newAck->cksum = 0;
        newAck->len = ACK_HDRLEN;
        newAck->ackno = pkt->seqno;
        newAck->cksum = cksum(newAck, 8);
        htons(newAck->len);
        htonl(newAck->ackno);
        conn_sendpkt(r->c, newAck, newAck->len);
        clock_gettime(CLOCK_MONOTONIC, r->ackTimestamp);
        lastAckPktSent = newAck;
        r->sentAckno = pkt->seqno;
      }
      else {
        overflowBuf = pkt;
        return;
      }
      //if EOF received, send connoutput 0 size and manually call rdt_destroy()
      if (n == 0){
        fprintf(stderr, "received EOF from network");
        rdt_destroy(r);
      }
    }
  }
}



/**
 * rdt_read - read packet from application and send to network layer
 * @param r - reliable connection state information
 */
void rdt_read(rdt_t *r) {
  char buf[500];
  int n = sizeof(buf);
  int dataRecvd = conn_input(r->c, buf, n);
  fprintf(stderr, "received input from app. layer");
  if(dataRecvd > 0){
    //create a data packet and send to other process
    packet_t * newDataPkt;
    newDataPkt->cksum = 0;
    newDataPkt->length = DATA_HDRLEN + n;
    newDataPkt->ackno = r->sentAckno;
    newDataPkt->seqno = r->sentSeqno;
    newDataPkt->data = buf;
    newDataPkt->cksum = cksum(newDataPkt, Data_HDRLEN + n);
    //change to network byte order
    htons(newDataPkt->cksum);
    htons(newDataPkt->len);
    htonl(newDataPkt->ackno);
    htonl(newDataPkt->seqno);
    htonl(newDataPkt->data);
    conn_sendpkt(r->c, newDataPkt, newDataPkt->len);
    clock_gettime(CLOCK_MONOTONIC, r->dataTimestamp);
    fprintf(stderr, "sent data packet read in from app. layer");
    lastDataPktSent = newDataPkt;
    r->sentSeqno = r->sentSeqno + 1;
    free(buf);
  }
  else if(dataRecvd == -1){
    //conn_input returns -1: send over EOF to process and call rdt_destroy
    fprintf(stderr, "recieved EOF from app. layer");
    packet_t * newEOFPkt;
    newDataPkt->cksum = 0;
    newDataPkt->length = DATA_HDRLEN;
    newDataPkt->ackno = r->sentAckno;
    newDataPkt->seqno = r->sentSeqno;
    newDataPkt->data = buf;
    newDataPkt->cksum = cksum(newDataPkt, Data_HDRLEN);
    //change to network byte order
    htons(newDataPkt->cksum);
    htons(newDataPkt->len);
    htonl(newDataPkt->ackno);
    htonl(newDataPkt->seqno);
    htonl(newDataPkt->data);
    conn_sendpkt(r->c, newDataPkt, newDataPkt->len);
    clock_gettime(CLOCK_MONOTONIC, r->dataTimestamp);
    fprintf(stderr, "send EOF from app. layer to network layer");
    lastDataPktSent = newDataPkt;
    r->sentSeqno = r->sentSeqno + 1;
    free(buf);
    // call rdt_destroy since we received an EOF 
    rdt_destroy(r);
  }
  //0 bytes returned, nothing currently available
  else{
    return;
  }
}



/**
 * rdt_output - callback for delivering packet to application layer if buffer was full
 * @param r - reliable connection state information
 */
void rdt_output(rdt_t *r) {
  fprintf(stderr, "space in buffer released, checking in output()");
  if (overFlowBuf->len - ACK_HDRLEN < conn_bufspace(r->c)){
    conn_output(r->c, overFlowBuf->data, overFlowBuf->len);
    packet_t * newAck;
    newAck->cksum = 0;
    newAck->len = ACK_HDRLEN;
    newAck->ackno = overFlowBuf->seqno;
    newAck->cksum = cksum(newAck, 8);
    htons(newAck->len);
    htonl(newAck->ackno);
    conn_sendpkt(r->c, newAck, newAck->len);
    fprintf(stderr, "sent ack packet from outpu()");
    clock_gettime(CLOCK_MONOTONIC, r->ackTimestamp);
    lastAckPktSent = newAck;
    r->sentAckno = pkt->seqno;
  }
  else{
    return;
  }
}




/**
 * rdt_timer() - timer callback invoked 1/5 of the retransmission rate
 */
void rdt_timer() {
  struct timespec * now;
  clock_gettime(CLOCK_MONOTONIC, now);
  for (rdt * p = rdtlist; p; p = p->next){
    if((now->tv_sec * 1000 - p->ackTimestamp->tv_sec * 1000) > cc->timeout){
      conn_sendpkt(p->c, lastAckPktSent, lastAckPktSent->len);
      clock_gettime(CLOCK_MONOTONIC, r->ackTimestamp);
    }
    if((now->tv_sec * 1000 - p->dataTimestamp->tv_sec * 1000) > cc->timetou){
      conn_sendpkt(p->c, lastDataPktSent, lastDataPktSent->len);
      clock_gettime(CLOCK_MONOTONIC, r->dataTimestamp);
    }
  }
}



/* This function only gets called when the process is running as a
 * server and must handle connections from multiple clients.  You have
 * to look up the rdt_t structure based on the address in the
 * sockaddr_storage passed in.  If this is a new connection (sequence
 * number 1), you will need to allocate a new conn_t using rdt_create
 * ().  (Pass rdt_create NULL for the conn_t, so it will know to
 * allocate a new connection.)
 */
void rdt_demux(const struct config_common *cc, const struct sockaddr_storage *ss, packet_t *pkt, size_t len) {
  // ignore this function
}
