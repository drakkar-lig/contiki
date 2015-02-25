/*
 * Copyright (c) 2005, Swedish Institute of Computer Science.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file is part of the Contiki operating system.
 *
 * $Id: rrpl.c,v 1.37 2010/01/20 09:58:16 chianhla Exp $
 */

/**
 * \file
 *         This protocol is evolved from
 *         the LOADng routing protocol
 *         IETF draft draft-clausen-lln-loadng-00.txt
 *         Version for slotted 802.15.4
 * \author
 *         Chi-Anh La la@imag.fr
 *         Martin Heusse Martin.Heusse@imag.fr
 */

#include "contiki.h"
#include "contiki-lib.h"
#include "net/rrpl/rrpl-def.h"
#include "net/rrpl/rrpl.h"
#include "contiki-net.h"


#include <string.h>

#if WITH_IPV6_RRPL

#define DEBUG 1
#include "net/ip/uip-debug.h"

#define QRY_INTERVAL 5 * CLOCK_SECOND
#define QRY_NB 5

#define RRPL_MAX_RANK           127

#define SEND_INTERVAL           100 * CLOCK_SECOND
#define RETRY_CHECK_INTERVAL    5 * CLOCK_SECOND
#define RV_CHECK_INTERVAL       10 * CLOCK_SECOND
#define MAX_PAYLOAD_LEN         50
#define DEFAULT_PREFIX_LEN      128
#define DEFAULT_LOCAL_PREFIX    64
#define DEFAULT_OPT_SEQ_SKIP    4
extern uip_ds6_route_t uip_ds6_routing_table[UIP_DS6_ROUTE_NB];
#define UIP_IP_BUF ((struct uip_udpip_hdr *)&uip_buf[UIP_LLH_LEN])
#define MAX_SEQNO               65534
#define SEQNO_GREATER_THAN(s1, s2)                   \
          (((s1 > s2) && (s1 - s2 <= (MAX_SEQNO/2))) \
        || ((s2 > s1) && (s2 - s1 > (MAX_SEQNO/2))))
#if RRPL_RREQ_RATELIMIT
static struct timer next_time;
#endif

#if SND_QRY && ! RRPL_IS_SINK
static struct etimer eqryt;
#endif // SND_QRY && ! RRPL_IS_SINK

static enum {
  COMMAND_NONE,
  COMMAND_SEND_RREQ,
  COMMAND_SEND_RERR,
} command;
#define LAST_RSSI cc2420_last_rssi
// extern int8_t last_rssi; // for stm32w
extern signed char cc2420_last_rssi ;
static struct ctimer sendmsg_ctimer;
static uint16_t my_hseqno, my_seq_id;
static int8_t my_rank;
static uint8_t my_weaklink;
static int8_t my_parent_rssi;
static uint16_t local_prefix_len;
#if RRPL_IS_SINK
static uint8_t opt_seq_skip_counter;
#endif // RRPL_IS_SINK
uip_ipaddr_t local_prefix;
uip_ipaddr_t ipaddr, myipaddr, mcastipaddr;
uip_ipaddr_t orig_addr, dest_addr, rreq_addr, def_rt_addr, my_sink_id;
static struct uip_udp_conn *udpconn;
static uip_ipaddr_t rerr_bad_addr, rerr_src_addr, rerr_next_addr;
static uint8_t in_rrpl_call = 0 ; // make sure we don't trigger a rreq from within rrpl

#if SND_QRY && ! RRPL_IS_SINK
static uint8_t qry_left_to_send = 0;
#endif // SND_QRY && ! RRPL_IS_SINK

/*---------------------------------------------------------------------------*/
PROCESS(rrpl_process, "RRPL process");

/*---------------------------------------------------------------------------*/
/* Route lookup without triggering RREQ ! */
static uip_ds6_route_t *
rrpl_route_lookup(uip_ipaddr_t *addr)
{
  uip_ds6_route_t *r;
  uip_ds6_route_t *found_route;
  uint8_t longestmatch;

  PRINTF("RRPL: Looking up route for ");
  PRINT6ADDR(addr);
  PRINTF("\n");

  found_route = NULL;
  longestmatch = 0;
  for(r = uip_ds6_route_head();
      r != NULL;
      r = uip_ds6_route_next(r)) {
    if(r->length >= longestmatch &&
      uip_ipaddr_prefixcmp(addr, &r->ipaddr, r->length)) {
      longestmatch = r->length;
      found_route = r;
    }
  }

  if(found_route != NULL) {
    PRINTF("RRPL: route found via ");
    PRINT6ADDR(uip_ds6_route_nexthop(found_route));
    PRINTF("\n");
  } else {
    PRINTF("RRPL: No route found\n");
  }

  return found_route;
}



/*---------------------------------------------------------------------------*/
/* Implementation of route validity time check and purge */
#if RRPL_R_HOLD_TIME
static void
rrpl_check_expired_route(uint16_t interval)
{
  uip_ds6_route_t *r;

  for(r = uip_ds6_route_head();
  r != NULL;
  r = uip_ds6_route_next(r)) {

    if(r->state.valid_time <= interval) {
      uip_ds6_route_rm(r);
    } else {
      r->state.valid_time -= interval;
    }
  }
}
#endif // RRPL_R_HOLD_TIME




/*---------------------------------------------------------------------------*/
/* Implementation of route flush */
#if ! RRPL_IS_SINK
static void
rrpl_flush_routes()
{
  uip_ds6_route_t *r;

  for(r = uip_ds6_route_head();
  r != NULL;
  r = uip_ds6_route_next(r)) {
    uip_ds6_route_rm(r);
  }
}
#endif

/*---------------------------------------------------------------------------*/
/* Implementation of request forwarding cache to avoid multiple forwarding */
#define FWCACHE 2

static struct {
  uip_ipaddr_t orig;
  uint16_t seqno;
} fwcache[FWCACHE];

static int
fwc_lookup(const uip_ipaddr_t *orig, const uint16_t *seqno)
{
  unsigned n = (((uint8_t *)orig)[0] + ((uint8_t *)orig)[15]) % FWCACHE;
  return fwcache[n].seqno == *seqno && uip_ipaddr_cmp(&fwcache[n].orig, orig);
}

static void
fwc_add(const uip_ipaddr_t *orig, const uint16_t *seqno)
{
  unsigned n = (((uint8_t *)orig)[0] + ((uint8_t *)orig)[15]) % FWCACHE;
  fwcache[n].seqno = *seqno;
  uip_ipaddr_copy(&fwcache[n].orig, orig);
}


/*---------------------------------------------------------------------------*/
/* Implementation of route request cache for RRPL_RREQ_RETRIES and RRPL_NET_TRAVERSAL_TIME */
#if RRPL_RREQ_RETRIES
#define RRCACHE 2

static struct {
  uip_ipaddr_t dest;
  uint16_t expire_time;
  uint8_t request_time;
} rrcache[RRCACHE];

static int
rrc_lookup(const uip_ipaddr_t *dest)
{
  unsigned n = (((uint8_t *)dest)[0] + ((uint8_t *)dest)[15]) % RRCACHE;
  return uip_ipaddr_cmp(&rrcache[n].dest, dest);
}

static void
rrc_remove(const uip_ipaddr_t *dest)
{
  unsigned n = (((uint8_t *)dest)[0] + ((uint8_t *)dest)[15]) % RRCACHE;
  if(uip_ipaddr_cmp(&rrcache[n].dest, dest)) {
     memset(&rrcache[n].dest, 0, sizeof(&rrcache[n].dest));
     rrcache[n].expire_time = 0;
     rrcache[n].request_time = 0;
  }
}

static void
rrc_add(const uip_ipaddr_t *dest)
{
  unsigned n = (((uint8_t *)dest)[0] + ((uint8_t *)dest)[15]) % RRCACHE;
  rrcache[n].expire_time = RRPL_NET_TRAVERSAL_TIME;
  rrcache[n].request_time = 1;
  uip_ipaddr_copy(&rrcache[n].dest, dest);
}

static void
rrc_check_expired_rreq(uint16_t interval)
{
  int i;
  for(i = 0; i < RRCACHE; ++i) {
    rrcache[i].expire_time -= interval;
    if(rrcache[i].expire_time <= 0) {
      rrpl_request_route_to(&rrcache[i].dest);
      rrcache[i].request_time++;
      if(rrcache[i].request_time == RRPL_RREQ_RETRIES) {
         rrc_remove(&rrcache[i].dest);
      } else {
         rrcache[i].expire_time = RRPL_NET_TRAVERSAL_TIME; // FIXME: RRPL_NET_TRAVERSAL_TIME or 2*RRPL_NET_TRAVERSAL_TIME ?
      }
    }
  }
}
#endif // RRPL_RREQ_RETRIES


/*---------------------------------------------------------------------------*/
void
uip_ds6_route_print(void)
{
  uip_ds6_route_t *locroute = NULL;

  PRINTF("RRPL: Print route entries: ");
  PRINT6ADDR(&myipaddr);

  for(locroute = uip_ds6_route_head();
      locroute != NULL;
      locroute = uip_ds6_route_next(locroute)) {
    PRINTF(" DEST ");
    PRINT6ADDR(&locroute->ipaddr);
    PRINTF("/%u ", locroute->length);
    PRINTF(" NEXT ");
    PRINT6ADDR(uip_ds6_route_nexthop(locroute));
    PRINTF(" HC %u ", locroute->state.route_cost);
    PRINTF(" | ");
  }
  PRINTF("\n");
}

static inline uint8_t
get_weaklink(uint8_t metric)
{
  return (metric & 0x0f) ;
}

static inline uint8_t
parent_weaklink(int8_t rssi)
{
  return ((rssi > RRPL_RSSI_THRESHOLD) ? 0 : 1);
}

/*---------------------------------------------------------------------------*/
static int
get_global_addr(uip_ipaddr_t *addr)
{
  int i;
  int state;

  for(i = 0; i < UIP_DS6_ADDR_NB; i++) {
    state = uip_ds6_if.addr_list[i].state;
    if(uip_ds6_if.addr_list[i].isused &&
      (state == ADDR_TENTATIVE || state == ADDR_PREFERRED)) {
      if(!uip_is_addr_link_local(&uip_ds6_if.addr_list[i].ipaddr)) {
        memcpy(addr, &uip_ds6_if.addr_list[i].ipaddr, sizeof(uip_ipaddr_t));
        return 1;
      }
    }
  }
  return 0;
}

static void
uip_rrpl_nbr_add(uip_ipaddr_t* next_hop)
{
#if !UIP_ND6_SEND_NA
  uip_ds6_nbr_t *nbr = NULL;
  // it's my responsability to create+maintain neighbor
  nbr = uip_ds6_nbr_lookup(next_hop);

  if (nbr==NULL){
    PRINTF("adding nbr from rrpl\n");
    uip_lladdr_t nbr_lladdr;
    memcpy(&nbr_lladdr, &next_hop->u8[8],
           UIP_LLADDR_LEN);

    nbr_lladdr.addr[0] ^= 2;
    nbr = uip_ds6_nbr_add(next_hop, &nbr_lladdr, 0, NBR_REACHABLE);
//    nbr->nscount = 1;

  }
  else{
    PRINT6ADDR(&nbr->ipaddr);
    PRINTF("\n");
  }

#endif // !UIP_ND6_SEND_NA
}

void
rrpl_rand_wait()
{
#if RRPL_RANDOM_WAIT == 1
      PRINTF("RRPL: Waiting rand time\n");
      clock_wait(random_rand()%50 * CLOCK_SECOND / 100);
      PRINTF("RRPL: Done waiting rand time\n");
#endif
}

static uip_ds6_route_t*
uip_rrpl_route_add(uip_ipaddr_t* orig_addr, uint8_t length,
            uip_ipaddr_t* next_hop, uint8_t route_cost, uint16_t seqno)
{

  struct uip_ds6_route *rt;

  in_rrpl_call = 1;

  PRINTF("uip_rrpl_route_add() --- nexthop :");
  PRINT6ADDR(next_hop);
  PRINTF(" to: ");
  PRINT6ADDR(orig_addr);
  PRINTF("\n");
  uip_rrpl_nbr_add(next_hop);

  rt = uip_ds6_route_add(orig_addr, length, next_hop);

  if(rt != NULL) {
    rt->state.route_cost = route_cost;
    rt->state.seqno = seqno;
    rt->state.valid_time = RRPL_R_HOLD_TIME;
  }
  in_rrpl_call = 0;
  return rt;
}

/*---------------------------------------------------------------------------*/
/* Restart QRY timer */
#if SND_QRY && ! RRPL_IS_SINK
static void
enable_qry()
{
  if(qry_left_to_send <= 0) {
    qry_left_to_send = QRY_NB;
    etimer_set(&eqryt, (QRY_INTERVAL * (random_rand() % 50)) / 50);
  }
}
#endif // SND_QRY && ! RRPL_IS_SINK

/*---------------------------------------------------------------------------*/
#if SND_QRY && ! RRPL_IS_SINK
static void
send_qry()
{
  char buf[MAX_PAYLOAD_LEN];
  PRINTF("RRPL: Send QRY from ");
  PRINT6ADDR(&myipaddr);
  PRINTF("\n");

  struct rrpl_msg_qry *rm = (struct rrpl_msg_qry *)buf;

  rm->type = RRPL_QRY_TYPE;
  rm->type = (rm->type << 4) | RRPL_RSVD1;
  rm->addr_len = RRPL_RSVD2;
  rm->addr_len = (rm->addr_len << 4) | RRPL_ADDR_LEN_IPV6;
  udpconn->ttl = 1;
  uip_create_linklocal_lln_routers_mcast(&udpconn->ripaddr);
  uip_udp_packet_send(udpconn, buf, sizeof(struct rrpl_msg_qry));
  memset(&udpconn->ripaddr, 0, sizeof(udpconn->ripaddr));
  qry_left_to_send--;
  if(qry_left_to_send > 0) {
    // Have to sent another qry later. Set timer.
    etimer_set(&eqryt, (QRY_INTERVAL * (random_rand() % 50)) / 50);
  }
}
#endif // SND_QRY && ! RRPL_IS_SINK

/*---------------------------------------------------------------------------*/
/* Broadcast a OPT message. */
#if RRPL_IS_COORDINATOR()
#if RDC_LAYER_ID == ID_mac_802154_rdc_driver
void
#else
static void
#endif // RDC_LAYER_ID == ID_mac_802154_rdc_driver
send_opt()
{
  char buf[MAX_PAYLOAD_LEN];

#if ! RRPL_IS_SINK
  if(uip_ds6_defrt_lookup(&def_rt_addr) == NULL) {
    // No default next hop, schedule to send qry
    enable_qry();
    return; // wait for sink OPT
  }
#endif // ! RRPL_IS_SINK

  PRINTF("RRPL: Send OPT from ");
  PRINT6ADDR(&myipaddr);
  PRINTF("\n");

  struct rrpl_msg_opt *rm = (struct rrpl_msg_opt *)buf;

  rm->type = RRPL_OPT_TYPE;
  rm->type = (rm->type << 4) | RRPL_RSVD1;
  rm->addr_len = RRPL_RSVD2;
  rm->addr_len = (rm->addr_len << 4) | RRPL_ADDR_LEN_IPV6;
  rm->seqno = my_seq_id;
  rm->rank = my_rank;
  rm->metric = RRPL_METRIC_HC;
  rm->metric = (rm->metric << 4) | (my_weaklink + parent_weaklink(my_parent_rssi));

#if RRPL_IS_SINK
  uip_ipaddr_copy(&rm->sink_addr, &myipaddr);
#else // RRPL_IS_SINK
  uip_ipaddr_copy(&rm->sink_addr, &my_sink_id);
#endif // RRPL_IS_SINK

  udpconn->ttl = 1;
  uip_create_linklocal_lln_routers_mcast(&udpconn->ripaddr);
//   PRINTF("RRPL: OPT length %u\n", sizeof(struct rrpl_msg_opt));
// #if RDC_LAYER_ID == ID_mac_802154_rdc_driver
//   tcpip_set_outputfunc(output_802154);
//   uip_udp_packet_send(udpconn, buf, sizeof(struct rrpl_msg_opt));
//   tcpip_set_outputfunc(output);
// #else // RDC_LAYER_ID == ID_mac_802154_rdc_driver
  uip_udp_packet_send(udpconn, buf, sizeof(struct rrpl_msg_opt));
// #endif // RDC_LAYER_ID == ID_mac_802154_rdc_driver
  memset(&udpconn->ripaddr, 0, sizeof(udpconn->ripaddr));

#if RRPL_IS_SINK
  // Count sent OPT messages
  if(opt_seq_skip_counter >= DEFAULT_OPT_SEQ_SKIP) {
    // Increase sequence id => rebuild tree from scratch
    opt_seq_skip_counter = 0;
    my_seq_id++;
    if(my_seq_id > MAX_SEQNO)
      my_seq_id = 1;
  } else {
    opt_seq_skip_counter++;
  }
#endif // RRPL_IS_SINK
}
#endif // RRPL_IS_COORDINATOR

/*---------------------------------------------------------------------------*/
static void
send_rreq()
{

  char buf[MAX_PAYLOAD_LEN];
  PRINTF("RRPL: Send RREQ for ");
  PRINT6ADDR(&rreq_addr);
  PRINTF(" from ");
  PRINT6ADDR(&myipaddr);
  PRINTF("\n");

  struct rrpl_msg_rreq *rm = (struct rrpl_msg_rreq *)buf;

  rm->type = RRPL_RREQ_TYPE;
  rm->type = (rm->type << 4) | RRPL_RSVD1;
  rm->addr_len = RRPL_RSVD2;
  rm->addr_len = (rm->addr_len << 4) | RRPL_ADDR_LEN_IPV6;
  my_hseqno++;
  if(my_hseqno>MAX_SEQNO)
    my_hseqno = 1;
  rm->seqno = my_hseqno;
  rm->metric = RRPL_METRIC_HC;
  rm->metric = (rm->metric << 4) | RRPL_WEAK_LINK;
  rm->route_cost = 0;
  uip_ipaddr_copy(&rm->dest_addr, &rreq_addr);
  uip_ipaddr_copy(&rm->orig_addr, &myipaddr);
  udpconn->ttl = RRPL_MAX_DIST;
  uip_create_linklocal_lln_routers_mcast(&udpconn->ripaddr);
  PRINTF("RRPL: RREQ length %u\n", sizeof(struct rrpl_msg_rreq));
  uip_udp_packet_send(udpconn, buf, sizeof(struct rrpl_msg_rreq));
  memset(&udpconn->ripaddr, 0, sizeof(udpconn->ripaddr));
}

/*---------------------------------------------------------------------------*/
static void
send_rrep(uip_ipaddr_t *dest, uip_ipaddr_t *nexthop, uip_ipaddr_t *orig,
          uint16_t *seqno, unsigned hop_count)
{
  char buf[MAX_PAYLOAD_LEN];
  struct rrpl_msg_rrep *rm = (struct rrpl_msg_rrep *)buf;
  PRINTF("RRPL: Send RREP for orig ");
  PRINT6ADDR(orig);
  PRINTF(" dest ");
  PRINT6ADDR(dest);
  PRINTF(" nexthop ");
  PRINT6ADDR(nexthop);
  PRINTF(" hopcount=%u\n", hop_count);

  rm->type = RRPL_RREP_TYPE;
  rm->type = (rm->type << 4) | RRPL_RSVD1;
  rm->addr_len = RRPL_RSVD2;
  rm->addr_len = (rm->addr_len << 4) | RRPL_ADDR_LEN_IPV6;
  rm->seqno = *seqno;
  rm->metric = RRPL_METRIC_HC;
  rm->metric = (rm->metric << 4) | RRPL_WEAK_LINK;
  rm->route_cost = hop_count;
  uip_ipaddr_copy(&rm->orig_addr, orig);
  uip_ipaddr_copy(&rm->dest_addr, dest);
  udpconn->ttl = RRPL_MAX_DIST;
  uip_ipaddr_copy(&udpconn->ripaddr, nexthop);
  PRINTF("RRPL: RREP length: %u\n", sizeof(struct rrpl_msg_rrep));
  uip_udp_packet_send(udpconn, buf, sizeof(struct rrpl_msg_rrep));
  memset(&udpconn->ripaddr, 0, sizeof(udpconn->ripaddr));
}

/*---------------------------------------------------------------------------*/
static void
send_rerr(uip_ipaddr_t *src, uip_ipaddr_t *dest, uip_ipaddr_t *nexthop)
{
  char buf[MAX_PAYLOAD_LEN];
  struct rrpl_msg_rerr *rm = (struct rrpl_msg_rerr *)buf;
  PRINTF("RRPL: Send RERR towards src: ");
  PRINT6ADDR(src);
  PRINTF(" for address in error: ");
  PRINT6ADDR(dest);
  PRINTF(" nexthop: ");
  PRINT6ADDR(nexthop);
  PRINTF("\n");
  rm->type = RRPL_RERR_TYPE;
  rm->type = (rm->type << 4) | RRPL_RSVD1;
  rm->addr_len = RRPL_RSVD2;
  rm->addr_len = (rm->addr_len << 4) | RRPL_ADDR_LEN_IPV6;
  uip_ipaddr_copy(&rm->addr_in_error, dest);
  uip_ipaddr_copy(&rm->src_addr, src);
  udpconn->ttl = RRPL_MAX_DIST;
  uip_ipaddr_copy(&udpconn->ripaddr, nexthop);
  PRINTF("RRPL: RERR length: %u\n", sizeof(struct rrpl_msg_rerr));
  uip_udp_packet_send(udpconn, buf, sizeof(struct rrpl_msg_rerr));
  memset(&udpconn->ripaddr, 0, sizeof(udpconn->ripaddr));
}

/*---------------------------------------------------------------------------*/
#if RRPL_RREP_ACK
static void
send_rack(uip_ipaddr_t *src, uip_ipaddr_t *nexthop, uint16_t seqno)
{
  char buf[MAX_PAYLOAD_LEN];
  struct rrpl_msg_rack *rm = (struct rrpl_msg_rack *)buf;
  PRINTF("RRPL: Send RACK for src ");
  PRINT6ADDR(src);
  PRINTF(" nexthop ");
  PRINT6ADDR(nexthop);
  PRINTF("\n");
  rm->type = RRPL_RACK_TYPE;
  rm->type = (rm->type << 4) | RRPL_RSVD1;
  rm->addr_len = RRPL_RSVD2;
  rm->addr_len = (rm->addr_len << 4) | RRPL_ADDR_LEN_IPV6;
  uip_ipaddr_copy(&rm->src_addr, src);
  rm->seqno = seqno;
  udpconn->ttl = RRPL_MAX_DIST;
  uip_ipaddr_copy(&udpconn->ripaddr, nexthop);
  PRINTF("RRPL: RACK length: %u\n", sizeof(struct rrpl_msg_rack));
  uip_udp_packet_send(udpconn, buf, sizeof(struct rrpl_msg_rack));
  memset(&udpconn->ripaddr, 0, sizeof(udpconn->ripaddr));
}
#endif // RRPL_RREP_ACK


/*---------------------------------------------------------------------------*/
static void
handle_incoming_rreq(void)
{
  struct rrpl_msg_rreq *rm = (struct rrpl_msg_rreq *)uip_appdata;
  uip_ipaddr_t dest_addr, orig_addr;

  PRINTF("RRPL: RREQ ");
  PRINT6ADDR(&UIP_IP_BUF->srcipaddr);
  PRINTF(" -> ");
  PRINT6ADDR(&UIP_IP_BUF->destipaddr);
  PRINTF(" ttl=%u ", UIP_IP_BUF->ttl);
  PRINTF(" hop=%u ", rm->route_cost);
  PRINTF(" seq=%u ", rm->seqno);
  PRINTF(" orig ");
  PRINT6ADDR(&rm->orig_addr);
  PRINTF(" dest ");
  PRINT6ADDR(&rm->dest_addr);
  PRINTF("\r\n");

  if(rrpl_is_my_global_address(&rm->orig_addr)) {
    PRINTF("RRPL: RREQ loops back, not process it\n");
    return;
  }


  /* Do not add reverse route while receiving RREQ, only useful with LOADng without DODAG
  rt = rrpl_route_lookup(&rm->orig_addr);

  if(rt == NULL){
    PRINTF("RRPL: Inserting route from RREQ\n");
    rt = uip_ds6_route_add(&rm->orig_addr, DEFAULT_PREFIX_LEN,
            &UIP_IP_BUF->srcipaddr, rm->route_cost, rm->seqno, RRPL_R_HOLD_TIME);
  } else if(SEQNO_GREATER_THAN(rm->seqno,rt->state.seqno)
            || (rm->seqno==rt->state.seqno && rm->route_cost < rt->state.route_cost)){
    PRINTF("RRPL: Update route from RREQ\n");
    uip_ipaddr_copy(&rt->nexthop, &UIP_IP_BUF->srcipaddr);
    rt->state.seqno = rm->seqno;
    rt->state.route_cost = rm->route_cost;
    rt->state.valid_time = RRPL_R_HOLD_TIME;
  } else {
    PRINTF("RRPL: Not a better route for inserting (RREQ)\n");
  }

  */

  if(rrpl_is_my_global_address(&rm->dest_addr)) { /* RREQ for our address */
    // FIXME: if we already have seen this RREQ, we retransmit RREP !! (see below)
    PRINTF("RRPL: RREQ for our address\n");
    uip_ipaddr_copy(&dest_addr, &rm->orig_addr);
    uip_ipaddr_copy(&orig_addr, &rm->dest_addr);
    my_hseqno++;
    if(my_hseqno > MAX_SEQNO)
      my_hseqno = 1;
    send_rrep(&dest_addr, &UIP_IP_BUF->srcipaddr, &orig_addr, &my_hseqno, 0); // FIXME: next hop = srcipaddr => we go on another branch of the tree…
  } else if (RRPL_IS_COORDINATOR()) {  //only coordinator forward RREQ
    if(UIP_IP_BUF->ttl > 1) { /* TTL still valid for forwarding */

      // FIXME: should do that even if it is our address
      /* Have we seen this RREQ before? */
      if(fwc_lookup(&rm->orig_addr, &rm->seqno)) {
        PRINTF("RRPL: RREQ cached, not forward it\n");
        return;
      }
      fwc_add(&rm->orig_addr, &rm->seqno);

      PRINTF("RRPL: forward RREQ\n");
      rm->route_cost++;
      udpconn->ttl = UIP_IP_BUF->ttl - 1;
      uip_create_linklocal_lln_routers_mcast(&udpconn->ripaddr);
      rrpl_rand_wait();
      uip_udp_packet_send(udpconn, rm, sizeof(struct rrpl_msg_rreq));
      memset(&udpconn->ripaddr, 0, sizeof(udpconn->ripaddr));
    }
  }
}
/*---------------------------------------------------------------------------*/
static void
handle_incoming_rrep(void)
{
  struct rrpl_msg_rrep *rm = (struct rrpl_msg_rrep *)uip_appdata;
  struct uip_ds6_route *rt;
  uip_ipaddr_t *nexthop;

  // No multicast RREP: drop
  if(uip_ipaddr_cmp(&UIP_IP_BUF->destipaddr, &mcastipaddr)) {
    return;
  }

  PRINTF("RRPL: RREP ");
  PRINT6ADDR(&UIP_IP_BUF->srcipaddr);
  PRINTF(" -> ");
  PRINT6ADDR(&UIP_IP_BUF->destipaddr);
  PRINTF(" ttl=%u ", UIP_IP_BUF->ttl);
  PRINTF(" hop=%u ", rm->route_cost);
  PRINTF(" seq=%u ", rm->seqno);
  PRINTF(" orig ");
  PRINT6ADDR(&rm->orig_addr);
  PRINTF(" dest ");
  PRINT6ADDR(&rm->dest_addr);
  PRINTF("\r\n");

  rt = rrpl_route_lookup(&rm->orig_addr);

  // New forward route?
  if(rt == NULL) {
    PRINTF("RRPL: Inserting route from RREP\n");
    rt = uip_rrpl_route_add(&rm->orig_addr, DEFAULT_PREFIX_LEN,
            &UIP_IP_BUF->srcipaddr, rm->route_cost, rm->seqno);
    if(rt != NULL) {
#if RRPL_RREP_ACK
      rt->state.ack_received = 0; /* Pending route for ACK */
#else
      rt->state.ack_received = 1;
#endif
    }
  } else if(SEQNO_GREATER_THAN(rm->seqno, rt->state.seqno)
          || (rm->seqno == rt->state.seqno && rm->route_cost < rt->state.route_cost)) {
    PRINTF("RRPL: Update route from RREP\n");
    uip_ds6_route_rm(rt);
    uip_rrpl_route_add(&rm->orig_addr, DEFAULT_PREFIX_LEN,
            &UIP_IP_BUF->srcipaddr, rm->route_cost, rm->seqno);
  } else {
    PRINTF("RRPL: Not a better route for inserting (RREP)\n");
  }

  /* Forward RREP towards originator? */
  if(uip_ipaddr_cmp(&rm->dest_addr, &myipaddr)) {
    PRINTF("RRPL: Received RREP to our own RREQ\n");
#if RRPL_RREQ_RETRIES
    //remove route request cache
    rrc_remove(&rm->orig_addr);
#endif
  } else {
    //rt = rrpl_route_lookup(&rm->dest_addr);
    nexthop = uip_ds6_defrt_choose();
    if(nexthop == NULL) {
      PRINTF("RRPL: RREP received, but no default route to originator\n");
      // No ACK and RREP forwarding
      return;
    }
    // Send ACK
#if RRPL_RREP_ACK
    send_rack(&rm->orig_addr, &UIP_IP_BUF->srcipaddr, rm->seqno);
#endif

    PRINTF("RRPL: Forward RREP to ");
    PRINT6ADDR(nexthop);
    PRINTF("\n");
    rm->route_cost++;
    udpconn->ttl = 1;
    uip_ipaddr_copy(&udpconn->ripaddr, nexthop);
    uip_udp_packet_send(udpconn, rm, sizeof(struct rrpl_msg_rrep));
    memset(&udpconn->ripaddr, 0, sizeof(udpconn->ripaddr));

  }
}

/*---------------------------------------------------------------------------*/
static void
handle_incoming_rack(void)
{
  struct rrpl_msg_rack *rm = (struct rrpl_msg_rack *)uip_appdata;
  struct uip_ds6_route *rt;


  PRINTF("RRPL: RACK ");
  PRINT6ADDR(&UIP_IP_BUF->srcipaddr);
  PRINTF(" -> ");
  PRINT6ADDR(&UIP_IP_BUF->destipaddr);
  PRINTF(" ttl=%u ", UIP_IP_BUF->ttl);
  PRINTF(" seq=%u ", rm->seqno);
  PRINTF(" src ");
  PRINT6ADDR(&rm->src_addr);
  PRINTF("\n");

  rt = rrpl_route_lookup(&rm->src_addr);

  /* No route? */
  if(rt == NULL) {
    PRINTF("RRPL: Receved RACK for non-existing route\n");
  } else {
    rt->state.ack_received = 1; /* Make pending route valid */
  }

}

/*---------------------------------------------------------------------------*/
static void
handle_incoming_rerr(void)
{
  struct rrpl_msg_rerr *rm = (struct rrpl_msg_rerr *)uip_appdata;
  struct uip_ds6_route *rt_in_err;
  struct uip_ds6_route *rt;
  uip_ds6_defrt_t *defrt;

  #if USE_OPT
  uip_ipaddr_t mcastLoadAddr;
  uip_create_linklocal_lln_routers_mcast(&mcastLoadAddr);
  #endif //USE_OPT



  PRINTF("RRPL: RERR ");
  PRINT6ADDR(&UIP_IP_BUF->srcipaddr);
  PRINTF(" -> ");
  PRINT6ADDR(&UIP_IP_BUF->destipaddr);
  PRINTF(" ttl=%u ", UIP_IP_BUF->ttl);
  PRINTF(" towards ");
  PRINT6ADDR(&rm->src_addr);
  PRINTF(" addr in error : ");
  PRINT6ADDR(&rm->addr_in_error);
  PRINTF("\r\n");

  rt_in_err = rrpl_route_lookup(&rm->addr_in_error);
  rt = rrpl_route_lookup(&rm->src_addr);

  // It may happen that the address in error is mine... Stop here !
  if(rrpl_is_my_global_address(&rm->addr_in_error)) {
    return;
  }

  /* No route? */
  if(rt_in_err == NULL) {
    PRINTF("RRPL: Received RERR for non-existing route\n");
  } else {
    uip_ds6_route_rm(rt_in_err); /* Remove route */
  }

  #if USE_OPT
  // if the RERR comes from a default router and it's for me, send spontaneous RREP
  defrt = uip_ds6_defrt_lookup(&UIP_IP_BUF->srcipaddr);
  if(defrt != NULL && rrpl_is_my_global_address(&rm->src_addr)) {
    PRINTF("RRPL: Spontaneously send RREP\n");
    my_hseqno++;
    send_rrep(&my_sink_id, &defrt->ipaddr, &myipaddr, &my_hseqno, 0);
    return;
  }
  // otherwise, if there is a matching tupple, send along default route

  #endif //USE_OPT
  // Draft draft-clausen-lln-rrpl-10#section-14.3 : still forward even if no matching routing tupple found
  if(rt != NULL) {
    send_rerr(&rm->src_addr, &rm->addr_in_error, uip_ds6_route_nexthop(rt));
  } /* Forward RERR to nexthop */
  #if USE_OPT
  // If the RERR was multicast and I had a route, send along default route
  // If not multicast, send along default route
  else if(!uip_ipaddr_cmp(&UIP_IP_BUF->destipaddr, &mcastLoadAddr) || rt_in_err != NULL) {
    if(!rrpl_is_my_global_address(&rm->src_addr))
      send_rerr(&rm->src_addr, &rm->addr_in_error, uip_ds6_defrt_choose());
  }
  #endif //USE_OPT

}

/*---------------------------------------------------------------------------*/
void
reinitialize_default_route(void)
{
  my_rank = 255;
  my_weaklink = 255;
  my_parent_rssi = -126;
  my_seq_id = 0;
  uip_ds6_defrt_t *defrt;
  defrt = uip_ds6_defrt_lookup(&def_rt_addr);
  if(defrt != NULL) {
    uip_ds6_defrt_rm(defrt);
  }
}

/*---------------------------------------------------------------------------*/
/* Change the default route to the specified one. */
#if ! RRPL_IS_SINK
static void
change_default_route(struct rrpl_msg_opt *rm)
{
  uip_ds6_defrt_t *defrt;
  my_rank = rm->rank + 1;
  my_weaklink = get_weaklink(rm->metric);
  // add default route
  defrt = uip_ds6_defrt_lookup(&def_rt_addr);
  // First check if we are actually changing of next hop!
  if(defrt != NULL) {
    if(!uip_ip6addr_cmp(&defrt->ipaddr, &UIP_IP_BUF->srcipaddr)) {
      PRINTF("Actually changing of defrt next hop!\n");
      uip_ds6_defrt_rm(defrt); // remove route
    } else {
      // We just need to refresh the route
      stimer_set(&defrt->lifetime, RRPL_DEFAULT_ROUTE_LIFETIME);
      return;
    }
  }

  // Flush all routes. If I'm changing of parent, It means this new parent does not know about
  // the nodes below me anyway, so better not keep stale entries.
  // Moreover, keeping old entries and changing parents can break the loop avoidance mechanism.
  rrpl_flush_routes();

  in_rrpl_call = 1;

  PRINTF("RRPL: call uip_rrpl_nbr_add\n");
  uip_rrpl_nbr_add(&UIP_IP_BUF->srcipaddr);

  uip_ds6_defrt_add(&UIP_IP_BUF->srcipaddr, RRPL_DEFAULT_ROUTE_LIFETIME);
  uip_ipaddr_copy(&def_rt_addr, &UIP_IP_BUF->srcipaddr);

#if RRPL_IS_COORDINATOR()
  ctimer_set(&sendmsg_ctimer, random_rand() / 1000,
          (void (*)(void *))send_opt, NULL);
#endif

  // FIXME: code specific to beacon-enabled
//   uip_lladdr_t coord_addr;
//   memcpy(&coord_addr, &UIP_IP_BUF->srcipaddr.u8[8], UIP_LLADDR_LEN);
//   coord_addr.addr[0] ^= 2;
//   NETSTACK_RDC_CONFIGURATOR.coordinator_choice((void *) &coord_addr,
//       rm->rank);
  in_rrpl_call = 0;
}
#endif // ! RRPL_IS_SINK

/*---------------------------------------------------------------------------*/
#if ! RRPL_IS_SINK
static void
handle_incoming_opt(void)
{
  uint8_t parent_changed = 0;
  uint8_t opt_weaklink = 0;
  // FIXME: code specific to beacon-enabled
//   if (NETSTACK_RDC_CONFIGURATOR.use_routing_information()) {
  struct rrpl_msg_opt *rm = (struct rrpl_msg_opt *)uip_appdata;
  PRINTF("RRPL: OPT message: ");
  PRINT6ADDR(&UIP_IP_BUF->srcipaddr);
  PRINTF(" -> ");
  PRINT6ADDR(&UIP_IP_BUF->destipaddr);
  PRINTF(" ttl=%u ", UIP_IP_BUF->ttl);
  PRINTF(" rank=%d ", rm->rank);
  PRINTF(" seq=%d ", rm->seqno);
  PRINTF(" rssi=%i\n", (int8_t)LAST_RSSI);

  if(uip_ipaddr_cmp(&UIP_IP_BUF->srcipaddr, &myipaddr)) {
    PRINTF("RRPL: OPT loops back, not processing\n");
    return;
  }

  if(SEQNO_GREATER_THAN(rm->seqno, my_seq_id)) {
    // First OPT with this seqno
    PRINTF("RRPL: new OPT sequence number received\n");
    my_seq_id = rm->seqno;
    parent_changed = 1;
  } else if(rm->seqno == my_seq_id ){
    opt_weaklink = get_weaklink(rm->metric) + parent_weaklink((int8_t)LAST_RSSI);
    if(opt_weaklink < my_weaklink + parent_weaklink(my_parent_rssi)) { /* less weak links */
      parent_changed = 1;
      PRINTF("less weak links\n");
    } else if(opt_weaklink == my_weaklink + parent_weaklink(my_parent_rssi)){ /* weak link ties */
      if(rm->rank < (my_rank - 1)) { /* better rank */
        parent_changed = 1;
        PRINTF("better rank\n");
      }
//      else if (!uip_ipaddr_cmp(&UIP_IP_BUF->srcipaddr, &def_rt_addr) && my_parent_rssi < (int8_t)LAST_RSSI){
//        parent_changed = 1;
//        PRINTF("addr  -- "); PRINT6ADDR(&UIP_IP_BUF->srcipaddr);printf("   "); PRINT6ADDR(&def_rt_addr);printf("\n");
//      }
    }
  }

  if(parent_changed) {
    uip_ipaddr_copy(&my_sink_id, &rm->sink_addr);
    my_parent_rssi = (int8_t)LAST_RSSI;
    PRINTF("RRPL: Update from received OPT r=%u wl=%u rssi=%i\n", my_rank, my_weaklink + parent_weaklink(my_parent_rssi), my_parent_rssi);
    change_default_route(rm);
#if RRPL_IS_SKIP_LEAF
    my_hseqno++;
    if(my_hseqno>MAX_SEQNO)
      my_hseqno = 1;
    nexthop = uip_ds6_defrt_choose();
       send_rrep(&rm->sink_addr, nexthop, &myipaddr, &my_hseqno, 0);
#endif // RRPL_IS_SKIP_LEAF
    } else {
       PRINTF("RRPL: Not a better rank/RSSI\n");
    }
}
#endif // ! RRPL_IS_SINK

/*---------------------------------------------------------------------------*/
static void
print_local_addresses(void)
{
  int i;
  uint8_t state;

  PRINTF("RRPL IPv6 addresses: \n");
  for(i = 0; i < UIP_DS6_ADDR_NB; i++) {
    state = uip_ds6_if.addr_list[i].state;
    if(uip_ds6_if.addr_list[i].isused &&
       (state == ADDR_TENTATIVE || state == ADDR_PREFERRED)) {
      PRINTF("- ");
      PRINT6ADDR(&uip_ds6_if.addr_list[i].ipaddr);
      PRINTF("\n");
    }
  }
}

/*---------------------------------------------------------------------------*/
static void
tcpip_handler(void)
{
  uint8_t type;
  if(uip_newdata()) {

    struct rrpl_msg *m = (struct rrpl_msg *)uip_appdata;
    type = m->type >> 4;
    switch(type) {
      case RRPL_RREQ_TYPE:
        PRINTF("RRPL: Received RREQ\n");
        handle_incoming_rreq();
        break;
      case RRPL_RREP_TYPE:
        PRINTF("RRPL: Received RREP\n");
        handle_incoming_rrep();
        break;
      case RRPL_RERR_TYPE:
        PRINTF("RRPL: Received RERR\n");
        handle_incoming_rerr();
        break;
      case RRPL_RACK_TYPE:
        PRINTF("RRPL: Received RACK\n");
        handle_incoming_rack();
        break;
      case RRPL_OPT_TYPE:
#if RRPL_IS_SINK
        PRINTF("RRPL: Recieved OPT. Skipping: is a sink\n");
#else
        PRINTF("RRPL: Received OPT\n");
        handle_incoming_opt();
#endif // RRPL_IS_SINK
        break;
      case RRPL_QRY_TYPE:
#if RRPL_IS_COORDINATOR()
        PRINTF("RRPL: Received QRY -- Send OPT\n");
        rrpl_rand_wait();
        send_opt();
#else
        PRINTF("RRPL: Received QRY. Skipping: not a coordinator\n");
#endif // RRPL_IS_COORDINATOR()
        break;
    }
  }
}

/*---------------------------------------------------------------------------*/
uint8_t
rrpl_addr_matches_local_prefix(uip_ipaddr_t *host)
{
  return uip_ipaddr_prefixcmp(&local_prefix, host, local_prefix_len);
}

/*---------------------------------------------------------------------------*/
/* Look for the route to a specified host. */
void
rrpl_request_route_to(uip_ipaddr_t *host)
{

  if(in_rrpl_call) {
    return;
  }
#if !RRPL_IS_SINK && USE_OPT
  // Schedule QRY transmission: if we are here, it's because we've lost our default next hop
  PROCESS_CONTEXT_BEGIN(&rrpl_process);
  enable_qry();
  PROCESS_CONTEXT_END(&rrpl_process) ;
  return; // only sink sends RREQ
#endif
  if(!rrpl_addr_matches_local_prefix(host)) {
    PRINTF("No RREQ for non-local address\n");
    //no local prefix matches this addr, no RREQ for non-local address
    return;
  }
#if RRPL_RREQ_RATELIMIT
  if(!timer_expired(&next_time)) {
     PRINTF("RRPL: RREQ exceeds rate limit");
     return;
  }
#endif

  PRINTF("RRPL: Request for route ");
  PRINT6ADDR(host);
  PRINTF("\n");
  if(uip_ds6_addr_lookup(host) == NULL) {
    uip_ipaddr_copy(&rreq_addr, host);
    command = COMMAND_SEND_RREQ;
    process_post(&rrpl_process, PROCESS_EVENT_MSG, NULL);
#if RRPL_RREQ_RETRIES
    if(!rrc_lookup(&rreq_addr)) {
      rrc_add(&rreq_addr);
    }
#endif
  } else {
    PRINTF("RRPL: Request for our address. Do nothing\n");
  }
#if RRPL_RREQ_RATELIMIT
  timer_set(&next_time, CLOCK_SECOND/RRPL_RREQ_RATELIMIT);
#endif
}

/*---------------------------------------------------------------------------*/
void
rrpl_no_route(uip_ipaddr_t *dest, uip_ipaddr_t *src)
{
  struct uip_ds6_route *rt = NULL;
  uip_ipaddr_t nexthop;
  uip_ipaddr_t *nexthptr = &nexthop;
  rt = rrpl_route_lookup(src);
  PRINTF("rrpl_no_route(): dest:"); PRINT6ADDR(dest); PRINTF(" src:");PRINT6ADDR(src);PRINTF("\n");
  if(rt == NULL){
    PRINTF("rt is NULL\n");
    #if USE_OPT
    // multicast RERR so the neighbors are notified -- this is helpful if a node has lost memory
    uip_create_linklocal_lln_routers_mcast(nexthptr);
    PRINTF("send to: "); PRINT6ADDR(nexthptr);PRINTF("\n");
    #else
    PRINTF("RRPL: Send a RERR with no route source address\n");
    return;
    #endif //USE_OPT
  }
  else{
    nexthptr=uip_ds6_route_nexthop(rt);
  }
  uip_ipaddr_copy(&rerr_bad_addr, dest);
  uip_ipaddr_copy(&rerr_src_addr, src);
  uip_ipaddr_copy(&rerr_next_addr, nexthptr);
  command = COMMAND_SEND_RERR;
  process_post(&rrpl_process, PROCESS_EVENT_MSG, NULL);
}

/*---------------------------------------------------------------------------*/
void
rrpl_set_local_prefix(uip_ipaddr_t *prefix, uint8_t len)
{
  uip_ipaddr_copy(&local_prefix, prefix);
  local_prefix_len = len;
}

/*---------------------------------------------------------------------------*/
void
get_prefix_from_addr(uip_ipaddr_t *addr, uip_ipaddr_t *prefix, uint8_t len)
{
  uint8_t i;
  local_prefix_len = len;
  for(i = 0; i < 16; i++) {
    if(i < len/8)
    {
       prefix->u8[i] = addr->u8[i];
    } else {
       prefix->u8[i] = 0;

    }
  }
}

/*---------------------------------------------------------------------------*/
uint8_t
rrpl_is_my_global_address(uip_ipaddr_t *addr)
{
  int i;
  int state;

  for(i = 0; i < UIP_DS6_ADDR_NB; i++) {
    state = uip_ds6_if.addr_list[i].state;
    if(uip_ds6_if.addr_list[i].isused &&
       (state == ADDR_TENTATIVE || state == ADDR_PREFERRED)) {
       if (uip_ipaddr_cmp(addr, &uip_ds6_if.addr_list[i].ipaddr)){
          return 1 ;
       }
    }
  }
  return 0;
}

/*---------------------------------------------------------------------------*/
PROCESS_THREAD(rrpl_process, ev, data)
{
  static struct etimer et;

  PROCESS_BEGIN();
  PRINTF("RRPL process started\n");
#if RRPL_IS_SINK
  my_seq_id = 1;
  my_rank = 1;
  my_weaklink = 0;
  my_parent_rssi = 126;
  opt_seq_skip_counter = 0;
#else
  my_seq_id = 0;
  my_rank = RRPL_MAX_RANK;
  my_weaklink = 255;
  my_parent_rssi = -126;
#endif
  PRINTF("RRPL is sink: %s\n", RRPL_IS_SINK ? "yes" : "no");

  my_hseqno = 1;
  print_local_addresses();
  get_global_addr(&myipaddr);
  get_prefix_from_addr(&myipaddr, &local_prefix, DEFAULT_LOCAL_PREFIX);
  uip_create_linklocal_lln_routers_mcast(&mcastipaddr);
  uip_create_linklocal_empty_addr(&def_rt_addr);
  uip_ds6_maddr_add(&mcastipaddr);
  /* new connection UDP */
  udpconn = udp_new(NULL, UIP_HTONS(RRPL_UDPPORT), NULL);
  udp_bind(udpconn, UIP_HTONS(RRPL_UDPPORT));

  PRINTF("RRPL: Created an UDP socket");
  PRINTF(" (local/remote port %u/%u)\n",
        UIP_HTONS(udpconn->lport), UIP_HTONS(udpconn->rport));

  if (RRPL_IS_COORDINATOR()) {
    PRINTF("RRPL: Set timer for OPT multicast %lu\n", SEND_INTERVAL);
    etimer_set(&et, SEND_INTERVAL);
    memset(&ipaddr, 0, sizeof(ipaddr));
  }
#if RRPL_RREQ_RETRIES
  PRINTF("RRPL: Set timer for RREQ retry %u\n", RETRY_CHECK_INTERVAL);
  etimer_set(&dfet, RETRY_CHECK_INTERVAL);
#endif

#if RRPL_RREQ_RATELIMIT
  timer_set(&next_time, CLOCK_SECOND/RRPL_RREQ_RATELIMIT);
#endif

#if RRPL_R_HOLD_TIME
  PRINTF("RRPL: Set timer for route validity time check %u\n", RV_CHECK_INTERVAL);
  etimer_set(&rv, RV_CHECK_INTERVAL);
#endif
  while(1) {
    PROCESS_YIELD();

    if(ev == tcpip_event) {
      tcpip_handler();
    }

#if RRPL_IS_COORDINATOR()
    if(etimer_expired(&et)) {
      send_opt();
//       uip_ds6_route_print();
      etimer_restart(&et);
    }
#endif // RRPL_IS_COORDINATOR()

#if SND_QRY && ! RRPL_IS_SINK
    // QRY timer
    if(etimer_expired(&eqryt)) {
      if(uip_ds6_defrt_lookup(&def_rt_addr) == NULL) {
        // Still no route, send QRY and reschedule
        send_qry();
      }
    }
#endif // SND_QRY && ! RRPL_IS_SINK

#if RRPL_RREQ_RETRIES
    if(etimer_expired(&dfet)) {
      rrc_check_expired_rreq(RETRY_CHECK_INTERVAL);
      etimer_restart(&dfet);
    }
#endif

#if RRPL_R_HOLD_TIME
    if(etimer_expired(&rv)) {
      rrpl_check_expired_route(RV_CHECK_INTERVAL);
      etimer_restart(&rv);
    }
#endif // RRPL_R_HOLD_TIME

    if(ev == PROCESS_EVENT_MSG) {
        if(command == COMMAND_SEND_RREQ) {
            PRINTF("RRPL: Send RREQ\n");
            ctimer_set(&sendmsg_ctimer, random_rand()%50 * CLOCK_SECOND / 1000,
                     (void (*)(void *))send_rreq, NULL);
        } else if (command == COMMAND_SEND_RERR) {
          send_rerr(&rerr_src_addr, &rerr_bad_addr, &rerr_next_addr);
        }
        command = COMMAND_NONE;
    }
  }

  PROCESS_END();
}

#endif // WITH_IPV6_RRPL
/*---------------------------------------------------------------------------*/
