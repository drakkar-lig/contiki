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
 * $Id: lrp.c,v 1.37 2010/01/20 09:58:16 chianhla Exp $
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
#include "net/lrp/lrp-def.h"
#include "net/lrp/lrp.h"
#include "contiki-net.h"


#include <string.h>

#if WITH_IPV6_LRP

#define DEBUG 1
#include "net/ip/uip-debug.h"

/* Exponential parameter for QRY sending. @see send_qry */
#define QRY_EXP_PARAM           0.80

#define LRP_MAX_RANK           127

/* Frequency of DIO broadcasting (in ticks) */
#define SEND_DIO_INTERVAL       100 * CLOCK_SECOND

/* RREQ retransmission interval (in ticks) */
#define RETRY_RREQ_INTERVAL     5 * CLOCK_SECOND / 1000

#define RV_CHECK_INTERVAL       10 * CLOCK_SECOND
#define MAX_PAYLOAD_LEN         50
#define DEFAULT_PREFIX_LEN      128
#define DEFAULT_LOCAL_PREFIX    64
#define DEFAULT_DIO_SEQ_SKIP    4
extern uip_ds6_route_t uip_ds6_routing_table[UIP_DS6_ROUTE_NB];
#define UIP_IP_BUF ((struct uip_udpip_hdr *)&uip_buf[UIP_LLH_LEN])
#define MAX_SEQNO               65534
#define SEQNO_GREATER_THAN(s1, s2)                   \
          (((s1 > s2) && (s1 - s2 <= (MAX_SEQNO/2))) \
        || ((s2 > s1) && (s2 - s1 > (MAX_SEQNO/2))))
#define SEQNO_INCREASE(seqno) (seqno >= MAX_SEQNO ? seqno = 1 : ++seqno)
#if LRP_RREQ_RATELIMIT
static struct timer rreq_ratelimit_timer;
#endif

#if SND_QRY && ! LRP_IS_SINK
static struct etimer qry_timer;
#endif /* SND_QRY && ! LRP_IS_SINK */

#if LRP_IS_COORDINATOR()
static struct etimer send_dio_et;
#endif /* LRP_IS_COORDINATOR() */

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
#if LRP_IS_SINK
static uint8_t dio_seq_skip_counter;
#endif /* LRP_IS_SINK */
static uip_ipaddr_t local_prefix;
static uip_ipaddr_t myipaddr, mcastipaddr;
static uip_ipaddr_t rreq_addr, def_rt_addr, my_sink_addr;
static struct uip_udp_conn *udpconn;
static uip_ipaddr_t rerr_bad_addr, rerr_src_addr, rerr_next_addr;
static uint8_t in_lrp_call = 0 ; // make sure we don't trigger a rreq from within lrp

#if SND_QRY && ! LRP_IS_SINK
static uint16_t qry_exp_residuum;
#endif /* SND_QRY && ! LRP_IS_SINK */

/*---------------------------------------------------------------------------*/
PROCESS(lrp_process, "LRP process");

/*---------------------------------------------------------------------------*/
/* Implementation of route validity time check and purge */
#if LRP_R_HOLD_TIME
static void
lrp_check_expired_route(uint16_t interval)
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
#endif /* LRP_R_HOLD_TIME */


/*---------------------------------------------------------------------------*/
/* Implementation of route flush */
#if ! LRP_IS_SINK
static void
lrp_flush_routes()
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
/* Implementation of Route Request Cache for LRP_RREQ_RETRIES and
 * LRP_NET_TRAVERSAL_TIME */
#if LRP_RREQ_RETRIES
#define RRCACHE 2 /* Size of the cache */

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
  rrcache[n].expire_time = 2 * LRP_NET_TRAVERSAL_TIME;
  rrcache[n].request_time = 1;
  uip_ipaddr_copy(&rrcache[n].dest, dest);
}

/* Check the expired RREQ. `interval` is the time interval between last check
 * and now (expressed in ticks). */
static void
rrc_check_expired_rreq(const uint16_t interval)
{
  int i;
  for(i = 0; i < RRCACHE; ++i) {
    rrcache[i].expire_time -= interval;
    if(rrcache[i].expire_time <= 0) {
      lrp_request_route_to(&rrcache[i].dest);
      rrcache[i].request_time++;
      if(rrcache[i].request_time == LRP_RREQ_RETRIES) {
         rrc_remove(&rrcache[i].dest);
      } else {
         rrcache[i].expire_time = 2 * LRP_NET_TRAVERSAL_TIME;
      }
    }
  }
}
#endif /* LRP_RREQ_RETRIES */


/*---------------------------------------------------------------------------*/
static inline uint8_t
get_weaklink(uint8_t metric)
{
  return (metric & 0x0f);
}

/*---------------------------------------------------------------------------*/
static inline uint8_t
parent_weaklink(int8_t rssi)
{
  return ((rssi > LRP_RSSI_THRESHOLD) ? 0 : 1);
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

/*---------------------------------------------------------------------------*/
static void
uip_lrp_nbr_add(uip_ipaddr_t* next_hop)
{
#if !UIP_ND6_SEND_NA
  uip_ds6_nbr_t *nbr = NULL;
  // it's my responsability to create+maintain neighbor
  nbr = uip_ds6_nbr_lookup(next_hop);

  if(nbr == NULL) {
    PRINTF("adding nbr from lrp\n");
    uip_lladdr_t nbr_lladdr;
    memcpy(&nbr_lladdr, &next_hop->u8[8],
           UIP_LLADDR_LEN);

    nbr_lladdr.addr[0] ^= 2;
    nbr = uip_ds6_nbr_add(next_hop, &nbr_lladdr, 0, NBR_REACHABLE);
//    nbr->nscount = 1;

  } else {
    PRINT6ADDR(&nbr->ipaddr);
    PRINTF("\n");
  }

#endif /* !UIP_ND6_SEND_NA */
}

/*---------------------------------------------------------------------------*/
static void
lrp_rand_wait()
{
#if LRP_RANDOM_WAIT == 1
      PRINTF("Waiting rand time\n");
      clock_wait(random_rand() % 50 * CLOCK_SECOND / 100);
      PRINTF("Done waiting rand time\n");
#endif
}

/*---------------------------------------------------------------------------*/
/* Add the described route into the routing table. Do not add route if it is
 * worse than previous one. Return NULL if the route has not been added, or
 * the added route. */
static uip_ds6_route_t*
uip_lrp_route_add(uip_ipaddr_t* orig_addr, uint8_t length,
            uip_ipaddr_t* next_hop, uint8_t route_cost, uint16_t seqno)
{
  uip_ds6_route_t* rt;

  in_lrp_call = 1;

  rt = uip_ds6_route_lookup(orig_addr);
  if (rt == NULL ||
      SEQNO_GREATER_THAN(seqno, rt->state.seqno) ||
      (seqno == rt->state.seqno && route_cost < rt->state.route_cost)) {
    // Offered route is better than previous one
    uip_lrp_nbr_add(next_hop);
    if (rt == NULL) {
      rt = uip_ds6_route_add(orig_addr, length, next_hop);
    }
    if(rt != NULL) {
      rt->state.route_cost = route_cost;
      rt->state.seqno = seqno;
      rt->state.valid_time = LRP_R_HOLD_TIME;
    }
  } else {
    // Offered route is worse, refusing route
    rt = NULL;
  }

  in_lrp_call = 0;
  return rt;
}

/*---------------------------------------------------------------------------*/
static uint8_t
lrp_is_my_global_address(uip_ipaddr_t *addr)
{
  int i;
  int state;

  for(i = 0; i < UIP_DS6_ADDR_NB; i++) {
    state = uip_ds6_if.addr_list[i].state;
    if(uip_ds6_if.addr_list[i].isused &&
        (state == ADDR_TENTATIVE || state == ADDR_PREFERRED)) {
      if(uip_ipaddr_cmp(addr, &uip_ds6_if.addr_list[i].ipaddr)) {
        return 1;
      }
    }
  }
  return 0;
}

/*---------------------------------------------------------------------------*/
/* Return true if `addr` is a predecessor, that is, is used as next hop into
 * the routing table */
#if !LRP_IS_SINK
static uint8_t
lrp_is_predecessor(uip_ipaddr_t *addr)
{
  uip_ds6_route_t* r;

  if (addr == NULL) {
    // Unknown neighor, not a predecessor
    return (0==1);
  }

  for(r = uip_ds6_route_head(); r != NULL; r = uip_ds6_route_next(r)) {
    if(memcmp(uip_ds6_route_nexthop(r), addr, sizeof(uip_ipaddr_t)) == 0) {
      // Found as route's next hop => is a predecessor
      return (1==1);
    }
  }
  return (0==1);
}
#endif /* !LRP_IS_SINK */

/*---------------------------------------------------------------------------*/
static void
reinitialize_default_route(void)
{
  my_rank = 255;
  my_weaklink = 255;
  my_parent_rssi = -126;
  my_seq_id = 0;
  uip_ds6_defrt_t *defrt;
  ANNOTATE("#L %u 0\n", def_rt_addr.u8[sizeof(def_rt_addr) - 1]);
  defrt = uip_ds6_defrt_lookup(&def_rt_addr);
  if(defrt != NULL) {
    uip_ds6_defrt_rm(defrt);
  }
}

/*---------------------------------------------------------------------------*/
/* Change default route for the one specified into the DIO `rm` packet. */
#if ! LRP_IS_SINK
static void
change_default_route(struct lrp_msg_dio *rm)
{
  uip_ds6_defrt_t *defrt;
  my_rank = rm->rank + 1;
  my_weaklink = get_weaklink(rm->metric);
  // add default route
  defrt = uip_ds6_defrt_lookup(&def_rt_addr);
  // First check if we are actually changing of next hop!
  if(defrt != NULL) {
    if(!uip_ip6addr_cmp(&defrt->ipaddr, &UIP_IP_BUF->srcipaddr)) {
      uip_ds6_defrt_rm(defrt); // remove route
    } else {
      // We just need to refresh the route
      stimer_set(&defrt->lifetime, LRP_DEFAULT_ROUTE_LIFETIME);
      return;
    }
  }

  // Flush all routes. If I'm changing of parent, It means this new parent
  // does not know about the nodes below me anyway, so better not keep stale
  // entries. Moreover, keeping old entries and changing parents can break the
  // loop avoidance mechanism.
  lrp_flush_routes();

  in_lrp_call = 1;

  uip_lrp_nbr_add(&UIP_IP_BUF->srcipaddr);

  uip_ds6_defrt_add(&UIP_IP_BUF->srcipaddr, LRP_DEFAULT_ROUTE_LIFETIME);
  ANNOTATE("#L %u 0\n", def_rt_addr.u8[sizeof(def_rt_addr) - 1]);
  uip_ipaddr_copy(&def_rt_addr, &UIP_IP_BUF->srcipaddr);
  ANNOTATE("#L %u 1;red\n", def_rt_addr.u8[sizeof(def_rt_addr) - 1]);

#if LRP_IS_COORDINATOR()
  etimer_set(&send_dio_et, random_rand() % 50 * CLOCK_SECOND / 100);
#endif

  // FIXME: code specific to beacon-enabled
//   uip_lladdr_t coord_addr;
//   memcpy(&coord_addr, &UIP_IP_BUF->srcipaddr.u8[8], UIP_LLADDR_LEN);
//   coord_addr.addr[0] ^= 2;
//   NETSTACK_RDC_CONFIGURATOR.coordinator_choice((void *) &coord_addr,
//       rm->rank);
  in_lrp_call = 0;
}
#endif /* ! LRP_IS_SINK */

/*---------------------------------------------------------------------------*/
/* Format and broadcast a QRY packet. */
#if SND_QRY && !LRP_IS_SINK
static void
send_qry()
{
  char buf[MAX_PAYLOAD_LEN];
  struct lrp_msg_qry *rm = (struct lrp_msg_qry *)buf;

  PRINTF("Broadcast QRY\n");

  rm->type = LRP_QRY_TYPE;
  rm->type = (rm->type << 4) | LRP_RSVD1;
  rm->addr_len = LRP_RSVD2;
  rm->addr_len = (rm->addr_len << 4) | LRP_ADDR_LEN_IPV6;
  udpconn->ttl = 1;

  uip_create_linklocal_lln_routers_mcast(&udpconn->ripaddr);
  uip_udp_packet_send(udpconn, buf, sizeof(struct lrp_msg_qry));
  memset(&udpconn->ripaddr, 0, sizeof(udpconn->ripaddr));
}
#endif /* SND_QRY && !LRP_IS_SINK */

/*---------------------------------------------------------------------------*/
/* Retransmit a QRY if there is no default route. Restart the QRY timer with
 * exponentially increasing time interval between them. Asymptotically, QRY
 * will be sent at the same rate as the DIO frequency. Time wait between two
 * QRY sending follow this sequence :
 * `Un = SEND_DIO_INTERVAL * (1 - QRY_EXP_PARAM ^ n)` */
#if SND_QRY && ! LRP_IS_SINK
static void
retransmit_qry()
{
  if(uip_ds6_defrt_lookup(&def_rt_addr) != NULL) {
    PRINTF("Deactivating QRY timer: have a default route\n");
    qry_exp_residuum = -1;
    return;
  }

  send_qry();

  // Configure timer for next time
  if (qry_exp_residuum == -1) {
    // Initialisation
    qry_exp_residuum = SEND_DIO_INTERVAL;
  }
  qry_exp_residuum *= QRY_EXP_PARAM;
  etimer_set(&qry_timer, SEND_DIO_INTERVAL - qry_exp_residuum);
  PRINTF("QRY timer reset (%lums)\n",
      SEND_DIO_INTERVAL - qry_exp_residuum);
}
#endif /* SND_QRY && ! LRP_IS_SINK */

/*---------------------------------------------------------------------------*/
/* Format and broadcast a DIO packet. */
#if LRP_IS_COORDINATOR()
static void
send_dio()
{
  char buf[MAX_PAYLOAD_LEN];
  struct lrp_msg_dio *rm = (struct lrp_msg_dio *)buf;

  PRINTF("Send DIO\n");

  rm->type = LRP_DIO_TYPE;
  rm->type = (rm->type << 4) | LRP_RSVD1;
  rm->addr_len = LRP_RSVD2;
  rm->addr_len = (rm->addr_len << 4) | LRP_ADDR_LEN_IPV6;
  rm->seqno = my_seq_id;
  rm->rank = my_rank;
  rm->metric = LRP_METRIC_HC;
  rm->metric = (rm->metric << 4) | (my_weaklink + parent_weaklink(my_parent_rssi));
  uip_ipaddr_copy(&rm->sink_addr, &my_sink_addr);
  udpconn->ttl = 1;

  uip_create_linklocal_lln_routers_mcast(&udpconn->ripaddr);
// #if RDC_LAYER_ID == ID_mac_802154_rdc_driver
//   tcpip_set_outputfunc(output_802154);
//   uip_udp_packet_send(udpconn, buf, sizeof(struct lrp_msg_dio));
//   tcpip_set_outputfunc(output);
// #else // RDC_LAYER_ID == ID_mac_802154_rdc_driver
  uip_udp_packet_send(udpconn, buf, sizeof(struct lrp_msg_dio));
// #endif /* RDC_LAYER_ID == ID_mac_802154_rdc_driver */
  memset(&udpconn->ripaddr, 0, sizeof(udpconn->ripaddr));

#if LRP_IS_SINK
  // Count sent DIO messages
  if(dio_seq_skip_counter >= DEFAULT_DIO_SEQ_SKIP) {
    // Increase sequence id => rebuild tree from scratch
    dio_seq_skip_counter = 0;
    SEQNO_INCREASE(my_seq_id);
  } else {
    dio_seq_skip_counter++;
  }
#endif /* LRP_IS_SINK */
}
#endif /* LRP_IS_COORDINATOR */

/*---------------------------------------------------------------------------*/
/* Format and broadcast a RREQ packet. */
static void
send_rreq()
{
  char buf[MAX_PAYLOAD_LEN];
  struct lrp_msg_rreq *rm = (struct lrp_msg_rreq *)buf;

  PRINTF("Send RREQ for ");
  PRINT6ADDR(&rreq_addr);
  PRINTF("\n");

  rm->type = LRP_RREQ_TYPE;
  rm->type = (rm->type << 4) | LRP_RSVD1;
  rm->addr_len = LRP_RSVD2;
  rm->addr_len = (rm->addr_len << 4) | LRP_ADDR_LEN_IPV6;
  SEQNO_INCREASE(my_hseqno);
  rm->seqno = my_hseqno;
  rm->metric = LRP_METRIC_HC;
  rm->metric = (rm->metric << 4) | LRP_WEAK_LINK;
  rm->route_cost = 0;
  uip_ipaddr_copy(&rm->dest_addr, &rreq_addr);
  uip_ipaddr_copy(&rm->orig_addr, &myipaddr);
  udpconn->ttl = LRP_MAX_DIST;

  uip_create_linklocal_lln_routers_mcast(&udpconn->ripaddr);
  uip_udp_packet_send(udpconn, buf, sizeof(struct lrp_msg_rreq));
  memset(&udpconn->ripaddr, 0, sizeof(udpconn->ripaddr));
}

/*---------------------------------------------------------------------------*/
/* Format and send a RREP packet to `nexthop`. */
static void
send_rrep(const uip_ipaddr_t *dest, const uip_ipaddr_t *nexthop,
    const uip_ipaddr_t *orig, const uint16_t *seqno, const unsigned hop_count)
{
  char buf[MAX_PAYLOAD_LEN];
  struct lrp_msg_rrep *rm = (struct lrp_msg_rrep *)buf;

  PRINTF("Send RREP -> ");
  PRINT6ADDR(nexthop);
  PRINTF(" orig=");
  PRINT6ADDR(orig);
  PRINTF(" dest=");
  PRINT6ADDR(dest);
  PRINTF(" hopcnt=%u\n", hop_count);

  rm->type = LRP_RREP_TYPE;
  rm->type = (rm->type << 4) | LRP_RSVD1;
  rm->addr_len = LRP_RSVD2;
  rm->addr_len = (rm->addr_len << 4) | LRP_ADDR_LEN_IPV6;
  rm->seqno = *seqno;
  rm->metric = LRP_METRIC_HC;
  rm->metric = (rm->metric << 4) | LRP_WEAK_LINK;
  rm->route_cost = hop_count;
  uip_ipaddr_copy(&rm->orig_addr, orig);
  uip_ipaddr_copy(&rm->dest_addr, dest);
  udpconn->ttl = 1;

  uip_ipaddr_copy(&udpconn->ripaddr, nexthop);
  uip_udp_packet_send(udpconn, buf, sizeof(struct lrp_msg_rrep));
  memset(&udpconn->ripaddr, 0, sizeof(udpconn->ripaddr));
}

/*---------------------------------------------------------------------------*/
/* Format and send a RERR to `nexthop`. */
static void
send_rerr(const uip_ipaddr_t *src, const uip_ipaddr_t *dest,
    const uip_ipaddr_t *nexthop)
{
  char buf[MAX_PAYLOAD_LEN];
  struct lrp_msg_rerr *rm = (struct lrp_msg_rerr *)buf;

  PRINTF("Send RERR -> ");
  PRINT6ADDR(nexthop);
  PRINTF(" address_in_error=");
  PRINT6ADDR(dest);
  PRINTF("\n");

  rm->type = LRP_RERR_TYPE;
  rm->type = (rm->type << 4) | LRP_RSVD1;
  rm->addr_len = LRP_RSVD2;
  rm->addr_len = (rm->addr_len << 4) | LRP_ADDR_LEN_IPV6;
  uip_ipaddr_copy(&rm->addr_in_error, dest);
  uip_ipaddr_copy(&rm->src_addr, src);
  udpconn->ttl = 1;

  uip_ipaddr_copy(&udpconn->ripaddr, nexthop);
  uip_udp_packet_send(udpconn, buf, sizeof(struct lrp_msg_rerr));
  memset(&udpconn->ripaddr, 0, sizeof(udpconn->ripaddr));
}

/*---------------------------------------------------------------------------*/
/* Format and send a RACK to `nexthop`. */
#if LRP_RREP_ACK
static void
send_rack(const uip_ipaddr_t *src, const uip_ipaddr_t *nexthop,
    const uint16_t seqno)
{
  char buf[MAX_PAYLOAD_LEN];
  struct lrp_msg_rack *rm = (struct lrp_msg_rack *)buf;

  PRINTF("Send RACK -> ");
  PRINT6ADDR(nexthop);
  PRINTF(" src=");
  PRINT6ADDR(src);
  PRINTF("\n");

  rm->type = LRP_RACK_TYPE;
  rm->type = (rm->type << 4) | LRP_RSVD1;
  rm->addr_len = LRP_RSVD2;
  rm->addr_len = (rm->addr_len << 4) | LRP_ADDR_LEN_IPV6;
  uip_ipaddr_copy(&rm->src_addr, src);
  rm->seqno = seqno;
  udpconn->ttl = 1;

  uip_ipaddr_copy(&udpconn->ripaddr, nexthop);
  uip_udp_packet_send(udpconn, buf, sizeof(struct lrp_msg_rack));
  memset(&udpconn->ripaddr, 0, sizeof(udpconn->ripaddr));
}
#endif /* LRP_RREP_ACK */

/*---------------------------------------------------------------------------*/
static void
handle_incoming_rreq(void)
{
  struct lrp_msg_rreq *rm = (struct lrp_msg_rreq *)uip_appdata;
  uip_ipaddr_t dest_addr, orig_addr;
#if !USE_DIO
  uip_ds6_route_t* rt;
#endif

  PRINTF("Received RREQ ");
  PRINT6ADDR(&UIP_IP_BUF->srcipaddr);
  PRINTF(" -> ");
  PRINT6ADDR(&UIP_IP_BUF->destipaddr);
  PRINTF(" orig=");
  PRINT6ADDR(&rm->orig_addr);
  PRINTF(" dest=");
  PRINT6ADDR(&rm->dest_addr);
  PRINTF(" seq=%u", rm->seqno);
  PRINTF(" hop=%u\n", rm->route_cost);

  if(lrp_is_my_global_address(&rm->orig_addr)) {
    PRINTF("Skipping: RREQ loops back\n");
    return;
  }

#if !USE_DIO
  // Add reverse route while receiving RREQ
  rt = uip_lrp_route_add(&rm->orig_addr, DEFAULT_PREFIX_LEN,
      &UIP_IP_BUF->srcipaddr, rm->route_cost, rm->seqno);
  if(rt != NULL) {
    PRINTF("Route inserted from RREQ\n");
  } else {
    PRINTF("Skipping: not a better route\n");
    return;
  }
#else
  // Have we seen this RREQ before?
  if(fwc_lookup(&rm->orig_addr, &rm->seqno)) {
    PRINTF("Skipping: RREQ cached\n");
    return;
  }
  fwc_add(&rm->orig_addr, &rm->seqno);
#endif /* !USE_OPT */

  if(lrp_is_my_global_address(&rm->dest_addr)) {
    // RREQ for our address
    uip_ipaddr_copy(&dest_addr, &rm->orig_addr);
    uip_ipaddr_copy(&orig_addr, &rm->dest_addr);
    SEQNO_INCREASE(my_hseqno);
    send_rrep(&dest_addr, &UIP_IP_BUF->srcipaddr, &orig_addr, &my_hseqno, 0);

#if LRP_IS_COORDINATOR()
    // Only coordinator forward RREQ
  } else {
    if(UIP_IP_BUF->ttl == 1) {
      PRINTF("Skipping: TTL expired\n");
      return;
    }
    // TTL still valid for forwarding
    PRINTF("Forward RREQ\n");
    rm->route_cost++;
    udpconn->ttl = UIP_IP_BUF->ttl - 1;
    uip_create_linklocal_lln_routers_mcast(&udpconn->ripaddr);
    lrp_rand_wait();
    uip_udp_packet_send(udpconn, rm, sizeof(struct lrp_msg_rreq));
    memset(&udpconn->ripaddr, 0, sizeof(udpconn->ripaddr));
#endif /* LRP_IS_COORDINATOR() */
  }
}

/*---------------------------------------------------------------------------*/
static void
handle_incoming_rrep(void)
{
  struct lrp_msg_rrep *rm = (struct lrp_msg_rrep *)uip_appdata;
  struct uip_ds6_route *rt;
  uip_ipaddr_t *nexthop;

  PRINTF("Received RREP ");
  PRINT6ADDR(&UIP_IP_BUF->srcipaddr);
  PRINTF(" -> ");
  PRINT6ADDR(&UIP_IP_BUF->destipaddr);
  PRINTF(" orig=");
  PRINT6ADDR(&rm->orig_addr);
  PRINTF(" dest=");
  PRINT6ADDR(&rm->dest_addr);
  PRINTF(" hopcnt=%u\n", rm->route_cost);

  // No multicast RREP: drop
  if(uip_ipaddr_cmp(&UIP_IP_BUF->destipaddr, &mcastipaddr)) {
    PRINTF("Skipping: multicasted RREP");
    return;
  }

  // No RREP from our default route
  if (uip_ds6_defrt_lookup(&UIP_IP_BUF->srcipaddr)) {
    PRINTF("Do not allow RREP from default route\n");
    return;
  }

  rt = uip_lrp_route_add(&rm->orig_addr, DEFAULT_PREFIX_LEN,
      &UIP_IP_BUF->srcipaddr, rm->route_cost, rm->seqno);
  if(rt != NULL) {
    PRINTF("Route inserted from RREP\n");
#if LRP_RREP_ACK
    rt->state.ack_received = 0; /* Pending route for ACK */
#else
    rt->state.ack_received = 1;
#endif
  } else {
    PRINTF("Former route is better\n");
  }

  if(uip_ipaddr_cmp(&rm->dest_addr, &myipaddr)) {
    // RREP is for our address
#if LRP_RREQ_RETRIES
    // Remove route request cache
    rrc_remove(&rm->orig_addr);
#if LRP_RREP_ACK
    send_rack(&rm->orig_addr, &UIP_IP_BUF->srcipaddr, rm->seqno);
#endif
    return;
#endif
  } else {
#if USE_DIO
    nexthop = uip_ds6_defrt_choose();
    if(nexthop == NULL) {
      PRINTF("Unable to forward RREP: no default route\n");
      return; // No ACK and RREP forwarding
    }
#else
    nexthop = uip_ds6_route_lookup(&rm->dest_addr);
    if (nexthop == NULL) {
      PRINTF("Unable to forward RREP: unknown destination\n");
      return; // No ACK and RREP forwarding
    }
#endif /* USE_DIO */

#if LRP_RREP_ACK
    send_rack(&rm->orig_addr, &UIP_IP_BUF->srcipaddr, rm->seqno);
#endif
    send_rrep(&rm->dest_addr, nexthop, &rm->orig_addr, &rm->seqno,
        rm->route_cost + 1);
  }
}

/*---------------------------------------------------------------------------*/
static void
handle_incoming_rack(void)
{
  struct lrp_msg_rack *rm = (struct lrp_msg_rack *)uip_appdata;
  struct uip_ds6_route *rt;

  PRINTF("Received RACK ");
  PRINT6ADDR(&UIP_IP_BUF->srcipaddr);
  PRINTF(" -> ");
  PRINT6ADDR(&UIP_IP_BUF->destipaddr);
  PRINTF(" seq=%u ", rm->seqno);
  PRINTF(" src=");
  PRINT6ADDR(&rm->src_addr);
  PRINTF("\n");

  rt = uip_ds6_route_lookup(&rm->src_addr);

  /* No route? */
  if(rt == NULL) {
    PRINTF("Receved RACK for non-existing route\n");
  } else {
    rt->state.ack_received = 1; /* Make pending route valid */
  }
}

/*---------------------------------------------------------------------------*/
static void
handle_incoming_rerr(void)
{
  struct lrp_msg_rerr *rm = (struct lrp_msg_rerr *)uip_appdata;
#if !USE_DIO
  struct uip_ds6_route *rt;
#endif /* !USE_DIO */

  PRINTF("Recieved RERR ");
  PRINT6ADDR(&UIP_IP_BUF->srcipaddr);
  PRINTF(" -> ");
  PRINT6ADDR(&UIP_IP_BUF->destipaddr);
  PRINTF(" addr_in_error=");
  PRINT6ADDR(&rm->addr_in_error);
  PRINTF("\n");

  /* Remove route */
  uip_ds6_route_rm(uip_ds6_route_lookup(&rm->addr_in_error));

#if !USE_DIO
  rt = uip_ds6_route_lookup(&rm->src_addr);
  if (rt == NULL) {
    PRINTF("Skipping RERR: unknown source\n");
    return;
  } else {
    PRINTF("Forward RERR to nexthop\n");
    send_rerr(&rm->src_addr, &rm->addr_in_error, uip_ds6_route_nexthop(rt));
  }
#else
#if !LRP_IS_SINK
  if (lrp_is_predecessor(&UIP_IP_BUF->srcipaddr)) {
    PRINTF("Cleaning broken host route\n");
    send_rerr(&rm->src_addr, &rm->addr_in_error, uip_ds6_defrt_choose());
  } else {
    PRINTF("Successor doesn't know us. Spontaneously send RREP\n");
    SEQNO_INCREASE(my_hseqno);
    send_rrep(&my_sink_addr, uip_ds6_defrt_choose(), &myipaddr, &my_hseqno, 0);
  }
#endif /* !LRP_IS_SINK */
#endif /* !USE_DIO */
}

/*---------------------------------------------------------------------------*/
static void
handle_incoming_dio(void)
{
#if LRP_IS_SINK
  PRINTF("Skipping DIO: is a sink\n");
#else

  uint8_t parent_changed = 0;
  uint8_t dio_weaklink = 0;
  // FIXME: code specific to beacon-enabled
//   if (NETSTACK_RDC_CONFIGURATOR.use_routing_information()) {
  struct lrp_msg_dio *rm = (struct lrp_msg_dio *)uip_appdata;

  PRINTF("Received DIO ");
  PRINT6ADDR(&UIP_IP_BUF->srcipaddr);
  PRINTF(" -> ");
  PRINT6ADDR(&UIP_IP_BUF->destipaddr);
  PRINTF(" rank=%d", rm->rank);
  PRINTF(" seq=%d", rm->seqno);
  PRINTF(" rssi=%i\n", (int8_t)LAST_RSSI);

  if(SEQNO_GREATER_THAN(rm->seqno, my_seq_id)) {
    PRINTF("Accepting offer: New sequence number\n");
    my_seq_id = rm->seqno;
    parent_changed = 1;
  } else if(rm->seqno == my_seq_id) {
    // Seqno ties
    dio_weaklink = get_weaklink(rm->metric) +
      parent_weaklink((int8_t)LAST_RSSI);
    if(dio_weaklink < my_weaklink + parent_weaklink(my_parent_rssi)) {
      PRINTF("Accepting offer: Less weak links\n");
      parent_changed = 1;
    } else if(dio_weaklink == my_weaklink + parent_weaklink(my_parent_rssi)){
      // Weak link ties
      if(rm->rank < (my_rank - 1)) {
        PRINTF("Accepting offer: Better rank\n");
        parent_changed = 1;
      }
    }
  }

  if(parent_changed == 1) {
    uip_ipaddr_copy(&my_sink_addr, &rm->sink_addr);
    my_parent_rssi = (int8_t)LAST_RSSI;
    change_default_route(rm);
  } else {
    PRINTF("Skipping: bad offer\n");
  }
#endif /* LRP_IS_SINK */
}

/*---------------------------------------------------------------------------*/
static void
handle_incoming_qry(void)
{
#if !LRP_IS_COORDINATOR()
  PRINTF("Skipping QRY: is a leaf\n");
  return;
#else
  PRINTF("Received QRY\n");

#if !LRP_IS_SINK
  if(uip_ds6_defrt_lookup(&def_rt_addr) == NULL) {
    PRINTF("Skipping: no default route\n");
    return;
  }
#endif
  PRINTF("Send DIO\n");
  lrp_rand_wait();
  send_dio();
#endif /* !LRP_IS_COORDINATOR() */
}

/*---------------------------------------------------------------------------*/
static void
print_local_addresses(void)
{
  int i;
  uint8_t state;

  PRINTF("LRP IPv6 addresses: \n");
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

    struct lrp_msg *m = (struct lrp_msg *)uip_appdata;
    type = m->type >> 4;
    switch(type) {
      case LRP_RREQ_TYPE:
        handle_incoming_rreq();
        break;
      case LRP_RREP_TYPE:
        handle_incoming_rrep();
        break;
      case LRP_RERR_TYPE:
        handle_incoming_rerr();
        break;
      case LRP_RACK_TYPE:
        handle_incoming_rack();
        break;
      case LRP_DIO_TYPE:
        handle_incoming_dio();
        break;
      case LRP_QRY_TYPE:
        handle_incoming_qry();
        break;
    }
  }
}

/*---------------------------------------------------------------------------*/
#if LRP_IS_SINK
static uint8_t
lrp_addr_matches_local_prefix(uip_ipaddr_t *host)
{
  return uip_ipaddr_prefixcmp(&local_prefix, host, local_prefix_len);
}
#endif /* LRP_IS_SINK */

/*---------------------------------------------------------------------------*/
#if LRP_IS_SINK
static void
lrp_request_route_to(uip_ipaddr_t *host)
{
  if(in_lrp_call) {
    return;
  }

  PRINTF("Request a route towards ");
  PRINT6ADDR(host);
  PRINTF("\n");

  if(!lrp_addr_matches_local_prefix(host)) {
    // Address cannot be on the managed network: address does not match.
    PRINTF("Skipping: No RREQ for a non-local address\n");
    return;
  }

#if LRP_RREQ_RATELIMIT
  if(!timer_expired(&rreq_ratelimit_timer)) {
     PRINTF("Skipping: RREQ exceeds rate limit\n");
     return;
  }
#endif /* LRP_RREQ_RATELIMIT */

  uip_ipaddr_copy(&rreq_addr, host);
  command = COMMAND_SEND_RREQ;
  process_post(&lrp_process, PROCESS_EVENT_MSG, NULL);
#if LRP_RREQ_RETRIES
  if(!rrc_lookup(&rreq_addr)) {
    rrc_add(&rreq_addr);
  }
#endif /* LRP_RREQ_RETRIES */

#if LRP_RREQ_RATELIMIT
  timer_set(&rreq_ratelimit_timer, LRP_RREQ_RATELIMIT);
#endif /* LRP_RREQ_RATELIMIT */
}
#endif /* LRP_IS_SINK */

/*---------------------------------------------------------------------------*/
#if LRP_IS_COORDINATOR() && !LRP_IS_SINK
static void
lrp_routing_error(uip_ipaddr_t* source, uip_ipaddr_t* destination,
    uip_lladdr_t* previoushop)
{
  uip_ipaddr_copy(&rerr_src_addr, source);
  uip_ipaddr_copy(&rerr_bad_addr, destination);
  uip_ipaddr_copy(&rerr_next_addr,
      uip_ds6_nbr_ipaddr_from_lladdr(previoushop));

  command = COMMAND_SEND_RERR;
  process_post(&lrp_process, PROCESS_EVENT_MSG, NULL);
}
#endif /* LRP_IS_COORDINATOR() && !LRP_IS_SINK */

/*---------------------------------------------------------------------------*/
void
lrp_set_local_prefix(uip_ipaddr_t *prefix, uint8_t len)
{
  uip_ipaddr_copy(&local_prefix, prefix);
  local_prefix_len = len;
}

/*---------------------------------------------------------------------------*/
static void
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
uip_ipaddr_t*
lrp_select_nexthop_for(uip_ipaddr_t* source, uip_ipaddr_t* destination,
    uip_lladdr_t* previoushop)
{
  uip_ds6_route_t *route_to_dest;
  uip_ipaddr_t *nexthop;

#if !LRP_IS_COORDINATOR()
  // Node is a leaf, always choose default route
  nexthop = uip_ds6_defrt_choose();
  route_to_dest = NULL;
#else

  route_to_dest = uip_ds6_route_lookup(destination);
#if !LRP_IS_SINK
  if(!lrp_is_predecessor(uip_ds6_nbr_ipaddr_from_lladdr(previoushop)) &&
      !lrp_is_my_global_address(source)) {
    // The previous hop is higher
    if(route_to_dest == NULL) {
      // No host route
      PRINTF("Discarding packet: previous and next hop are higher\n");
      lrp_routing_error(source, destination, previoushop);
      return NULL;
    } else {
      // Valid host route
      nexthop = uip_ds6_route_nexthop(route_to_dest);
    }
  } else {
#endif /* !LRP_IS_SINK */
    // The previous hop is lower
    if(route_to_dest == NULL) {
      // No host route
#if LRP_IS_SINK
      // Send RREQ
      lrp_request_route_to(destination);
      return NULL;
#else
      // Use default route instead
      nexthop = uip_ds6_defrt_choose();
      if(nexthop == NULL) {
        PRINTF("Discarding packet: no default route\n");
        return NULL;
      }
#endif /* LRP_IS_SINK */
    } else {
      // Use provided host route
      nexthop = uip_ds6_route_nexthop(route_to_dest);
    }
#if !LRP_IS_SINK
  }
#endif /* !LRP_IS_SINK */
#endif /* !LRP_IS_COORDINATOR() */

  if(nexthop == NULL) {
    // The nexthop is not in neighbour table
    PRINTF("Discarding packet: nexthop in routing table is not in "
        "neighbour table\n");
  } else {
    PRINTF("Routing through ");
    PRINT6ADDR(nexthop);
    if(route_to_dest == NULL) {
      PRINTF(" (default route)\n");
    } else {
      PRINTF(" (host route)\n");
    }
  }
  return nexthop;
}

/*---------------------------------------------------------------------------*/
PROCESS_THREAD(lrp_process, ev, data)
{
  PROCESS_BEGIN();
  PRINTF("LRP process started\n");
#if LRP_IS_SINK
  my_seq_id = 1;
  my_rank = 0;
  my_weaklink = 0;
  my_parent_rssi = 126;
  dio_seq_skip_counter = 0;
#else
  my_seq_id = 0;
  my_rank = LRP_MAX_RANK;
  my_weaklink = 255;
  my_parent_rssi = -126;
#endif
  PRINTF("LRP is sink: %s\n", LRP_IS_SINK ? "yes" : "no");

  my_hseqno = 1;
  print_local_addresses();
  get_global_addr(&myipaddr);
  get_prefix_from_addr(&myipaddr, &local_prefix, DEFAULT_LOCAL_PREFIX);
#if LRP_IS_SINK
  uip_ipaddr_copy(&my_sink_addr, &myipaddr);
#endif
  uip_create_linklocal_lln_routers_mcast(&mcastipaddr);
  uip_create_linklocal_empty_addr(&def_rt_addr);
  uip_ds6_maddr_add(&mcastipaddr);

  udpconn = udp_new(NULL, UIP_HTONS(LRP_UDPPORT), NULL);
  udp_bind(udpconn, UIP_HTONS(LRP_UDPPORT));
  PRINTF("Created an UDP socket");
  PRINTF(" (local/remote port %u/%u)\n",
        UIP_HTONS(udpconn->lport), UIP_HTONS(udpconn->rport));

#if LRP_RREQ_RETRIES
  PRINTF("Set timer for RREQ retry %lums\n", RETRY_RREQ_INTERVAL * 1000 / CLOCK_SECOND);
  etimer_set(&dfet, RETRY_RREQ_INTERVAL);
#endif

#if LRP_RREQ_RATELIMIT
  timer_set(&rreq_ratelimit_timer, LRP_RREQ_RATELIMIT);
#endif

#if LRP_R_HOLD_TIME
  PRINTF("Set timer for route validity time check %u\n", RV_CHECK_INTERVAL);
  etimer_set(&rv, RV_CHECK_INTERVAL);
#endif

#if SND_QRY && ! LRP_IS_SINK
  // Start sending QRY to find nodes just around
  qry_exp_residuum = -1;
  retransmit_qry();
#endif

  while(1) {
    PROCESS_YIELD();

    if(ev == tcpip_event) {
      tcpip_handler();
    }

#if LRP_IS_COORDINATOR()
    // DIO timer
    if(etimer_expired(&send_dio_et)) {
#if LRP_IS_SINK
      send_dio();
      etimer_set(&send_dio_et, SEND_DIO_INTERVAL);
#else /* LRP_IS_SINK */
      if(uip_ds6_defrt_lookup(&def_rt_addr) != NULL) {
        send_dio();
        etimer_set(&send_dio_et, SEND_DIO_INTERVAL);
      }
#endif /* LRP_IS_SINK */
    }
#endif /* LRP_IS_COORDINATOR() */

#if SND_QRY && !LRP_IS_SINK
    // QRY timer
    if(qry_exp_residuum != -1 && etimer_expired(&qry_timer)) {
      retransmit_qry();
    }
#endif /* SND_QRY && !LRP_IS_SINK */

#if LRP_RREQ_RETRIES
    if(etimer_expired(&dfet)) {
      rrc_check_expired_rreq(RETRY_RREQ_INTERVAL);
      etimer_restart(&dfet);
    }
#endif

#if LRP_R_HOLD_TIME
    if(etimer_expired(&rv)) {
      lrp_check_expired_route(RV_CHECK_INTERVAL);
      etimer_restart(&rv);
    }
#endif /* LRP_R_HOLD_TIME */

    if(ev == PROCESS_EVENT_MSG) {
      if(command == COMMAND_SEND_RREQ) {
        ctimer_set(&sendmsg_ctimer, random_rand() % 50 * CLOCK_SECOND / 1000,
            (void (*)(void *))send_rreq, NULL);
      } else if (command == COMMAND_SEND_RERR) {
        send_rerr(&rerr_src_addr, &rerr_bad_addr, &rerr_next_addr);
      }
      command = COMMAND_NONE;
    }
  }
  PROCESS_END();
}

#endif /* WITH_IPV6_LRP */
/*---------------------------------------------------------------------------*/
