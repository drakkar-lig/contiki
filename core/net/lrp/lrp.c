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

/* Exponential parameter for QRY sending. @see retransmit_qry */
#define QRY_EXP_PARAM           0.80

#define LRP_MAX_RANK            127

/* Frequency of DIO broadcasting (in ticks) */
#define SEND_DIO_INTERVAL       500 * CLOCK_SECOND

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
#if LRP_RREQ_MININTERVAL
static struct timer rreq_ratelimit_timer;
#endif
#if LRP_IS_COORDINATOR() && !LRP_IS_SINK && LRP_BRK_MININTERVAL
static struct timer brk_ratelimit_timer;
#endif

#if SND_QRY && !LRP_IS_SINK
static struct etimer qry_timer;
#endif /* SND_QRY && !LRP_IS_SINK */

#if LRP_IS_COORDINATOR()
static struct etimer send_dio_et;
#endif /* LRP_IS_COORDINATOR() */

#define LAST_RSSI cc2420_last_rssi
// extern int8_t last_rssi; // for stm32w
extern signed char cc2420_last_rssi;
static uint16_t my_hseqno, my_sink_seqno, local_prefix_len;
static int8_t my_rank, my_weaklink, my_parent_rssi;
#if LRP_IS_SINK
static uint8_t dio_seq_skip_counter;
#endif /* LRP_IS_SINK */
static uip_ipaddr_t local_prefix, my_sink_addr,
                    myipaddr, mcastipaddr;
static struct uip_udp_conn *udpconn;
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
/* Implementation of request forwarding cache to avoid multiple forwarding */
#if !LRP_IS_SINK
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
#endif /* !LRP_IS_SINK */

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
/* Implementation of broken routes cache to avoid multiple broadcasting and to
 * be able to retransmit UPD in reverted */
#if LRP_IS_COORDINATOR() && !LRP_IS_SINK
#define BRCACHE 2

static struct {
  uip_ipaddr_t lost_node;
  uip_ipaddr_t forwarder;
  uint16_t seqno;
} brcache[BRCACHE];

/* Return the forwarder previously inserted, or null if there is no matching
 * entry */
static uip_ipaddr_t*
brc_lookup(const uip_ipaddr_t *lost_node)
{
  unsigned n = (((uint8_t *)lost_node)[0] +
      ((uint8_t *)lost_node)[15]) % BRCACHE;
  if(uip_ipaddr_cmp(&brcache[n].lost_node, lost_node)) {
    return &brcache[n].forwarder;
  }
  return NULL;
}

/* Return true if the offer was better than previous one (for the same
 * lost_node), and has thus been inserted */
static uint8_t
brc_add(const uip_ipaddr_t *lost_node, const uint16_t seqno,
    const uip_ipaddr_t *forwarder)
{
  unsigned n = (((uint8_t *)lost_node)[0] +
      ((uint8_t *)lost_node)[15]) % BRCACHE;
  if(SEQNO_GREATER_THAN(seqno, brcache[n].seqno) ||
      !uip_ipaddr_cmp(&brcache[n].lost_node, lost_node)) {
    brcache[n].seqno = seqno;
    uip_ipaddr_copy(&brcache[n].forwarder, forwarder);
    uip_ipaddr_copy(&brcache[n].lost_node, lost_node);
    return (1==1);
  } else {
    return (0==1);
  }
}
#endif /* LRP_IS_COORDINATOR() && !LRP_IS_SINK */


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
lrp_nbr_add(uip_ipaddr_t* next_hop)
{
#if !UIP_ND6_SEND_NA
  uip_lladdr_t nbr_lladdr;
#endif
  uip_ds6_nbr_t *nbr = uip_ds6_nbr_lookup(next_hop);

  if(nbr == NULL) {
    PRINTF("Adding ");
    PRINT6ADDR(next_hop);
    PRINTF(" to neighbor table");
#if !UIP_ND6_SEND_NA
    // it's my responsability to create+maintain neighbor
    PRINTF(" (without NA),");
    memcpy(&nbr_lladdr, &next_hop->u8[8],
           UIP_LLADDR_LEN);
    nbr_lladdr.addr[0] ^= 2;
    PRINTF(" with lladdress ");
    PRINTLLADDR(&nbr_lladdr);
    uip_ds6_nbr_add(next_hop, &nbr_lladdr, 0, NBR_REACHABLE);
//    nbr->nscount = 1;
#else /* if not !UIP_ND6_SEND_NA */
    PRINTF(" (waiting for a NA)\n");
    uip_ds6_nbr_add(next_hop, NULL, 0, NBR_INCOMPLETE);
#endif /* !UIP_ND6_SEND_NA */
  } else {
    PRINTF("Neighbor ");
    PRINT6ADDR(next_hop);
    PRINTF(" is already known (as");
    PRINTLLADDR(uip_ds6_nbr_get_ll(nbr));
    PRINTF(")\n");
  }
}

/*---------------------------------------------------------------------------*/
/* Return true if `addr` is empty */
#if LRP_IS_COORDINATOR() && !LRP_IS_SINK
static uint8_t
lrp_uip_ipaddr_is_empty(uip_ipaddr_t* addr) {
  uip_ipaddr_t empty;
  uip_create_linklocal_empty_addr(&empty);
  return uip_ipaddr_cmp(&empty, addr);
}
#endif /* LRP_IS_COORDINATOR() && !LRP_IS_SINK */

/*---------------------------------------------------------------------------*/
#if LRP_IS_COORDINATOR()
static void
lrp_rand_wait()
{
#if LRP_RANDOM_WAIT == 1
      PRINTF("Waiting rand time\n");
      clock_wait(random_rand() % 50 * CLOCK_SECOND / 100);
      PRINTF("Done waiting rand time\n");
#endif
}
#endif /* LRP_IS_COORDINATOR() */

/*---------------------------------------------------------------------------*/
/* Change default route for the one specified with informations in parameter.
 * */
#if !LRP_IS_SINK
static uip_ds6_defrt_t*
change_default_route(uip_ipaddr_t* def_route,
    const uip_ipaddr_t* sink_addr, const uint16_t seqno,
    const uint8_t metric, const uint8_t rank)
{
  uip_ds6_defrt_t *defrt;

  uip_ipaddr_copy(&my_sink_addr, sink_addr);
  my_sink_seqno = seqno;
  my_rank = rank + 1;
  my_parent_rssi = (int8_t)LAST_RSSI;
  my_weaklink = get_weaklink(metric);

  /* First check if we are actually changing of next hop! */
  defrt = uip_ds6_defrt_lookup(uip_ds6_defrt_choose());
  if(defrt == NULL || !uip_ip6addr_cmp(&defrt->ipaddr, def_route)) {
    // New default route, remove previous one
    PRINTF("New default route\n");
    uip_ds6_defrt_rm(defrt);
    // Flush routes through new default route
    uip_ds6_route_rm_by_nexthop(def_route);
    lrp_nbr_add(def_route);
    defrt = uip_ds6_defrt_add(def_route, LRP_DEFAULT_ROUTE_LIFETIME);
  } else {
    // We just need to refresh the route
    PRINTF("Refreshing default route\n");
    stimer_set(&defrt->lifetime, LRP_DEFAULT_ROUTE_LIFETIME);
  }

#if LRP_IS_COORDINATOR()
  //etimer_set(&send_dio_et, random_rand() % 50 * CLOCK_SECOND / 100);
  // FIXME: when should we activate DIOs?
#endif

  // FIXME: code specific to beacon-enabled
//   uip_lladdr_t coord_addr;
//   memcpy(&coord_addr, &UIP_IP_BUF->srcipaddr.u8[8], UIP_LLADDR_LEN);
//   coord_addr.addr[0] ^= 2;
//   NETSTACK_RDC_CONFIGURATOR.coordinator_choice((void *) &coord_addr,
//       rm->rank);
  return defrt;
}
#endif /* !LRP_IS_SINK */

/*---------------------------------------------------------------------------*/
/* Add route into routing table, with LRP's specific informations. Return the
 * inserted route or NULL */
#if LRP_IS_COORDINATOR()
static uip_ds6_route_t*
lrp_route_add(uip_ipaddr_t* orig_addr, const uint8_t length,
    uip_ipaddr_t* next_hop, const uint8_t route_cost, const uint16_t seqno)
{
  uip_ds6_route_t* rt;

  rt = uip_ds6_route_lookup(orig_addr);
  if(rt != NULL) uip_ds6_route_rm(rt);

  lrp_nbr_add(next_hop);
  rt = uip_ds6_route_add(orig_addr, length, next_hop);
  if(rt != NULL) {
    rt->state.route_cost = route_cost;
    rt->state.seqno = seqno;
    rt->state.valid_time = LRP_R_HOLD_TIME;
  }
  return rt;
}
#endif /* LRP_IS_COORDINATOR() */

/*---------------------------------------------------------------------------*/
/* Add the described route into the routing table, if it is better than
 * the previous one. Return NULL if the route has not been added. */
#if LRP_IS_COORDINATOR()
static uip_ds6_route_t*
offer_route(uip_ipaddr_t* orig_addr, const uint8_t length,
    uip_ipaddr_t* next_hop, const uint8_t route_cost,
    const uint16_t seqno)
{
  uip_ds6_route_t* rt;

  rt = uip_ds6_route_lookup(orig_addr);
  if(rt == NULL ||
      SEQNO_GREATER_THAN(seqno, rt->state.seqno) ||
      (seqno == rt->state.seqno && route_cost < rt->state.route_cost)) {
    // Offered route is better than previous one
    return lrp_route_add(orig_addr, length, next_hop, route_cost, seqno);
  } else {
    // Offered route is worse, refusing route
    return NULL;
  }
}
#endif /* LRP_IS_COORDINATOR() */

/*---------------------------------------------------------------------------*/
/* Change default route if offered one is better than the previous one. Return
 * NULL if the route has not been added. */
#if !LRP_IS_SINK
static uip_ds6_defrt_t*
offer_default_route(const uip_ipaddr_t* sink_addr,
    uip_ipaddr_t* next_hop, const uint8_t route_cost,
    const uint16_t seqno)
{
  uint8_t parent_changed = (0==1);

  if(uip_ipaddr_cmp(sink_addr, &my_sink_addr) &&
      SEQNO_GREATER_THAN(seqno, my_sink_seqno)) {
    // New seqno, better than before
    PRINTF("New tree sequence number\n");
    parent_changed = (1==1);
  } else if(!uip_ipaddr_cmp(sink_addr, &my_sink_addr) ||
      seqno == my_sink_seqno) {
//    new_weaklink = get_weaklink(rm->metric) +
//      parent_weaklink((int8_t) LAST_RSSI);
//    if(new_weaklink < my_weaklink + parent_weaklink(my_parent_rssi)) {
      // Fewer weak links, better than before
//      PRINTF("Fewer weak links\n");
//      parent_changed = (1==1);
//    } else if(new_weaklink ==
//        my_weaklink + parent_weaklink(my_parent_rssi)) {
      if(route_cost < (my_rank - 1)) {
        // Better rank than before
        PRINTF("Better rank\n");
        parent_changed = (1==1);
      }
//    }
  }

  if(parent_changed) {
    return change_default_route(next_hop, sink_addr, seqno, 0, route_cost);
    // TODO: 4th field (metric)
  } else {
    PRINTF("Offered route is worse than before. Keeping current one\n");
    return NULL;
  }
}
#endif /* !LRP_IS_SINK */

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

  if(addr == NULL) {
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
#if SND_QRY && !LRP_IS_SINK
static void
retransmit_qry()
{
  if(uip_ds6_defrt_choose() != NULL) {
    PRINTF("Deactivating QRY timer: have a default route\n");
    qry_exp_residuum = -1;
    return;
  }

  send_qry();

  // Configure timer for next time
  if(qry_exp_residuum == -1) {
    // Initialisation
    qry_exp_residuum = SEND_DIO_INTERVAL;
  }
  qry_exp_residuum *= QRY_EXP_PARAM;
  etimer_set(&qry_timer, SEND_DIO_INTERVAL - qry_exp_residuum);
  PRINTF("QRY timer reset (%lums)\n",
      SEND_DIO_INTERVAL - qry_exp_residuum);
}
#endif /* SND_QRY && !LRP_IS_SINK */

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
  rm->seqno = my_sink_seqno;
  rm->rank = my_rank;
  rm->metric = LRP_METRIC_HC;
  rm->metric = (rm->metric << 4) |
    (my_weaklink + parent_weaklink(my_parent_rssi));
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
    SEQNO_INCREASE(my_sink_seqno);
  } else {
    dio_seq_skip_counter++;
  }
#endif /* LRP_IS_SINK */
}
#endif /* LRP_IS_COORDINATOR() */

/*---------------------------------------------------------------------------*/
/* Format and broadcast a RREQ packet. */
#if LRP_IS_COORDINATOR()
static void
send_rreq(const uip_ipaddr_t *dest, const uip_ipaddr_t *orig,
    const uint16_t *seqno, const uint8_t route_cost, const uint8_t ttl)
{
  char buf[MAX_PAYLOAD_LEN];
  struct lrp_msg_rreq *rm = (struct lrp_msg_rreq *)buf;

  PRINTF("Broadcast RREQ for ");
  PRINT6ADDR(dest);
  PRINTF(" rtecost=%u", route_cost);
  PRINTF(" ttl=%u\n", ttl);

  rm->type = LRP_RREQ_TYPE;
  rm->type = (rm->type << 4) | LRP_RSVD1;
  rm->addr_len = LRP_RSVD2;
  rm->addr_len = (rm->addr_len << 4) | LRP_ADDR_LEN_IPV6;
  rm->seqno = *seqno;
  rm->metric = LRP_METRIC_HC;
  rm->metric = (rm->metric << 4) | LRP_WEAK_LINK;
  rm->route_cost = route_cost;
  uip_ipaddr_copy(&rm->dest_addr, dest);
  uip_ipaddr_copy(&rm->orig_addr, orig);
  udpconn->ttl = ttl;

  uip_create_linklocal_lln_routers_mcast(&udpconn->ripaddr);
  uip_udp_packet_send(udpconn, buf, sizeof(struct lrp_msg_rreq));
  memset(&udpconn->ripaddr, 0, sizeof(udpconn->ripaddr));
}
#endif /* LRP_IS_COORDINATOR() */

/*---------------------------------------------------------------------------*/
/* Format and send a RREP packet to `nexthop`. */
#if !LRP_IS_SINK
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
#endif /* !LRP_IS_SINK */

/*---------------------------------------------------------------------------*/
/* Format and send a RERR to `nexthop`. */
#if !LRP_IS_SINK
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
#endif /* !LRP_IS_SINK */

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
#if LRP_IS_COORDINATOR() && !LRP_IS_SINK
static void
send_brk(const uip_ipaddr_t *broken_link_node, const uip_ipaddr_t *nexthop,
    const uint16_t *seqno, const uint8_t hop_count)
{
  char buf[MAX_PAYLOAD_LEN];
  struct lrp_msg_brk *rm = (struct lrp_msg_brk *) buf;

  PRINTF("Send BRK -> ");
  PRINT6ADDR(nexthop);
  PRINTF(" lost_node=");
  PRINT6ADDR(broken_link_node);
  PRINTF("\n");

  rm->type = LRP_BRK_TYPE;
  rm->type = (rm->type << 4) | LRP_RSVD1;
  rm->addr_len = LRP_RSVD2;
  rm->addr_len = (rm->addr_len << 4) | LRP_ADDR_LEN_IPV6;
  rm->seqno = *seqno; // FIXME: what about endianess
  rm->rank = hop_count;
  uip_ipaddr_copy(&rm->broken_link_node, broken_link_node);
  udpconn->ttl = LRP_MAX_DIST;

  uip_ipaddr_copy(&udpconn->ripaddr, nexthop);
  uip_udp_packet_send(udpconn, buf, sizeof(struct lrp_msg_brk));
  memset(&udpconn->ripaddr, 0, sizeof(udpconn->ripaddr));
}
#endif /* LRP_IS_COORDINATOR() && !LRP_IS_SINK */

/*---------------------------------------------------------------------------*/
#if LRP_IS_COORDINATOR()
static void
send_upd(const uip_ipaddr_t *broken_link_node, const uip_ipaddr_t *sink_addr,
         const uip_ipaddr_t *nexthop, const uint16_t *seqno,
         const uint8_t hop_count)
{
  char buf[MAX_PAYLOAD_LEN];
  struct lrp_msg_upd *rm = (struct lrp_msg_upd *)buf;

  PRINTF("Send UPD -> ");
  PRINT6ADDR(nexthop);
  PRINTF(" lost_node=");
  PRINT6ADDR(broken_link_node);
  PRINTF("\n");

  rm->type = LRP_UPD_TYPE;
  rm->type = (rm->type << 4) | LRP_RSVD1;
  rm->addr_len = LRP_RSVD2;
  rm->addr_len = (rm->addr_len << 4) | LRP_ADDR_LEN_IPV6;
  rm->seqno = *seqno;
  rm->rank = hop_count;
  rm->metric = LRP_METRIC_HC;
  rm->metric = (rm->metric << 4) |
               (my_weaklink + parent_weaklink(my_parent_rssi));
  uip_ipaddr_copy(&rm->sink_addr, sink_addr);
  uip_ipaddr_copy(&rm->broken_link_node, broken_link_node);
  udpconn->ttl = 1;

  uip_ipaddr_copy(&udpconn->ripaddr, nexthop);
  uip_udp_packet_send(udpconn, buf, sizeof(struct lrp_msg_upd));
  memset(&udpconn->ripaddr, 0, sizeof(udpconn->ripaddr));
}
#endif // LRP_IS_COORDINATOR()


/*---------------------------------------------------------------------------*/
#if !LRP_IS_SINK
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

#if !USE_DIO
  if(lrp_is_my_global_address(&rm->orig_addr)) {
    PRINTF("Skipping: RREQ loops back\n");
    return;
  }

  // Add reverse route while receiving RREQ
  rt = offer_route(&rm->orig_addr, DEFAULT_PREFIX_LEN,
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
    lrp_rand_wait();
    send_rreq(&rm->dest_addr, &rm->orig_addr, &rm->seqno,
        rm->route_cost + 1, UIP_IP_BUF->ttl - 1);
#endif /* LRP_IS_COORDINATOR() */
  }
}
#endif /* !LRP_IS_SINK */

/*---------------------------------------------------------------------------*/
#if LRP_IS_COORDINATOR()
static void
handle_incoming_rrep(void)
{
  struct lrp_msg_rrep *rm = (struct lrp_msg_rrep *)uip_appdata;
  struct uip_ds6_route *rt;
#if !LRP_IS_SINK
  uip_ipaddr_t *nexthop;
#endif

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
  if(uip_ds6_defrt_lookup(&UIP_IP_BUF->srcipaddr)) {
    PRINTF("Do not allow RREP from default route\n");
    return;
  }

  rt = offer_route(&rm->orig_addr, DEFAULT_PREFIX_LEN,
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

#if LRP_IS_SINK || !USE_OPT
  if(uip_ipaddr_cmp(&rm->dest_addr, &myipaddr)) {
    // RREP is for our address
#if LRP_RREQ_RETRIES
    // Remove route request cache
    rrc_remove(&rm->orig_addr);
#endif /* LRP_RREQ_RETRIES */
#if LRP_RREP_ACK
    send_rack(&rm->orig_addr, &UIP_IP_BUF->srcipaddr, rm->seqno);
#endif /* LRP_RREP_ACK */
    return;
  }
#endif /* LRP_IS_SINK || !USE_OPT */

#if !LRP_IS_SINK
#if USE_DIO
  nexthop = uip_ds6_defrt_choose();
  if(nexthop == NULL) {
    PRINTF("Unable to forward RREP: no default route\n");
    return; // No ACK and RREP forwarding
  }
#else
  nexthop = uip_ds6_route_lookup(&rm->dest_addr);
  if(nexthop == NULL) {
    PRINTF("Unable to forward RREP: unknown destination\n");
    return; // No ACK and RREP forwarding
  }
#endif /* USE_DIO */

#if LRP_RREP_ACK
  send_rack(&rm->orig_addr, &UIP_IP_BUF->srcipaddr, rm->seqno);
#endif
  send_rrep(&rm->dest_addr, nexthop, &rm->orig_addr, &rm->seqno,
      rm->route_cost + 1);
#endif /* !LRP_IS_SINK */
}
#endif /* LRP_IS_COORDINATOR() */

/*---------------------------------------------------------------------------*/
#if LRP_RREP_ACK
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
#endif /* LRP_RREP_ACK */

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
  if(rt == NULL) {
    PRINTF("Skipping RERR: unknown source\n");
    return;
  } else {
    PRINTF("Forward RERR to nexthop\n");
    send_rerr(&rm->src_addr, &rm->addr_in_error, uip_ds6_route_nexthop(rt));
  }
#else
#if !LRP_IS_SINK
  if(lrp_is_predecessor(&UIP_IP_BUF->srcipaddr)) {
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
#if !LRP_IS_SINK
static void
handle_incoming_dio(void)
{
  struct lrp_msg_dio *rm = (struct lrp_msg_dio *)uip_appdata;

  PRINTF("Received DIO ");
  PRINT6ADDR(&UIP_IP_BUF->srcipaddr);
  PRINTF(" -> ");
  PRINT6ADDR(&UIP_IP_BUF->destipaddr);
  PRINTF(" rank=%d", rm->rank);
  PRINTF(" seq=%d", rm->seqno);
  PRINTF(" rssi=%i\n", (int8_t)LAST_RSSI);

  offer_default_route(&rm->sink_addr, &UIP_IP_BUF->srcipaddr,
      rm->rank, rm->seqno);
}
#endif /* !LRP_IS_SINK */

/*---------------------------------------------------------------------------*/
#if LRP_IS_COORDINATOR()
static void
handle_incoming_qry(void)
{
  PRINTF("Received QRY\n");

#if !LRP_IS_SINK
  if(uip_ds6_defrt_choose() == NULL) {
    PRINTF("Skipping: no default route\n");
    return;
  }
#endif
  lrp_rand_wait();
  send_dio();
}
#endif /* LRP_IS_COORDINATOR() */

/*---------------------------------------------------------------------------*/
#if LRP_IS_COORDINATOR()
static void
handle_incoming_brk()
{
  struct lrp_msg_brk *rm = (struct lrp_msg_brk *)uip_appdata;
#if !LRP_IS_SINK
  uip_ds6_defrt_t* defrt;
  uip_ipaddr_t nexthop;
#endif

  if(lrp_is_my_global_address(&rm->broken_link_node)) {
    PRINTF("Skipping BRK: loops back\n");
    return;
  }

  PRINTF("Received BRK ");
  PRINT6ADDR(&UIP_IP_BUF->srcipaddr);
  PRINTF(" -> ");
  PRINT6ADDR(&UIP_IP_BUF->destipaddr);
  PRINTF(" seqno=%d", rm->seqno);
  PRINTF(" route_cost=%d", rm->rank);
  PRINTF(" lost_node=");
  PRINT6ADDR(&rm->broken_link_node);
  PRINTF("\n");

#if LRP_IS_SINK
  // Send UPD on the reversed route
  SEQNO_INCREASE(my_sink_seqno);
  send_upd(&rm->broken_link_node, &my_sink_addr, &UIP_IP_BUF->srcipaddr,
           &my_sink_seqno, 0);
#else /* LRP_IS_SINK */

  // Keep track of BRK to be able to route subsequent UPD
  if(!brc_add(&rm->broken_link_node, rm->seqno, &UIP_IP_BUF->srcipaddr)) {
    PRINTF("Skipping: BRK is worst than previous one\n");
    return;
  }

  defrt = uip_ds6_defrt_lookup(&UIP_IP_BUF->srcipaddr);
  if(defrt != NULL) {
    // BRK comes from our default next hop. Broadcasting
    uip_create_linklocal_lln_routers_mcast(&nexthop);
    lrp_rand_wait();
    send_brk(&rm->broken_link_node, &nexthop, &rm->seqno, rm->rank + 1);
  } else {
    // BRK comes from a neighbor broken branch. Forwarding BRK to sink
    send_brk(&rm->broken_link_node, uip_ds6_defrt_choose(),
        &rm->seqno, rm->rank + 1);
  }
#endif /* LRP_IS_SINK */
}
#endif /* LRP_IS_COORDINATOR() */

/*---------------------------------------------------------------------------*/
#if LRP_IS_COORDINATOR() && !LRP_IS_SINK
static void
handle_incoming_upd()
{
  struct lrp_msg_upd *rm = (struct lrp_msg_upd *)uip_appdata;
  uip_ds6_defrt_t *rt;
  uip_ipaddr_t *nexthop;

  PRINTF("UPD message: ");
  PRINT6ADDR(&UIP_IP_BUF->srcipaddr);
  PRINTF(" -> ");
  PRINT6ADDR(&UIP_IP_BUF->destipaddr);
  PRINTF(" seqno=%d", rm->seqno);
  PRINTF(" route_cost=%d", rm->rank);
  PRINTF(" broken_link_node=");
  PRINT6ADDR(&rm->broken_link_node);
  PRINTF("\n");

  rt = offer_default_route(&rm->sink_addr, &UIP_IP_BUF->srcipaddr,
      rm->rank, rm->seqno);
  if(rt == NULL) {
    PRINTF("Skipping: not a better route\n");
    return;
  }

  if(lrp_is_my_global_address(&rm->broken_link_node)) {
    // We are BRK originator. UPD has reach its final destination
    PRINTF("Route successfully repaired\n");
    return;
  }

  // Forward to broken_node
  nexthop = brc_lookup(&rm->broken_link_node);
  if(nexthop == NULL) {
    PRINTF("Skipping: No route to transmit UPD\n");
    return;
  }
  send_upd(&rm->broken_link_node, &rm->sink_addr, nexthop,
      &rm->seqno, rm->rank+1);
}
#endif /* LRP_IS_COORDINATOR() && !LRP_IS_SINK */

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
#if LRP_IS_SINK
        PRINTF("Skipping RREQ: is a sink\n");
#else
        handle_incoming_rreq();
#endif
        break;
      case LRP_RREP_TYPE:
#if !LRP_IS_COORDINATOR()
        PRINTF("Skipping RREP: is a leaf\n");
#else
        handle_incoming_rrep();
#endif
        break;
      case LRP_RERR_TYPE:
        handle_incoming_rerr();
        break;
      case LRP_RACK_TYPE:
#if !LRP_RREP_ACK
        PRINTF("Skipping RACK: not configured with acks\n");
#else
        handle_incoming_rack();
#endif
        break;
      case LRP_DIO_TYPE:
#if LRP_IS_SINK
        PRINTF("Skipping DIO: is a sink\n");
#else
        handle_incoming_dio();
#endif
        break;
      case LRP_QRY_TYPE:
#if !LRP_IS_COORDINATOR()
        PRINTF("Skipping QRY: is a leaf\n");
#else
        handle_incoming_qry();
#endif
        break;
      case LRP_BRK_TYPE:
#if !LRP_IS_COORDINATOR()
        PRINTF("Skipping BRK: is a leaf\n");
#else
        handle_incoming_brk();
#endif
        break;
      case LRP_UPD_TYPE:
#if LRP_IS_SINK
        PRINTF("Skipping UPD: is a sink\n");
#else
#if !LRP_IS_COORDINATOR()
        PRINTF("Skipping BRK: is a leaf\n");
#else
        handle_incoming_upd();
#endif
#endif
        break;
      default:
        PRINTF("Unknown message type\n");
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
#if LRP_IS_SINK || !USE_DIO
static void
lrp_request_route_to(uip_ipaddr_t *host)
{
  PRINTF("Request a route towards ");
  PRINT6ADDR(host);
  PRINTF("\n");

  if(!lrp_addr_matches_local_prefix(host)) {
    // Address cannot be on the managed network: address does not match.
    PRINTF("Skipping: No RREQ for a non-local address\n");
    return;
  }

#if LRP_RREQ_MININTERVAL
  if(!timer_expired(&rreq_ratelimit_timer)) {
     PRINTF("Skipping: RREQ exceeds rate limit\n");
     return;
  }
#endif /* LRP_RREQ_MININTERVAL */

  lrp_rand_wait();
  SEQNO_INCREASE(my_hseqno);
  send_rreq(host, &myipaddr, &my_hseqno, 0, LRP_MAX_DIST);
#if LRP_RREQ_RETRIES
  if(!rrc_lookup(&rreq_addr)) {
    rrc_add(&rreq_addr);
  }
#endif /* LRP_RREQ_RETRIES */

#if LRP_RREQ_MININTERVAL
  timer_set(&rreq_ratelimit_timer, LRP_RREQ_MININTERVAL);
#endif /* LRP_RREQ_MININTERVAL */
}
#endif /* LRP_IS_SINK */

/*---------------------------------------------------------------------------*/
#if LRP_IS_COORDINATOR() && !LRP_IS_SINK
static void
lrp_routing_error(uip_ipaddr_t* source, uip_ipaddr_t* destination,
    uip_lladdr_t* previoushop)
{
  send_rerr(source, destination, uip_ds6_nbr_ipaddr_from_lladdr(previoushop));
}
#endif /* LRP_IS_COORDINATOR() && !LRP_IS_SINK */

/*---------------------------------------------------------------------------*/
#if !LRP_IS_SINK
static void
lrp_no_default_route(void)
{
#if LRP_IS_COORDINATOR()
  uip_ipaddr_t nexthop;

  if(lrp_uip_ipaddr_is_empty(&my_sink_addr)) {
    PRINTF("Not associated with a tree\n");
    return;
  }

#if LRP_BRK_MININTERVAL
  if(!timer_expired(&brk_ratelimit_timer)) {
     PRINTF("Skipping BRK: exceed rate limit\n");
     return;
  }
#endif /* LRP_BRK_MININTERVAL */

  uip_create_linklocal_lln_routers_mcast(&nexthop);
  SEQNO_INCREASE(my_hseqno);
  send_brk(&myipaddr, &nexthop, &my_hseqno, 0);

#if LRP_BRK_MININTERVAL
  timer_set(&brk_ratelimit_timer, LRP_BRK_MININTERVAL);
#endif /* LRP_BRK_MININTERVAL */

#else /* if not LRP_IS_COORDINATOR() */

  // Is a leaf: resetting tree-related informations and broadcasting QRY
  PRINTF("No more default route: deassociating with tree\n");
  uip_create_linklocal_empty_addr(&my_sink_addr);
  my_sink_seqno = 0;
  my_rank = LRP_MAX_RANK;
  my_weaklink = 255;
  my_parent_rssi = -126;
#if SND_QRY && !LRP_IS_SINK
  qry_exp_residuum = -1;
  retransmit_qry();
#endif
#endif /* LRP_IS_COORDINATOR() */
}
#endif /* !LRP_IS_SINK */

/*---------------------------------------------------------------------------*/
void
lrp_set_local_prefix(uip_ipaddr_t *prefix, uint8_t len)
{
  uip_ipaddr_copy(&local_prefix, prefix);
  local_prefix_len = len;
}

/*---------------------------------------------------------------------------*/
uip_ipaddr_t*
lrp_select_nexthop_for(uip_ipaddr_t* source, uip_ipaddr_t* destination,
    uip_lladdr_t* previoushop)
{
  uip_ds6_route_t *route_to_dest;
  uip_ipaddr_t *nexthop;

  route_to_dest = uip_ds6_route_lookup(destination);
#if USE_DIO && LRP_IS_COORDINATOR() && !LRP_IS_SINK
  if(!lrp_is_predecessor(uip_ds6_nbr_ipaddr_from_lladdr(previoushop)) &&
      !lrp_is_my_global_address(source)) {
    // The previous hop is higher
    if(route_to_dest == NULL) {
      PRINTF("Discarding packet: previous and next hop are higher\n");
      // Change the context to ensure that timers set in this code wake up the
      // LRP process, and not the routing process
      PROCESS_CONTEXT_BEGIN(&lrp_process);
      lrp_routing_error(source, destination, previoushop);
      PROCESS_CONTEXT_END();
      return NULL;
    }
  }
#endif /* USE_DIO && LRP_IS_COORDINATOR() && !LRP_IS_SINK */

  if(route_to_dest == NULL) {
    // No host route
#if LRP_IS_SINK
    // Send RREQ
    PRINTF("Discarding packet: unknown destination\n");
    // Change the context to ensure that timers set in this code wake up the
    // LRP process, and not the routing process
    PROCESS_CONTEXT_BEGIN(&lrp_process);
    lrp_request_route_to(destination);
    PROCESS_CONTEXT_END();
    return NULL;
#else
    // Use default route instead
    nexthop = uip_ds6_defrt_choose();
    if(nexthop == NULL) {
      PRINTF("Discarding packet: no default route\n");
      // Change the context to ensure that timers set in this code wake up the
      // LRP process, and not the routing process
      PROCESS_CONTEXT_BEGIN(&lrp_process);
      lrp_no_default_route();
      PROCESS_CONTEXT_END();
      return NULL;
    }
#endif /* LRP_IS_SINK */
  } else {
    // Use provided host route
    nexthop = uip_ds6_route_nexthop(route_to_dest);
  }

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
  my_sink_seqno = 1;
  my_rank = 0;
  my_weaklink = 0;
  my_parent_rssi = 126;
  dio_seq_skip_counter = 0;
#else
  my_sink_seqno = 0;
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
  uip_ds6_maddr_add(&mcastipaddr);

  udpconn = udp_new(NULL, UIP_HTONS(LRP_UDPPORT), NULL);
  udp_bind(udpconn, UIP_HTONS(LRP_UDPPORT));
  PRINTF("Created an UDP socket");
  PRINTF(" (local/remote port %u/%u)\n",
        UIP_HTONS(udpconn->lport), UIP_HTONS(udpconn->rport));

#if LRP_RREQ_RETRIES
  PRINTF("Set timer for RREQ retry %lums\n",
      RETRY_RREQ_INTERVAL * 1000 / CLOCK_SECOND);
  etimer_set(&dfet, RETRY_RREQ_INTERVAL);
#endif

#if LRP_RREQ_MININTERVAL
  timer_set(&rreq_ratelimit_timer, LRP_RREQ_MININTERVAL);
#endif

#if LRP_R_HOLD_TIME
  PRINTF("Set timer for route validity time check %u\n", RV_CHECK_INTERVAL);
  etimer_set(&rv, RV_CHECK_INTERVAL);
#endif

#if SND_QRY && !LRP_IS_SINK
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
      if(uip_ds6_defrt_choose() != NULL) {
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
  }
  PROCESS_END();
}

#endif /* WITH_IPV6_LRP */
/*---------------------------------------------------------------------------*/
