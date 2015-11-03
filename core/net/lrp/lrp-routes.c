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
 */

/**
 * \file
 *         Routes management
 * \author Chi-Anh La <la@imag.fr>
 * \author Martin Heusse <martin.heusse@imag.fr>
 * \author Audéoud Henry-Joseph <henry-joseph.audeoud@imag.fr>
 */

#if WITH_IPV6_LRP

#define DEBUG DEBUG_PRINT

#include "net/lrp/lrp.h"
#include "net/lrp/lrp-def.h"
#include "net/lrp/lrp-routes.h"
#include "net/lrp/lrp-global.h"
#include "net/lrp/lrp-msg.h"
#include "net/uip-debug.h"
#include <string.h>

#define UIP_IP_BUF ((struct uip_udpip_hdr *)&uip_buf[UIP_LLH_LEN])
#define HOST_ROUTE_PREFIX_LEN 128


/*---------------------------------------------------------------------------*/
/* Implementation of Route Request Cache for LRP_RREQ_RETRIES and
 * LRP_NET_TRAVERSAL_TIME */
#if LRP_RREQ_RETRIES && (LRP_IS_SINK || !LRP_USE_DIO)
#define RRCACHE 2 /* Size of the cache */

static struct {
  uip_ipaddr_t dest;
  uint16_t expire_time; // == 0 if entry is inactive
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
     rrcache[n].expire_time = 0;
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
void
rrc_check_expired_rreq()
{
  static struct ctimer retry_rreq_timer = {0};
  int i;
  for(i = 0; i < RRCACHE; ++i) {
    if(rrcache[i].expire_time > LRP_RETRY_RREQ_INTERVAL) {
      rrcache[i].expire_time -= LRP_RETRY_RREQ_INTERVAL;
    } else if(rrcache[i].expire_time > 0) {
      if(rrcache[i].request_time == LRP_RREQ_RETRIES) {
        PRINTF("Abort RREQ to ");
        PRINT6ADDR(&rrcache[i].dest);
        PRINTF("\n");
        rrcache[i].expire_time = 0;
      } else {
        PRINTF("Retry RREQ to ");
        PRINT6ADDR(&rrcache[i].dest);
        PRINTF("\n");
        lrp_request_route_to(&rrcache[i].dest);
        rrcache[i].request_time++;
        rrcache[i].expire_time = 2 * LRP_NET_TRAVERSAL_TIME;
      }
    }
  }
  ctimer_set(&retry_rreq_timer, LRP_RETRY_RREQ_INTERVAL,
      (void (*)(void*))&rrc_check_expired_rreq, NULL);
}
#endif /* LRP_RREQ_RETRIES && (LRP_IS_SINK || !LRP_USE_DIO) */


/*---------------------------------------------------------------------------*/
/* Implementation of route validity time check and purge */
#if LRP_ROUTE_HOLD_TIME
void
lrp_check_expired_route()
{
  static struct ctimer check_route_validity_timer = {0};
  uip_ds6_route_t *r;

  for(r = uip_ds6_route_head(); r != NULL; r = uip_ds6_route_next(r)) {
    if(r->state.valid_time > LRP_ROUTE_VALIDITY_CHECK_INTERVAL) {
      r->state.valid_time -= LRP_ROUTE_VALIDITY_CHECK_INTERVAL;
    } else {
      uip_ds6_route_rm(r);
    }
  }

  ctimer_set(&check_route_validity_timer, LRP_ROUTE_VALIDITY_CHECK_INTERVAL,
      (void (*)(void*))&lrp_check_expired_route, NULL);
}
#endif /* LRP_ROUTE_HOLD_TIME */


/*---------------------------------------------------------------------------*/
/* Implementation of RREQ Forwarding Cache to avoid multiple forwarding */
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
  return fwcache[n].seqno >= *seqno && uip_ipaddr_cmp(&fwcache[n].orig, orig);
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
/* Add the described route into the routing table, if it is better than
 * the previous one. Return NULL if the route has not been added. */
#if LRP_IS_COORDINATOR
static uip_ds6_route_t*
offer_route(uip_ipaddr_t* orig_addr, const uint8_t length,
    uip_ipaddr_t* next_hop, const uint8_t metric_type,
    const uint16_t metric_value, const uint16_t node_seqno)
{
  uip_ds6_route_t* rt;
  uint16_t lc;

  // Computing link cost
  lc = lrp_link_cost(next_hop, metric_type);
  if(lc == 0) {
    PRINTF("Unable to determine the cost of the link to ");
    PRINT6ADDR(&UIP_IP_BUF->srcipaddr);
    PRINTF("\n");
    return NULL;
  }

  rt = uip_ds6_route_lookup(orig_addr);
  if(rt == NULL ||
      SEQNO_GREATER_THAN(node_seqno, rt->state.seqno) ||
      (node_seqno == rt->state.seqno &&
       (metric_type == rt->state.metric_type &&
        metric_value + lc < rt->state.metric_value))) {
    // Offered route is better than previous one
    if(rt != NULL) uip_ds6_route_rm(rt);
    lrp_nbr_add(next_hop);
    rt = uip_ds6_route_add(orig_addr, length, next_hop);
    if(rt != NULL) {
      rt->state.metric_type = metric_type;
      rt->state.metric_value = metric_value;
      rt->state.seqno = node_seqno;
      rt->state.valid_time = LRP_ROUTE_HOLD_TIME;
      rt->state.ack_received = 1;
    }
    return rt;
  } else {
    // Offered route is worse, refusing route
    return NULL;
  }
}
#endif /* LRP_IS_COORDINATOR */


/*---------------------------------------------------------------------------*/
/* Handle an incoming RREQ type message. */
void
lrp_handle_incoming_rreq(void)
{
#if !LRP_IS_SINK
  struct lrp_msg_rreq *rm = (struct lrp_msg_rreq *)uip_appdata;
  //uip_ipaddr_t dest_addr, orig_addr; // FIXME
#if !LRP_USE_DIO
  uip_ds6_route_t* rt;
#endif
#if LRP_IS_COORDINATOR
  uint16_t lc;
#endif /* LRP_IS_COORDINATOR */

  PRINTF("Received RREQ ");
  PRINT6ADDR(&UIP_IP_BUF->srcipaddr);
  PRINTF(" -> ");
  PRINT6ADDR(&UIP_IP_BUF->destipaddr);
  PRINTF(" orig=");
  PRINT6ADDR(&rm->source_addr);
  PRINTF(" searched=");
  PRINT6ADDR(&rm->searched_addr);
  PRINTF(" seq=%u", uip_ntohs(rm->source_seqno));
  PRINTF(" metric t/v=%x/%u\n", rm->metric_type, rm->metric_value);

  rm->source_seqno = uip_ntohs(rm->source_seqno);

  // Check if we do not have already received a better RREQ message
#if !LRP_USE_DIO
  // LOADng's: try to add route to source
  if(!lrp_is_my_global_address(&rm->orig_addr)) {
    if((rt = offer_route(&rm->orig_addr, HOST_ROUTE_PREFIX_LEN,
            &UIP_IP_BUF->srcipaddr, rm->metric_type, metric_value, rm->node_seqno)) == NULL) {
      PRINTF("Skipping: has a better RREQ to dest\n");
      return;
    }
  }

#else
  // LRP: consult cache
  if(fwc_lookup(&rm->source_addr, &rm->source_seqno)) {
    PRINTF("Skipping: RREQ cached\n");
    return;
  }
  fwc_add(&rm->source_addr, &rm->source_seqno);
#endif /* !LRP_USE_DIO */

  // Answer to RREQ if the searched address is our address
  if(lrp_is_my_global_address(&rm->searched_addr)) {
    //uip_ipaddr_copy(&dest_addr, &rm->orig_addr);
    //uip_ipaddr_copy(&orig_addr, &rm->dest_addr);
    SEQNO_INCREASE(lrp_state.node_seqno);
    lrp_state_save();
    lrp_send_rrep(&rm->source_addr, &UIP_IP_BUF->srcipaddr, &rm->searched_addr,
        lrp_state.node_seqno, LRP_METRIC_HOP_COUNT, 0);

#if LRP_IS_COORDINATOR
    // Only coordinator forward RREQ
  } else {
    PRINTF("Forward RREQ\n");
    lc = lrp_link_cost(&UIP_IP_BUF->srcipaddr, rm->metric_type);
    lrp_rand_wait();
    lrp_send_rreq(&rm->searched_addr, &rm->source_addr, rm->source_seqno,
        rm->metric_type, rm->metric_value + lc);
#endif /* LRP_IS_COORDINATOR */
  }
#endif /* !LRP_IS_SINK */
}


/*---------------------------------------------------------------------------*/
/* Handle an incoming RREP type message. */
void
lrp_handle_incoming_rrep(void)
{
#if LRP_IS_COORDINATOR
  struct lrp_msg_rrep *rm = (struct lrp_msg_rrep *)uip_appdata;
  struct uip_ds6_route *rt;
#if !LRP_IS_SINK
  uip_ipaddr_t *nexthop = NULL;
  uint16_t lc;
#endif

  PRINTF("Received RREP ");
  PRINT6ADDR(&UIP_IP_BUF->srcipaddr);
  PRINTF(" -> ");
  PRINT6ADDR(&UIP_IP_BUF->destipaddr);
  PRINTF(" source=");
  PRINT6ADDR(&rm->source_addr);
  PRINTF(" dest=");
  PRINT6ADDR(&rm->dest_addr);
  PRINTF(" source_seqno=%u", uip_ntohs(rm->source_seqno));
  PRINTF(" metric t/v=%x/%u\n", rm->metric_type, rm->metric_value);

  rm->source_seqno = uip_ntohs(rm->source_seqno);

#if LRP_USE_DIO
  // LRP: Do not accept RREP from our default route
  if(uip_ds6_defrt_lookup(&UIP_IP_BUF->srcipaddr)) {
    PRINTF("Do not allow RREP from default route\n");
    return;
  }
#endif /* LRP_USE_DIO */

  // Offer route to routing table
  rt = offer_route(&rm->source_addr, HOST_ROUTE_PREFIX_LEN,
      &UIP_IP_BUF->srcipaddr, rm->metric_type, rm->metric_value, rm->source_seqno);
  if(rt != NULL) {
    PRINTF("Route inserted from RREP\n");
#if LRP_RREP_ACK
    rt->state.ack_received = 0; /* Pending route for ACK */
#endif /* LRP_RREP_ACK */
  } else {
    PRINTF("Former route is better\n");
  }

#if LRP_RREQ_RETRIES && (LRP_IS_SINK || !LRP_USE_DIO)
  // Clean route request cache
  rrc_remove(&rm->source_addr);
#endif /* LRP_RREQ_RETRIES && (LRP_IS_SINK || !LRP_USE_DIO) */

  // Select next hop
#if !LRP_USE_DIO
  // LOADng: find a host route to destination
  if(!lrp_is_my_global_address(&rm->dest_addr)) {
    nexthop = uip_ds6_route_nexthop(uip_ds6_route_lookup(&rm->dest_addr));
    if(nexthop == NULL) {
      PRINTF("Unable to forward RREP: unknown destination\n");
    }
  }
#else /* !LRP_USE_DIO */
  // LRP: get the default route
#if !LRP_IS_SINK
  nexthop = uip_ds6_defrt_choose();
  if(uip_ds6_defrt_choose() == NULL) {
    PRINTF("Unable to forward RREP: no defaut route\n");
  }
#endif /* !LRP_IS_SINK */
#endif /* !LRP_USE_DIO */

#if !LRP_IS_SINK
  // Forward RREP to nexthop
  if(nexthop != NULL) {
    lc = lrp_link_cost(&UIP_IP_BUF->srcipaddr, rm->metric_type);
    lrp_send_rrep(&rm->dest_addr, nexthop, &rm->source_addr, rm->source_seqno,
        rm->metric_type, rm->metric_value + lc);
  }
#endif
#endif /* LRP_IS_COORDINATOR */
}


/*---------------------------------------------------------------------------*/
/* Handle an incoming RERR type message. */
void
lrp_handle_incoming_rerr(void)
{
  struct lrp_msg_rerr *rm = (struct lrp_msg_rerr *)uip_appdata;
#if !LRP_USE_DIO
  struct uip_ds6_route *rt;
#endif
#if LRP_IS_COORDINATOR && LRP_USE_DIO && !LRP_IS_SINK
  uip_ipaddr_t* defrt;
#endif

  PRINTF("Recieved RERR ");
  PRINT6ADDR(&UIP_IP_BUF->srcipaddr);
  PRINTF(" -> ");
  PRINT6ADDR(&UIP_IP_BUF->destipaddr);
  PRINTF(" addr_in_error=");
  PRINT6ADDR(&rm->addr_in_error);
  PRINTF(" dest=");
  PRINT6ADDR(&rm->dest_addr);
  PRINTF("\n");

#if LRP_IS_COORDINATOR
  // Remove route
  uip_ds6_route_rm(uip_ds6_route_lookup(&rm->addr_in_error));

#if !LRP_USE_DIO
  // LOADng: forwarding RERR to dest_addr
  rt = uip_ds6_route_lookup(&rm->dest_addr);
  if(rt != NULL) {
    lrp_send_rerr(&rm->dest_addr, &rm->addr_in_error, uip_ds6_route_nexthop(rt));
  }
#else
  // LRP
#if !LRP_IS_SINK
  if(uip_ds6_defrt_lookup(&UIP_IP_BUF->srcipaddr) != NULL) {
    PRINTF("Successor doesn't know us. Spontaneously send RREP\n");
    SEQNO_INCREASE(lrp_state.node_seqno);
    lrp_state_save();
    lrp_send_rrep(&lrp_state.sink_addr, &UIP_IP_BUF->srcipaddr, &lrp_myipaddr,
        lrp_state.node_seqno, LRP_METRIC_HOP_COUNT, 0);
  } else {
    // Forward the RERR higher
    defrt = uip_ds6_defrt_choose();
    if(defrt != NULL) {
      lrp_send_rerr(&rm->dest_addr, &rm->addr_in_error, defrt);
    }
  }
#endif /* !LRP_IS_SINK */
#endif /* !LRP_USE_DIO */
#else /* LRP_IS_COORDINATOR */
  PRINTF("Successor doesn't know us. Spontaneously send RREP\n");
  SEQNO_INCREASE(lrp_state.node_seqno);
  lrp_state_save();
  lrp_send_rrep(&lrp_state.sink_addr, &UIP_IP_BUF->srcipaddr, &lrp_myipaddr,
      lrp_state.node_seqno, LRP_METRIC_HOP_COUNT, 0);
#endif /* LRP_IS_COORDINATOR */
}

/*---------------------------------------------------------------------------*/
#if LRP_IS_SINK || !LRP_USE_DIO
void
lrp_request_route_to(uip_ipaddr_t *host)
{
#if LRP_RREQ_MININTERVAL
  static struct timer rreq_ratelimit_timer = {0};
#endif

  PRINTF("Request a route towards ");
  PRINT6ADDR(host);
  PRINTF("\n");

  if(!lrp_addr_match_local_prefix(host)) {
    // Address cannot be on the managed network: address does not match.
    PRINTF("Skipping: No RREQ for a non-local address\n");
    return;
  }

#if LRP_RREQ_RETRIES
  if(rrc_lookup(host)) {
    PRINTF("Skipping: address already requested\n");
    return;
  }
  rrc_add(host);
#endif /* LRP_RREQ_RETRIES */

#if LRP_RREQ_MININTERVAL
  if(!timer_expired(&rreq_ratelimit_timer)) {
     PRINTF("Skipping: RREQ exceeds rate limit\n");
     return;
  }
#endif /* LRP_RREQ_MININTERVAL */

  lrp_rand_wait();
  SEQNO_INCREASE(lrp_state.node_seqno);
  lrp_state_save();
  lrp_send_rreq(host, &lrp_myipaddr, lrp_state.node_seqno, LRP_METRIC_HOP_COUNT, 0);

#if LRP_RREQ_MININTERVAL
  timer_set(&rreq_ratelimit_timer, LRP_RREQ_MININTERVAL);
#endif /* LRP_RREQ_MININTERVAL */
}
#endif /* LRP_IS_SINK || !LRP_USE_DIO */

/*---------------------------------------------------------------------------*/
#if LRP_IS_COORDINATOR && !LRP_IS_SINK
void
lrp_routing_error(uip_ipaddr_t* source, uip_ipaddr_t* destination,
    uip_lladdr_t* previoushop)
{
  uip_ipaddr_t *prevhop, ipaddr;
  prevhop = uip_ds6_nbr_ipaddr_from_lladdr(previoushop);
  if(prevhop == NULL) {
    // Neighbor is unknown. Calculating its fe80:: ipaddr (it must listen it
    // even if it does not really use it).
    uip_create_linklocal_prefix(&ipaddr);
    uip_ds6_set_addr_iid(&ipaddr, previoushop);
    uip_ds6_nbr_add(&ipaddr, previoushop, 0, NBR_REACHABLE);
    prevhop = &ipaddr;
  }
  if(prevhop != NULL) {
    lrp_send_rerr(source, destination, prevhop);
  }
}
#endif /* LRP_IS_COORDINATOR && !LRP_IS_SINK */

#endif /* WITH_IPV6_LRP */
