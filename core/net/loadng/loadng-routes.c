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

#if UIP_CONF_IPV6_LOADNG

#define DEBUG DEBUG_PRINT

#include "net/loadng/loadng.h"
#include "net/loadng/loadng-def.h"
#include "net/loadng/loadng-routes.h"
#include "net/loadng/loadng-global.h"
#include "net/loadng/loadng-msg.h"
#include "net/ip/uip-debug.h"
#include <string.h>

#define UIP_IP_BUF ((struct uip_udpip_hdr *)&uip_buf[UIP_LLH_LEN])
#define HOST_ROUTE_PREFIX_LEN 128

/*---------------------------------------------------------------------------*/
/* Implementation of Route Request Cache for LOADNG_RREQ_RETRIES and
 * LOADNG_NET_TRAVERSAL_TIME */
#if LOADNG_RREQ_RETRIES
#define RRCACHE 2 /* Size of the cache */

static struct {
  uip_ipaddr_t dest;
  uint16_t expire_time; /* == 0 if entry is inactive */
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
  rrcache[n].expire_time = 2 * LOADNG_NET_TRAVERSAL_TIME;
  rrcache[n].request_time = 1;
  uip_ipaddr_copy(&rrcache[n].dest, dest);
}
/* Check the expired RREQ. `interval` is the time interval between last check
 * and now (expressed in ticks). */
void
rrc_check_expired_rreq()
{
  static struct ctimer retry_rreq_timer = { 0 };
  int i;
  for(i = 0; i < RRCACHE; ++i) {
    if(rrcache[i].expire_time > LOADNG_RETRY_RREQ_INTERVAL) {
      rrcache[i].expire_time -= LOADNG_RETRY_RREQ_INTERVAL;
    } else if(rrcache[i].expire_time > 0) {
      if(rrcache[i].request_time == LOADNG_RREQ_RETRIES) {
        PRINTF("Abort RREQ to ");
        PRINT6ADDR(&rrcache[i].dest);
        PRINTF("\n");
        rrcache[i].expire_time = 0;
      } else {
        PRINTF("Retry RREQ to ");
        PRINT6ADDR(&rrcache[i].dest);
        PRINTF("\n");
        loadng_request_route_to(&rrcache[i].dest);
        rrcache[i].request_time++;
        rrcache[i].expire_time = 2 * LOADNG_NET_TRAVERSAL_TIME;
      }
    }
  }
  ctimer_set(&retry_rreq_timer, LOADNG_RETRY_RREQ_INTERVAL,
             (void (*)(void *)) & rrc_check_expired_rreq, NULL);
}
#endif /* LOADNG_RREQ_RETRIES */

/*---------------------------------------------------------------------------*/
/* Implementation of route validity time check and purge */
#if LOADNG_ROUTE_HOLD_TIME
void
loadng_check_expired_route()
{
  static struct ctimer check_route_validity_timer = { 0 };
  uip_ds6_route_t *r;

  for(r = uip_ds6_route_head(); r != NULL; r = uip_ds6_route_next(r)) {
    if(r->state.valid_time > LOADNG_ROUTE_VALIDITY_CHECK_INTERVAL) {
      r->state.valid_time -= LOADNG_ROUTE_VALIDITY_CHECK_INTERVAL;
    } else {
      uip_ds6_route_rm(r);
    }
  }

  ctimer_set(&check_route_validity_timer, LOADNG_ROUTE_VALIDITY_CHECK_INTERVAL,
             (void (*)(void *)) & loadng_check_expired_route, NULL);
}
#endif /* LOADNG_ROUTE_HOLD_TIME */

/*---------------------------------------------------------------------------*/
/* Add the described route into the routing table, if it is better than
 * the previous one. Return NULL if the route has not been added. */
static uip_ds6_route_t *
offer_route(uip_ipaddr_t *orig_addr, const uint8_t length,
            uip_ipaddr_t *next_hop, const uint8_t metric_type,
            const uint16_t metric_value, const uint16_t node_seqno)
{
  uip_ds6_route_t *rt;
  enum path_length_comparison_result_t plc;

  rt = uip_ds6_route_lookup(orig_addr);
  if(rt != NULL) {
    plc = path_length_compare(
      node_seqno, metric_type, metric_value,
      rt->state.seqno, rt->state.metric_type, rt->state.metric_value);
  }
  if(rt == NULL || plc == PLC_NEWER_SEQNO || plc == PLC_SHORTER_METRIC) {
    /* Offered route is better than previous one */
    if(rt != NULL) {
      uip_ds6_route_rm(rt);
    }
    loadng_nbr_add(next_hop);
    rt = uip_ds6_route_add(orig_addr, length, next_hop);
    if(rt != NULL) {
      rt->state.metric_type = metric_type;
      rt->state.metric_value = metric_value;
      rt->state.seqno = node_seqno;
      rt->state.valid_time = LOADNG_ROUTE_HOLD_TIME;
    }
    PRINTF("Route to ");
    PRINT6ADDR(&rt->ipaddr);
    PRINTF("/%d through ", rt->length);
    PRINT6ADDR(uip_ds6_route_nexthop(rt));
    PRINTF(" inserted)\n");
    return rt;
  } else {
    /* Offered route is worse, refusing route */
    return NULL;
  }
}

/*---------------------------------------------------------------------------*/
/* Handle an incoming RREQ type message. */
void
loadng_handle_incoming_rreq(uip_ipaddr_t* neighbor, struct loadng_msg_rreq_t* rreq)
{
  /* Add local link to described metric */
  rreq->metric_value += loadng_link_cost(neighbor, rreq->metric_type);

  /* Try to add route to source */
  if(!loadng_is_my_global_address(&rreq->source_addr)) {
    if(offer_route(&rreq->source_addr, HOST_ROUTE_PREFIX_LEN, neighbor,
                   rreq->metric_type, rreq->metric_value, rreq->source_seqno)
         == NULL) {
      PRINTF("Skip: RREQ is too bad\n");
      return;
    }
  }

  /* Answer to RREQ if the searched address is our address */
  if(loadng_is_my_global_address(&rreq->searched_addr)) {
    PRINTF("Answer to RREQ\n");
    SEQNO_INCREASE(loadng_state.node_seqno);
    loadng_state_save();
    loadng_send_rrep(&rreq->source_addr, neighbor, &rreq->searched_addr,
                     loadng_state.node_seqno, LOADNG_METRIC_HOP_COUNT, 0);
  } else {
    PRINTF("Forward RREQ\n");
    loadng_delayed_rreq(&rreq->searched_addr, &rreq->source_addr, rreq->source_seqno,
                        rreq->metric_type, rreq->metric_value);
  }
}
/*---------------------------------------------------------------------------*/
/* Handle an incoming RREP type message. */
void
loadng_handle_incoming_rrep(uip_ipaddr_t* neighbor, struct loadng_msg_rrep_t* rrep)
{
  uip_ipaddr_t *nexthop = NULL;

  /* Add link cost to described metric */
  rrep->metric_value += loadng_link_cost(neighbor, rrep->metric_type);

  /* Offer route to routing table */
  if(offer_route(&rrep->source_addr, HOST_ROUTE_PREFIX_LEN,
                 neighbor, rrep->metric_type,
                 rrep->metric_value, rrep->source_seqno) == NULL) {
    PRINTF("Skip: RREP is too bad\n");
  }

#if LOADNG_RREQ_RETRIES
  /* Clean route request cache */
  rrc_remove(&rrep->source_addr);
#endif /* LOADNG_RREQ_RETRIES */

  if(loadng_is_my_global_address(&rrep->dest_addr)) {
    /* RREP has reach its destination */
    return;
  }

  /* Select next hop */
  nexthop = uip_ds6_route_nexthop(uip_ds6_route_lookup(&rrep->dest_addr));
  if(nexthop == NULL) {
    PRINTF("Unable to forward RREP: unknown destination\n");
    return;
  }

  loadng_send_rrep(&rrep->dest_addr, nexthop, &rrep->source_addr,
                   rrep->source_seqno, rrep->metric_type, rrep->metric_value);
}
/*---------------------------------------------------------------------------*/
/* Handle an incoming RERR type message. */
void
loadng_handle_incoming_rerr(uip_ipaddr_t* neighbor, struct loadng_msg_rerr_t* rerr)
{
  uip_ipaddr_t *nexthop;
  uip_ds6_route_t *route;

  route = uip_ds6_route_lookup(&rerr->addr_in_error);
  nexthop = uip_ds6_route_nexthop(route);
  if(nexthop == NULL || uip_ipaddr_cmp(nexthop, neighbor)) {
    /* Incorrect next hop / local route */
    PRINTF("Local route does not match RERR's one: ");
    if(route == NULL) {
      PRINTF("no local route\n");
    } else {
      PRINTF("next hops does not match (local=");
      PRINT6ADDR(nexthop);
      PRINTF(" v.s. rerr=");
      PRINT6ADDR(neighbor);
      PRINTF(")\n");
    }
    return;
  }

  /* Remove described route */
  PRINTF("Remove route towards ");
  PRINT6ADDR(&rerr->addr_in_error);
  PRINTF("\n");
  uip_ds6_route_rm(route);

  if(loadng_is_my_global_address(&rerr->dest_addr)) {
    /* RERR has reach its destination */
    return;
  }

  /* Forward RERR to dest_addr */
  nexthop = uip_ds6_route_nexthop(uip_ds6_route_lookup(&rerr->dest_addr));
  if(nexthop == NULL) {
    PRINTF("Unable to forward RERR: no route towards ");
    PRINT6ADDR(&rerr->dest_addr);
    PRINTF("\n");
    return;
  }

  PRINTF("Forwarding RERR to ");
  PRINT6ADDR(nexthop);
  PRINTF("\n");
  loadng_send_rerr(&rerr->dest_addr, &rerr->addr_in_error, nexthop);
}
/*---------------------------------------------------------------------------*/
void
loadng_request_route_to(uip_ipaddr_t *host)
{
#if LOADNG_RREQ_MININTERVAL
  static struct timer rreq_ratelimit_timer = { 0 };
#endif

  PRINTF("Request a route towards ");
  PRINT6ADDR(host);
  PRINTF("\n");

  if(!loadng_addr_match_local_prefix(host)) {
    /* Address cannot be on the managed network: address does not match. */
    PRINTF("Skip: No RREQ for a non-local address\n");
    return;
  }

#if LOADNG_RREQ_RETRIES
  if(rrc_lookup(host)) {
    PRINTF("Skip: address already requested\n");
    return;
  }
  rrc_add(host);
#endif /* LOADNG_RREQ_RETRIES */

#if LOADNG_RREQ_MININTERVAL
  if(!timer_expired(&rreq_ratelimit_timer)) {
    PRINTF("Skip: RREQ exceeds rate limit\n");
    return;
  }
#endif /* LOADNG_RREQ_MININTERVAL */

  SEQNO_INCREASE(loadng_state.node_seqno);
  loadng_state_save();
  loadng_delayed_rreq(host, &loadng_myipaddr, loadng_state.node_seqno,
                      LOADNG_METRIC_HOP_COUNT, 0);

#if LOADNG_RREQ_MININTERVAL
  timer_set(&rreq_ratelimit_timer, LOADNG_RREQ_MININTERVAL);
#endif /* LOADNG_RREQ_MININTERVAL */
}

/*---------------------------------------------------------------------------*/
void
loadng_routing_error(uip_ipaddr_t *source, uip_ipaddr_t *destination,
                     uip_lladdr_t *previoushop)
{
  uip_ipaddr_t *prevhop, ipaddr;
  prevhop = uip_ds6_nbr_ipaddr_from_lladdr(previoushop);
  if(prevhop == NULL) {
    /* Neighbor is unknown. Calculating its fe80:: ipaddr (it must listen it
     * even if it does not really use it). */
    uip_create_linklocal_prefix(&ipaddr);
    uip_ds6_set_addr_iid(&ipaddr, previoushop);
    uip_ds6_nbr_add(&ipaddr, previoushop, 0, 0, NBR_TABLE_REASON_UNDEFINED, NULL);
    prevhop = &ipaddr;
  }
  if(prevhop != NULL) {
    loadng_send_rerr(source, destination, prevhop);
  }
}
#endif /* UIP_CONF_IPV6_LOADNG */
