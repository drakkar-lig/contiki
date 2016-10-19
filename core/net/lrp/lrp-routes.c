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

#if UIP_CONF_IPV6_LRP

#define DEBUG DEBUG_PRINT

#include "net/lrp/lrp.h"
#include "net/lrp/lrp-def.h"
#include "net/lrp/lrp-routes.h"
#include "net/lrp/lrp-global.h"
#include "net/lrp/lrp-msg.h"
#include "net/ip/uip-debug.h"
#include <string.h>

#define UIP_IP_BUF ((struct uip_udpip_hdr *)&uip_buf[UIP_LLH_LEN])
#define HOST_ROUTE_PREFIX_LEN 128

/*---------------------------------------------------------------------------*/
/* Implementation of Route Request Cache for LRP_RREQ_RETRIES and
 * LRP_NET_TRAVERSAL_TIME */
#if LRP_RREQ_RETRIES && LRP_IS_SINK
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
  rrcache[n].expire_time = 2 * LRP_NET_TRAVERSAL_TIME;
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
             (void (*)(void *)) & rrc_check_expired_rreq, NULL);
}
#endif /* LRP_RREQ_RETRIES && LRP_IS_SINK */

/*---------------------------------------------------------------------------*/
/* Implementation of route validity time check and purge */
#if LRP_ROUTE_HOLD_TIME
void
lrp_check_expired_route()
{
  static struct ctimer check_route_validity_timer = { 0 };
  uip_ds6_route_t *r;

  for(r = uip_ds6_route_head(); r != NULL; r = uip_ds6_route_next(r)) {
    if(r->state.valid_time > LRP_ROUTE_VALIDITY_CHECK_INTERVAL) {
      r->state.valid_time -= LRP_ROUTE_VALIDITY_CHECK_INTERVAL;
    } else {
      uip_ds6_route_rm(r);
    }
  }

  ctimer_set(&check_route_validity_timer, LRP_ROUTE_VALIDITY_CHECK_INTERVAL,
             (void (*)(void *)) & lrp_check_expired_route, NULL);
}
#endif /* LRP_ROUTE_HOLD_TIME */

/*---------------------------------------------------------------------------*/
/* Add the described route into the routing table, if it is better than
 * the previous one. Return NULL if the route has not been added. */
#if LRP_IS_COORDINATOR
static uip_ds6_route_t *
offer_route(uip_ipaddr_t *orig_addr, const uint8_t length,
            uip_ipaddr_t *next_hop, const uint8_t metric_type,
            const uint16_t metric_value, const uint16_t node_seqno)
{
  uip_ds6_route_t *rt;
  uint16_t lc;

  /* Computing link cost */
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
    /* Offered route is better than previous one */
    if(rt != NULL) {
      uip_ds6_route_rm(rt);
    }
    lrp_nbr_add(next_hop);
    rt = uip_ds6_route_add(orig_addr, length, next_hop);
    if(rt != NULL) {
      rt->state.metric_type = metric_type;
      rt->state.metric_value = metric_value;
      rt->state.seqno = node_seqno;
      rt->state.valid_time = LRP_ROUTE_HOLD_TIME;
    }
    return rt;
  } else {
    /* Offered route is worse, refusing route */
    return NULL;
  }
}
#endif /* LRP_IS_COORDINATOR */

/*---------------------------------------------------------------------------*/
/* Handle an incoming RREQ type message. */
void
lrp_handle_incoming_rreq(uip_ipaddr_t* neighbor, struct lrp_msg_rreq_t* rreq)
{
#if !LRP_IS_SINK
  static seqno_t last_seen_rreq_seqno = 0;

  /* Check if it is a new RREQ message */
  if(SEQNO_GREATER_THAN(last_seen_rreq_seqno, rreq->source_seqno) ||
     last_seen_rreq_seqno == rreq->source_seqno) {
    PRINTF("Skip: RREQ too old\n");
    return;
  }

  /* Ensure the RREQ follows the DODAG */
  if(uip_ds6_defrt_lookup(neighbor) == NULL) {
    /* This is not a upstream neighbor */
    PRINTF("Skip: RREQ does not come from upstream neighbor\n");
    return;
  }

  last_seen_rreq_seqno = rreq->source_seqno;

  /* Answer to RREQ if the searched address is our address */
  if(lrp_is_my_global_address(&rreq->searched_addr)) {
    SEQNO_INCREASE(lrp_state.node_seqno);
    lrp_state_save();
    lrp_send_rrep(&lrp_state.sink_addr, uip_ds6_defrt_choose(),
                  &rreq->searched_addr,
                  lrp_state.node_seqno, LRP_METRIC_HOP_COUNT, 0);

#if LRP_IS_COORDINATOR
    /* Only coordinator forward RREQ */
  } else {
    PRINTF("Forward RREQ\n");
    lrp_delayed_rreq(&rreq->searched_addr, &rreq->source_addr,
                     rreq->source_seqno);
#endif /* LRP_IS_COORDINATOR */
  }
#else /* not !LRP_IS_SINK */
  PRINTF("Skip RREQ processing: is a sink\n");
#endif /* !LRP_IS_SINK */
}
/*---------------------------------------------------------------------------*/
/* Handle an incoming RREP type message. */
void
lrp_handle_incoming_rrep(uip_ipaddr_t* neighbor, struct lrp_msg_rrep_t* rrep)
{
#if LRP_IS_COORDINATOR
  struct uip_ds6_route *rt;
#if !LRP_IS_SINK
  uip_ipaddr_t *upstream_neighbor = NULL;
#endif

  /* Do not accept RREP from our default route */
  if(uip_ds6_defrt_lookup(neighbor) != NULL) {
    PRINTF("Do not allow RREP from default route\n");
    return;
  }

  /* Add link cost to described metric */
  rrep->metric_value += lrp_link_cost(neighbor, rrep->metric_type);

  /* Offer route to routing table */
  rt = offer_route(&rrep->source_addr, HOST_ROUTE_PREFIX_LEN,
                   neighbor, rrep->metric_type,
                   rrep->metric_value, rrep->source_seqno);
  if(rt != NULL) {
    PRINTF("Route inserted from RREP\n");
  } else {
    PRINTF("Former route is better\n");
  }
#if LRP_RREQ_RETRIES && LRP_IS_SINK
  /* Clean route request cache */
  rrc_remove(&rrep->source_addr);
#endif /* LRP_RREQ_RETRIES && LRP_IS_SINK */

#if !LRP_IS_SINK
  /* Forward RREP to upstream neighbor */
  upstream_neighbor = uip_ds6_defrt_choose();
  if(upstream_neighbor != NULL) {
    lrp_send_rrep(&rrep->dest_addr, upstream_neighbor, &rrep->source_addr,
                  rrep->source_seqno, rrep->metric_type, rrep->metric_value);
  } else {
    PRINTF("Unable to forward RREP: no defaut route\n");
    return;
  }
#endif /* !LRP_IS_SINK */
#endif /* LRP_IS_COORDINATOR */
}
/*---------------------------------------------------------------------------*/
/* Handle an incoming RERR type message. */
void
lrp_handle_incoming_rerr(uip_ipaddr_t* neighbor, struct lrp_msg_rerr_t* rerr)
{
#if LRP_IS_COORDINATOR && !LRP_IS_SINK
  uip_ipaddr_t *defrt;
#endif

#if LRP_IS_COORDINATOR
  /* Remove route */
  uip_ds6_route_rm(uip_ds6_route_lookup(&rerr->addr_in_error));
#endif /* LRP_IS_COORDINATOR */

#if !LRP_IS_SINK
  if(uip_ds6_defrt_lookup(neighbor) != NULL) {
    /* Upstream neighbor does not know us as its downstream neighbor */
    PRINTF("Upstream neighbor does not know us as its downstream neighbor. "
           "Spontaneously send RREP\n");
    SEQNO_INCREASE(lrp_state.node_seqno);
    lrp_state_save();
    lrp_send_rrep(&lrp_state.sink_addr, neighbor, &lrp_myipaddr,
                  lrp_state.node_seqno, LRP_METRIC_HOP_COUNT, 0);
  }

#if LRP_IS_COORDINATOR
  if(uip_ds6_defrt_lookup(neighbor) == NULL) {
    /* Forward packet upward, to completely remove the route */
    defrt = uip_ds6_defrt_choose();
    if(defrt != NULL) {
      lrp_send_rerr(&rerr->addr_in_error, defrt);
    }
  }
#endif /* LRP_IS_COORDINATOR */
#endif /* !LRP_IS_SINK */
}
/*---------------------------------------------------------------------------*/
#if LRP_IS_SINK
void
lrp_request_route_to(uip_ipaddr_t *host)
{
#if LRP_RREQ_MININTERVAL
  static struct timer rreq_ratelimit_timer = { 0 };
#endif

  PRINTF("Request a route towards ");
  PRINT6ADDR(host);
  PRINTF("\n");

  if(!lrp_addr_match_local_prefix(host)) {
    /* Address cannot be on the managed network: address does not match. */
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

  SEQNO_INCREASE(lrp_state.node_seqno);
  lrp_state_save();
  lrp_delayed_rreq(host, NULL, lrp_state.node_seqno);

#if LRP_RREQ_MININTERVAL
  timer_set(&rreq_ratelimit_timer, LRP_RREQ_MININTERVAL);
#endif /* LRP_RREQ_MININTERVAL */
}
#endif /* LRP_IS_SINK */

/*---------------------------------------------------------------------------*/
#if LRP_IS_COORDINATOR && !LRP_IS_SINK
void
lrp_routing_error(uip_ipaddr_t *source, uip_ipaddr_t *destination,
                  uip_lladdr_t *previoushop)
{
  uip_ipaddr_t *prevhop, ipaddr;
  prevhop = uip_ds6_nbr_ipaddr_from_lladdr(previoushop);
  if(prevhop == NULL) {
    /* Neighbor is unknown. Calculating its fe80:: ipaddr (it must listen it
     * even if it does not really use it). */
    uip_create_linklocal_prefix(&ipaddr);
    uip_ds6_set_addr_iid(&ipaddr, previoushop);
    uip_ds6_nbr_add(&ipaddr, previoushop, 0, NBR_REACHABLE);
    prevhop = &ipaddr;
  }
  if(prevhop != NULL) {
    lrp_send_rerr(destination, prevhop);
  }
}
#endif /* LRP_IS_COORDINATOR && !LRP_IS_SINK */

#endif /* UIP_CONF_IPV6_LRP */
