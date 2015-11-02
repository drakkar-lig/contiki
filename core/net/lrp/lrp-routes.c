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
#include "net/lrp/lrp-global.h"
#include "net/lrp/lrp-msg.h"
#include "net/uip-debug.h"
#include <string.h>

#define UIP_IP_BUF ((struct uip_udpip_hdr *)&uip_buf[UIP_LLH_LEN])
#define HOST_ROUTE_PREFIX_LEN 128


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
      rt->state.valid_time = LRP_R_HOLD_TIME;
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
handle_incoming_rreq(void)
{
#if !LRP_IS_SINK
  struct lrp_msg_rreq *rm = (struct lrp_msg_rreq *)uip_appdata;
  //uip_ipaddr_t dest_addr, orig_addr; // FIXME
#if !USE_DIO
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
#if !USE_DIO
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
#endif /* !USE_DIO */

  // Answer to RREQ if the searched address is our address
  if(lrp_is_my_global_address(&rm->searched_addr)) {
    //uip_ipaddr_copy(&dest_addr, &rm->orig_addr);
    //uip_ipaddr_copy(&orig_addr, &rm->dest_addr);
    SEQNO_INCREASE(lrp_state.node_seqno);
#if SAVE_STATE
    state_save();
#endif
    send_rrep(&rm->source_addr, &UIP_IP_BUF->srcipaddr, &rm->searched_addr,
        lrp_state.node_seqno, LRP_METRIC_HOP_COUNT, 0);

#if LRP_IS_COORDINATOR
    // Only coordinator forward RREQ
  } else {
    PRINTF("Forward RREQ\n");
    lc = lrp_link_cost(&UIP_IP_BUF->srcipaddr, rm->metric_type);
    lrp_rand_wait();
    send_rreq(&rm->searched_addr, &rm->source_addr, rm->source_seqno,
        rm->metric_type, rm->metric_value + lc);
#endif /* LRP_IS_COORDINATOR */
  }
#endif /* !LRP_IS_SINK */
}


/*---------------------------------------------------------------------------*/
/* Handle an incoming RREP type message. */
void
handle_incoming_rrep(void)
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

#if USE_DIO
  // LRP: Do not accept RREP from our default route
  if(uip_ds6_defrt_lookup(&UIP_IP_BUF->srcipaddr)) {
    PRINTF("Do not allow RREP from default route\n");
    return;
  }
#endif /* USE_DIO */

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

#if LRP_RREQ_RETRIES && (LRP_IS_SINK || !USE_DIO)
  // Clean route request cache
  if(uip_ipaddr_cmp(&rm->dest_addr, &lrp_myipaddr)) {
    rrc_remove(&rm->orig_addr);
  }
#endif /* LRP_RREQ_RETRIES && (LRP_IS_SINK || !USE_DIO) */

  // Select next hop
#if !USE_DIO
  // LOADng: find a host route to destination
  if(!lrp_is_my_global_address(&rm->dest_addr)) {
    nexthop = uip_ds6_route_nexthop(uip_ds6_route_lookup(&rm->dest_addr));
    if(nexthop == NULL) {
      PRINTF("Unable to forward RREP: unknown destination\n");
    }
  }
#else /* !USE_DIO */
  // LRP: get the default route
#if !LRP_IS_SINK
  nexthop = uip_ds6_defrt_choose();
  if(uip_ds6_defrt_choose() == NULL) {
    PRINTF("Unable to forward RREP: no defaut route\n");
  }
#endif /* !LRP_IS_SINK */
#endif /* !USE_DIO */

#if !LRP_IS_SINK
  // Forward RREP to nexthop
  if(nexthop != NULL) {
    lc = lrp_link_cost(&UIP_IP_BUF->srcipaddr, rm->metric_type);
    send_rrep(&rm->dest_addr, nexthop, &rm->source_addr, rm->source_seqno,
        rm->metric_type, rm->metric_value + lc);
  }
#endif
#endif /* LRP_IS_COORDINATOR */
}


/*---------------------------------------------------------------------------*/
/* Handle an incoming RERR type message. */
void
handle_incoming_rerr(void)
{
  struct lrp_msg_rerr *rm = (struct lrp_msg_rerr *)uip_appdata;
#if !USE_DIO
  struct uip_ds6_route *rt;
#endif
#if LRP_IS_COORDINATOR && USE_DIO && !LRP_IS_SINK
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

#if !USE_DIO
  // LOADng: forwarding RERR to dest_addr
  rt = uip_ds6_route_lookup(&rm->dest_addr);
  if(rt != NULL) {
    send_rerr(&rm->dest_addr, &rm->addr_in_error, uip_ds6_route_nexthop(rt));
  }
#else
  // LRP
#if !LRP_IS_SINK
  if(uip_ds6_defrt_lookup(&UIP_IP_BUF->srcipaddr) != NULL) {
    PRINTF("Successor doesn't know us. Spontaneously send RREP\n");
    SEQNO_INCREASE(lrp_state.node_seqno);
    lrp_state_save();
    send_rrep(&lrp_state.sink_addr, &UIP_IP_BUF->srcipaddr, &lrp_myipaddr,
        lrp_state.node_seqno, LRP_METRIC_HOP_COUNT, 0);
  } else {
    // Forward the RERR higher
    defrt = uip_ds6_defrt_choose();
    if(defrt != NULL) {
      send_rerr(&rm->dest_addr, &rm->addr_in_error, defrt);
    }
  }
#endif /* !LRP_IS_SINK */
#endif /* !USE_DIO */
#else /* LRP_IS_COORDINATOR */
  PRINTF("Successor doesn't know us. Spontaneously send RREP\n");
  SEQNO_INCREASE(lrp_state.node_seqno);
  lrp_state_save();
  send_rrep(&lrp_state.sink_addr, &UIP_IP_BUF->srcipaddr, &lrp_myipaddr,
      lrp_state.node_seqno, LRP_METRIC_HOP_COUNT, 0);
#endif /* LRP_IS_COORDINATOR */
}

#endif /* WITH_IPV6_LRP */
