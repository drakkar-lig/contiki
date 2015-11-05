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
 *         Collection Tree maintenance algorithm
 * \author Chi-Anh La <la@imag.fr>
 * \author Martin Heusse <martin.heusse@imag.fr>
 * \author Audéoud Henry-Joseph <henry-joseph.audeoud@imag.fr>
 */

#if UIP_CONF_IPV6_LRP

#define DEBUG DEBUG_PRINT

#include "net/lrp/lrp.h"
#include "net/lrp/lrp-def.h"
#include "net/lrp/lrp-ct.h"
#include "net/lrp/lrp-global.h"
#include "net/lrp/lrp-msg.h"
#include "net/uip-debug.h"
#include "contiki.h"
#include "contiki-lib.h"
#include "contiki-net.h"
#include <string.h>

#define UIP_IP_BUF ((struct uip_udpip_hdr *)&uip_buf[UIP_LLH_LEN])
#define HOST_ROUTE_PREFIX_LEN 128

#if !LRP_IS_SINK
static struct ctimer retransmit_timer = {0};
static uint16_t dis_brk_nb_sent = 0;
static uint16_t exp_residuum = LRP_SEND_DIO_INTERVAL;
#endif /* !LRP_IS_SINK */


/*---------------------------------------------------------------------------*/
/* Implementation of Broken Routes Cache to avoid multiple forwarding of BRK
 * messages and to be able to retransmit UPD on the reverted path */
#if LRP_USE_DIO && LRP_IS_COORDINATOR && !LRP_IS_SINK
#define BRCACHESIZE 2

static struct {
  uip_ipaddr_t brk_sender;
  uint16_t seqno;
  uip_ipaddr_t forwarded_to;
} brcache[BRCACHESIZE];

/* Look for an entry into the cache */
static uip_ipaddr_t*
brc_lookup(const uip_ipaddr_t *brk_sender)
{
  unsigned n = (((uint8_t *)brk_sender)[0] +
      ((uint8_t *)brk_sender)[15]) % BRCACHESIZE;
  if(uip_ipaddr_cmp(&brcache[n].brk_sender, brk_sender)) {
    return &brcache[n].forwarded_to;
  }
  return NULL;
}

/* Force insertion of the BRK offer, without considering cached values. */
static void
brc_force_add(const uip_ipaddr_t *brk_sender, const uint16_t seqno,
    uip_ipaddr_t *forwarded_to)
{
  lrp_nbr_add(forwarded_to);
  unsigned n = (((uint8_t *)brk_sender)[0] +
      ((uint8_t *)brk_sender)[15]) % BRCACHESIZE;
  brcache[n].seqno = seqno;
  uip_ipaddr_copy(&brcache[n].forwarded_to, forwarded_to);
  uip_ipaddr_copy(&brcache[n].brk_sender, brk_sender);
}

/* Consider the BRK offer. If it is interesting, insert it into cache. */
static uint8_t
brc_add(const uip_ipaddr_t *brk_sender, const uint16_t seqno,
    uip_ipaddr_t *forwarded_to)
{
  lrp_nbr_add(forwarded_to);
  unsigned n = (((uint8_t *)brk_sender)[0] +
      ((uint8_t *)brk_sender)[15]) % BRCACHESIZE;
  if(SEQNO_GREATER_THAN(seqno, brcache[n].seqno) ||
      !uip_ipaddr_cmp(&brcache[n].brk_sender, brk_sender)) {
    brc_force_add(brk_sender, seqno, forwarded_to);
    return (1==1);
  } else {
    return (0==1);
  }
}
#endif /* LRP_USE_DIO && LRP_IS_COORDINATOR && !LRP_IS_SINK */


/*---------------------------------------------------------------------------*/
/* Change default route if offered one is better than the previous one. Return
 * NULL if the route has not been added. tree_seqno is the seqno used into the
 * tree; repair_seqno is the last known seqno sent by the sink to handle local
 * reparations. To choose route, we rely on repair_seqno, but only tree_seqno
 * is broadcasted through DIOs. */
#if !LRP_IS_SINK
static uip_ds6_defrt_t*
offer_default_route(const uip_ipaddr_t* sink_addr, uip_ipaddr_t* next_hop,
    const uint8_t metric_type, const uint16_t metric_value,
    const uint16_t tree_seqno,const uint16_t repair_seqno)
{
  uip_ds6_defrt_t *defrt = NULL;
  uint16_t lc;

  if(!lrp_ipaddr_is_empty(&lrp_state.sink_addr) &&
      !uip_ipaddr_cmp(sink_addr, &lrp_state.sink_addr)) {
    PRINTF("Not the same sink. Do not change it\n");
    return NULL;
  }

  lc = lrp_link_cost(next_hop, metric_type);
  if(SEQNO_GREATER_THAN(repair_seqno, lrp_state.repair_seqno) ||
      (repair_seqno == lrp_state.repair_seqno &&
       (metric_type == lrp_state.metric_type &&
        (metric_value + lc < lrp_state.metric_value ||
         (metric_value + lc == lrp_state.metric_value &&
          uip_ds6_defrt_choose() == NULL))))) {

    // Offered route is accepted, changing the state
    uip_ipaddr_copy(&lrp_state.sink_addr, sink_addr);
    lrp_state.tree_seqno = tree_seqno;
    lrp_state.repair_seqno = repair_seqno;
    lrp_state.metric_type = metric_type;
    lrp_state.metric_value = metric_value + lc;
    lrp_state_save();

    // Check if we are actually changing of next hop!
    defrt = uip_ds6_defrt_lookup(uip_ds6_defrt_choose());
    if(defrt == NULL || !uip_ip6addr_cmp(&defrt->ipaddr, next_hop)) {
      // New default route, remove previous one
      PRINTF("New default route\n");
      uip_ds6_defrt_rm(defrt);
      // Flush routes through new default route
      uip_ds6_route_rm_by_nexthop(next_hop);
      lrp_nbr_add(next_hop);
      defrt = uip_ds6_defrt_add(next_hop, LRP_DEFRT_LIFETIME);
#if LRP_SEND_SPONTANEOUS_RREP
      PRINTF("Will send spontaneous RREP to new successor\n");
      lrp_delayed_rrep();
#endif /* LRP_SEND_SPONTANEOUS_RREP */
    } else if(defrt != NULL) {
      // We just need to refresh the route
      PRINTF("Refreshing default route\n");
      stimer_set(&defrt->lifetime, LRP_DEFRT_LIFETIME);
    }
  } else {
    PRINTF("Skipping: route worse than previous\n");
  }
  return defrt;
}
#endif /* !LRP_IS_SINK */


/*---------------------------------------------------------------------------*/
/* Stop the reconnection algorithm */
#if !LRP_IS_SINK
static void
stop_reconnect_callback()
{
    ctimer_stop(&retransmit_timer);
    dis_brk_nb_sent = 0;
    exp_residuum = LRP_SEND_DIO_INTERVAL;
}

/* Emit messages needed when the node is disconnected to the LRP tree
 * structure.
 *
 * Node tries first a Direct Reassociation (DR) by sending DIS messages, then
 * tries a Link Reversal (LR) by sending BRK messages. If the node was never
 * associated to any tree, it may use only DR.
 */
static void
reconnect_callback()
{
  if(uip_ds6_defrt_choose() != NULL) {
    if(dis_brk_nb_sent >= LRP_LR_SEND_DIS_NB) {
      // We have a default route. Stop the reconnection algorithm.
      stop_reconnect_callback();
      return;
    }
    // Else, we do not have send enough DIS messages. Maybe a neighbour has
    // not send us a DIO message successfully. We thus continue sending DIS
    // messages.
  }

  // Send DIS/BRK message.
#if !LRP_IS_COORDINATOR
  // Is a leaf: only use DR.
  lrp_send_dis();
#else /* !LRP_IS_COORDINATOR */
  // Not a leaf. Should one use LR or DR?
  if(dis_brk_nb_sent < LRP_LR_SEND_DIS_NB || lrp_ipaddr_is_empty(&lrp_state.sink_addr)) {
    // Use DR
    lrp_send_dis();
  } else {
    // Use LR
    SEQNO_INCREASE(lrp_state.node_seqno);
    lrp_state_save();
    lrp_send_brk(&lrp_myipaddr, NULL, lrp_state.node_seqno, LRP_METRIC_HOP_COUNT, 0);
  }
#endif /* !LRP_IS_COORDINATOR */

  // Update state
  dis_brk_nb_sent++;
  exp_residuum *= LRP_DIS_EXP_PARAM;

  // Configure the callback timer
  ctimer_set(&retransmit_timer, LRP_SEND_DIO_INTERVAL - exp_residuum,
      (void (*)(void*))&reconnect_callback, NULL);
  PRINTF("DIS-BRK timer reset (%lums)\n",
      (LRP_SEND_DIO_INTERVAL - exp_residuum) * 1000 / CLOCK_SECOND);
}
#endif /* !LRP_IS_SINK */


/*---------------------------------------------------------------------------*/
/* Handle an incoming DIO type message. */
void
lrp_handle_incoming_dio(void)
{
#if !LRP_IS_SINK
  struct lrp_msg_dio *rm = (struct lrp_msg_dio *)uip_appdata;
#if LRP_IS_COORDINATOR
  uint16_t old_seqno = lrp_state.tree_seqno;
  uint8_t old_metric_type = lrp_state.metric_type;
  uint16_t old_metric_value = lrp_state.metric_value;
#endif /* LRP_IS_COORDINATOR */

  PRINTF("Received DIO ");
  PRINT6ADDR(&UIP_IP_BUF->srcipaddr);
  PRINTF(" -> ");
  PRINT6ADDR(&UIP_IP_BUF->destipaddr);
  PRINTF(" sink_addr=");
  PRINT6ADDR(&rm->sink_addr);
  PRINTF(" tree_seqno=%d", uip_ntohs(rm->tree_seqno));
  PRINTF(" metric type/value=%x/%u\n", rm->metric_type, rm->metric_value);

  rm->tree_seqno = uip_ntohs(rm->tree_seqno);

  offer_default_route(&rm->sink_addr, &UIP_IP_BUF->srcipaddr,
      rm->metric_type, rm->metric_value, rm->tree_seqno, rm->tree_seqno);

  // Check if state has changed
#if LRP_IS_COORDINATOR
  if(old_seqno != lrp_state.tree_seqno ||
      old_metric_type != lrp_state.metric_type ||
      old_metric_value != lrp_state.metric_value) {
    PRINTF("Position has changed. Will broadcast DIO message\n");
    lrp_delayed_dio(NULL);
  } else if(SEQNO_GREATER_THAN(lrp_state.tree_seqno, rm->tree_seqno) ||
      (lrp_state.metric_type == rm->metric_type &&
       lrp_state.metric_value + lrp_link_cost(&UIP_IP_BUF->srcipaddr, rm->metric_type) < rm->metric_value)) {
    // Assume symmetric costs
    PRINTF("Sender node may be interested by our DIO...\n");
    lrp_send_dio(&UIP_IP_BUF->srcipaddr);
  }
#endif
#endif /* !LRP_IS_SINK */
}


/*---------------------------------------------------------------------------*/
/* Handle an incoming DIS type message. */
void
lrp_handle_incoming_dis(void)
{
#if LRP_IS_COORDINATOR
  PRINTF("Received DIS\n");

  if(uip_ds6_defrt_lookup(&UIP_IP_BUF->srcipaddr) != NULL) {
    PRINTF("Skipping: it comes from a successor\n");
    return;
  }

#if !LRP_IS_SINK
  if(uip_ds6_defrt_choose() == NULL) {
    PRINTF("Skipping: no default route\n");
    return;
  }
#endif
  lrp_rand_wait();
#if LRP_SEND_DIO_UNICAST
  lrp_nbr_add(&UIP_IP_BUF->srcipaddr);
  lrp_send_dio(&UIP_IP_BUF->srcipaddr);
#else /* LRP_SEND_DIO_UNICAST */
  lrp_send_dio(NULL);
#endif /* LRP_SEND_DIO_UNICAST */
#endif /* LRP_IS_COORDINATOR */
}


/*---------------------------------------------------------------------------*/
/* Handle an incoming BRK type message. */
void
lrp_handle_incoming_brk()
{
#if LRP_USE_DIO && LRP_IS_COORDINATOR
  struct lrp_msg_brk *rm = (struct lrp_msg_brk *)uip_appdata;
#if !LRP_IS_SINK
  uip_ds6_defrt_t* defrt;
  uint16_t lc;
#endif

  if(lrp_is_my_global_address(&rm->lost_node)) {
    PRINTF("Skipping BRK: loops back\n");
    return;
  }

  PRINTF("Received BRK ");
  PRINT6ADDR(&UIP_IP_BUF->srcipaddr);
  PRINTF(" -> ");
  PRINT6ADDR(&UIP_IP_BUF->destipaddr);
  PRINTF(" node_seqno=%d", uip_ntohs(rm->node_seqno));
  PRINTF(" metric type/value=%x/%u", rm->metric_type, rm->metric_value);
  PRINTF(" lost_node=");
  PRINT6ADDR(&rm->lost_node);
  PRINTF("\n");

  rm->node_seqno = uip_ntohs(rm->node_seqno);

#if LRP_IS_SINK
  // Send UPD on the reversed route and exits
  SEQNO_INCREASE(lrp_state.repair_seqno);
  lrp_state_save();
  lrp_send_upd(&rm->lost_node, &lrp_state.sink_addr, &UIP_IP_BUF->srcipaddr,
           lrp_state.tree_seqno, lrp_state.repair_seqno, lrp_state.metric_type, 0);

#else /* LRP_IS_SINK */

  // Computing link cost
  lc = lrp_link_cost(&UIP_IP_BUF->srcipaddr, rm->metric_type);
  if(lc == 0) {
    PRINTF("Unable to determine the cost of the link to ");
    PRINT6ADDR(&UIP_IP_BUF->srcipaddr);
    PRINTF("\n");
    return;
  }

  defrt = uip_ds6_defrt_lookup(&UIP_IP_BUF->srcipaddr);
  if(defrt != NULL) {
    // BRK comes from our default next hop. Broadcasting
    brc_force_add(&rm->lost_node, rm->node_seqno, &UIP_IP_BUF->srcipaddr);
    lrp_rand_wait();
    lrp_send_brk(&rm->lost_node, NULL, rm->node_seqno, rm->metric_type,
        rm->metric_value + lc);
  } else {
    // BRK comes from a neighbor broken branch. Forwarding BRK to sink
    if(!brc_add(&rm->lost_node, rm->node_seqno, &UIP_IP_BUF->srcipaddr)) {
      PRINTF("Skipping: BRK is older than previous one\n");
      return;
    }
    lrp_send_brk(&rm->lost_node, uip_ds6_defrt_choose(), rm->node_seqno,
        rm->metric_type, rm->metric_value + lc);
  }
#endif /* LRP_IS_SINK */
#endif /* LRP_USE_DIO && LRP_IS_COORDINATOR */
}


/*---------------------------------------------------------------------------*/
/* Handle an incoming UPD type message. */
void
lrp_handle_incoming_upd()
{
#if LRP_USE_DIO && LRP_IS_COORDINATOR && !LRP_IS_SINK
  struct lrp_msg_upd *rm = (struct lrp_msg_upd *)uip_appdata;
  uip_ipaddr_t *nexthop;
  uint16_t lc;

  PRINTF("UPD message: ");
  PRINT6ADDR(&UIP_IP_BUF->srcipaddr);
  PRINTF(" -> ");
  PRINT6ADDR(&UIP_IP_BUF->destipaddr);
  PRINTF(" tree_seqno=%d", uip_ntohs(rm->tree_seqno));
  PRINTF(" repair_seqno=%d", uip_ntohs(rm->repair_seqno));
  PRINTF(" metric type/value=%x/%u", rm->metric_type, rm->metric_value);
  PRINTF(" lost_node=");
  PRINT6ADDR(&rm->lost_node);
  PRINTF("\n");

  rm->tree_seqno = uip_ntohs(rm->tree_seqno);
  rm->repair_seqno = uip_ntohs(rm->repair_seqno);

  // Try to use this UPD as default route
  if(offer_default_route(&rm->sink_addr, &UIP_IP_BUF->srcipaddr,
        rm->metric_type, rm->metric_value, rm->tree_seqno, rm->repair_seqno)
      == NULL) {
    PRINTF("Skipping: not a better route\n");
    return;
  }

  if(lrp_is_my_global_address(&rm->lost_node)) {
    // We are BRK originator. UPD has reach its final destination
    PRINTF("Route successfully repaired\n");
    return;
  }

  // Find route to lost node
  nexthop = brc_lookup(&rm->lost_node);
  if(nexthop == NULL) {
    PRINTF("Skipping: No route to transmit UPD\n");
    return;
  }

  // Computing link cost
  lc = lrp_link_cost(&UIP_IP_BUF->srcipaddr, rm->metric_type);
  if(lc == 0) {
    PRINTF("Unable to determine the cost of the link to ");
    PRINT6ADDR(&UIP_IP_BUF->srcipaddr);
    PRINTF("\n");
    return;
  }

  lrp_send_upd(&rm->lost_node, &rm->sink_addr, nexthop, rm->tree_seqno,
      rm->repair_seqno, rm->metric_type, rm->metric_value + lc);
#endif /* LRP_USE_DIO && LRP_IS_COORDINATOR && !LRP_IS_SINK */
}


/*---------------------------------------------------------------------------*/
/**
 * Activate a (re-)association to the collection tree
 */
#if !LRP_IS_SINK
void lrp_no_more_default_route(void)
{
#if !LRP_IS_COORDINATOR
  // Is a leaf: resetting tree-related informations
  lrp_state_new();
#endif /* !LRP_IS_COORDINATOR */
  reconnect_callback();
}
#endif /* !LRP_IS_SINK */

/*---------------------------------------------------------------------------*/
/* Initiate a global repair. Launch it once at start; then, it will be
 * automatically called again aftr LRP_MAX_DODAG_LIFETIME time. Or, it may be
 * called to force the global repair. */
#if LRP_IS_SINK
void
global_repair()
{
#if !LRP_MAX_DODAG_LIFETIME
  lrp_state.tree_seqno = SEQNO_INCREASE(lrp_state.repair_seqno);
  lrp_state_save();
  lrp_send_dio(NULL);
#else /* !LRP_MAX_DODAG_LIFETIME */
  static uint32_t gr_32bits_timer = 0;
  static struct ctimer gr_timer = {0};

  if(!ctimer_expired(&gr_timer) || gr_32bits_timer == 0) {
    // GR has been forced or has expired
    PRINTF("Initiating global repair\n");
    lrp_state.tree_seqno = SEQNO_INCREASE(lrp_state.repair_seqno);
    lrp_state_save();
    lrp_send_dio(NULL);
    gr_32bits_timer = LRP_MAX_DODAG_LIFETIME;
  }

  // Reinitialize the 32bits timer
  if(gr_32bits_timer > 0xFFFF) {
    ctimer_set(&gr_timer, 0xFFFF,
        (void (*)(void*))&global_repair, NULL);
    gr_32bits_timer -= 0xFFFF;
  } else {
    ctimer_set(&gr_timer, (uint16_t)gr_32bits_timer,
        (void (*)(void*))&global_repair, NULL);
    gr_32bits_timer = 0;
  }
#endif /* !LRP_MAX_DODAG_LIFETIME */
}
#endif /* LRP_IS_SINK */

#endif /* UIP_CONF_IPV6_LRP */
