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
#include "net/ip/uip-debug.h"
#include "contiki.h"
#include "contiki-lib.h"
#include "contiki-net.h"
#include <string.h>
#include <inttypes.h>

#define UIP_IP_BUF ((struct uip_udpip_hdr *)&uip_buf[UIP_LLH_LEN])
#define HOST_ROUTE_PREFIX_LEN 128

/** Store informations about a neighbor */
typedef struct {
  uint8_t  link_cost_type;
  uint16_t link_cost_value;
  uint8_t  nb_consecutive_noack_msg;
  enum {
    UNKNOWN = 0,  // Initialization value
    REACHABLE,
    UNREACHABLE
  } reachability;
  struct timer unreachable_timer;/* TODO */
} lrp_neighbor_t;
/** List of all known neighbors and description to reach them */
NBR_TABLE_GLOBAL(lrp_neighbor_t, lrp_neighbors);
/** Check if the neighbor is still unreachable. Is so, return true. If not, mark
 * its reachability as UNKNOWN and return false. */
static uint8_t is_still_unreachable(lrp_neighbor_t*);
/** A callback function, used in HELLO message processing */
typedef void (*hello_callback_f)(uip_ipaddr_t* neighbor, struct lrp_msg* msg);
/** Add a callback, linked with a neighbor: when a HELLO message is received,
 * the callback function is called. Useful to postpone a message processing. */
static void hello_callback_add(
    const uip_ipaddr_t*, const hello_callback_f, const struct lrp_msg*);

#if !LRP_IS_SINK
static struct ctimer reconnect_timer = { 0 };
static uint16_t reconnect_nb_sent = 0;
static uint32_t exp_residuum = LRP_SEND_DIO_INTERVAL;
#endif /* !LRP_IS_SINK */

/*---------------------------------------------------------------------------*/
/* Implementation of Broken Routes Cache to avoid multiple forwarding of BRK
 * messages and to be able to retransmit UPD on the reverted path */
#if LRP_IS_COORDINATOR
#define BRCACHESIZE 2

static struct {
  uip_ipaddr_t brk_sender;
  uint16_t seqno;
  uip_ipaddr_t forwarded_to;
} brcache[BRCACHESIZE];

#if !LRP_IS_SINK
/* Look for an entry into the cache */
uip_ipaddr_t *
lrp_brc_lookup(const uip_ipaddr_t *brk_sender)
{
  unsigned n = (((uint8_t *)brk_sender)[0] +
                ((uint8_t *)brk_sender)[15]) % BRCACHESIZE;
  if(uip_ipaddr_cmp(&brcache[n].brk_sender, brk_sender)) {
    return &brcache[n].forwarded_to;
  }
  return NULL;
}
#endif /* !LRP_IS_SINK */
/** Force insertion of the BRK offer, without considering cached values. */
void
lrp_brc_force_add(const uip_ipaddr_t *brk_sender, const uint16_t seqno,
              uip_ipaddr_t *forwarded_to)
{
  lrp_nbr_add(forwarded_to);
  unsigned n = (((uint8_t *)brk_sender)[0] +
                ((uint8_t *)brk_sender)[15]) % BRCACHESIZE;
  brcache[n].seqno = seqno;
  uip_ipaddr_copy(&brcache[n].forwarded_to, forwarded_to);
  uip_ipaddr_copy(&brcache[n].brk_sender, brk_sender);
}
/** Consider the BRK offer. If it is interesting, insert it in the cache and
 * true is returned. */
uint8_t
lrp_brc_add(const uip_ipaddr_t *brk_sender, const uint16_t seqno,
        uip_ipaddr_t *forwarded_to)
{
  lrp_nbr_add(forwarded_to);
  unsigned n = (((uint8_t *)brk_sender)[0] +
                ((uint8_t *)brk_sender)[15]) % BRCACHESIZE;
  if(SEQNO_GREATER_THAN(seqno, brcache[n].seqno) ||
     !uip_ipaddr_cmp(&brcache[n].brk_sender, brk_sender)) {
    lrp_brc_force_add(brk_sender, seqno, forwarded_to);
    return 1 == 1;
  } else {
    return 0 == 1;
  }
}
#endif /* LRP_IS_COORDINATOR */

/*---------------------------------------------------------------------------*/
#if !LRP_IS_SINK
/* Change the default route. `successor` is the neighbor to use as successor ;
 * `link_cost` is the link cost value to this neighbor (types are not checked,
 * and are supposed to be equal between this variable and the information in
 * `msg`). `msg` is a DIO or UPD message from which the decision was taken to
 * select this neighbor as successor. */
static void
select_default_route(uip_ipaddr_t *successor, uint16_t link_cost,
                     struct lrp_msg *msg)
{
  uip_ds6_defrt_t *old_defrt = uip_ds6_defrt_lookup(successor);

  /* Update state */
  if(msg->type >> 4 == LRP_DIO_TYPE) {
    uip_ipaddr_copy(&lrp_state.sink_addr,
                    &((struct lrp_msg_dio_t*)msg)->sink_addr);
    lrp_state.tree_seqno   = ((struct lrp_msg_dio_t*)msg)->tree_seqno;
    lrp_state.repair_seqno = ((struct lrp_msg_dio_t*)msg)->tree_seqno;
    lrp_state.metric_type  = ((struct lrp_msg_dio_t*)msg)->metric_type;
    lrp_state.metric_value =
        ((struct lrp_msg_dio_t*)msg)->metric_value + link_cost;
  } else if(msg->type >> 4 == LRP_UPD_TYPE) {
    uip_ipaddr_copy(&lrp_state.sink_addr,
                    &((struct lrp_msg_upd_t*)msg)->sink_addr);
    lrp_state.tree_seqno   = ((struct lrp_msg_upd_t*)msg)->tree_seqno;
    lrp_state.repair_seqno = ((struct lrp_msg_upd_t*)msg)->repair_seqno;
    lrp_state.metric_type  = ((struct lrp_msg_upd_t*)msg)->metric_type;
    lrp_state.metric_value =
        ((struct lrp_msg_upd_t*)msg)->metric_value + link_cost;
  } else {
    PRINTF("WARNING: can't use message type 0x%x when selecting default route\n",
           msg->type >> 4);
    return;
  }


  /* Check if we are actually changing of next hop */
  if(old_defrt == NULL) {
    /* Remove previous default route */
    uip_ds6_defrt_rm(uip_ds6_defrt_lookup(uip_ds6_defrt_choose()));

    /* Flush routes through new default route */
    uip_ds6_route_rm_by_nexthop(successor);

    /* Record new default route */
    PRINTF("New default route. Successor is ");
    PRINT6ADDR(successor);
    PRINTF("\n");
    uip_ds6_defrt_add(successor, LRP_DEFRT_LIFETIME);

    /* Schedule RREP */
    PRINTF("Will send RREP to new successor\n");
    SEQNO_INCREASE(lrp_state.node_seqno);
    lrp_delayed_rrep(&lrp_state.sink_addr, successor, &lrp_myipaddr,
                     lrp_state.node_seqno, LRP_METRIC_HOP_COUNT, 0);
  } else {
    /* We just need to refresh this route */
    PRINTF("Refreshing default route (through ");
    PRINT6ADDR(successor);
    PRINTF(")\n");
    stimer_set(&old_defrt->lifetime, LRP_DEFRT_LIFETIME);
  }
  lrp_state_save();
}
#endif /* !LRP_IS_SINK */

/*---------------------------------------------------------------------------*/
/* Stop the reconnection algorithm */
#if !LRP_IS_SINK
static void
stop_reconnect_callback()
{
  ctimer_stop(&reconnect_timer);
  reconnect_nb_sent = 0;
  exp_residuum = LRP_SEND_DIO_INTERVAL;
}
/* Emit messages needed when the node is disconnected to the LRP tree
 * structure.
 *
 * Node tries first a Direct Reassociation (DR) by sending infinite-rank DIO
 * messages, then tries a Link Reversal (LR) by sending BRK messages. If the
 * node was never associated to any tree, it may use only DR.
 */
static void
reconnect_callback()
{
  uint8_t ring_size;

  if(!ctimer_expired(&reconnect_timer)) {
    PRINTF("Aborting reconnection: already pending\n");
    return;
  }

  if(uip_ds6_defrt_choose() != NULL) {
    if(reconnect_nb_sent >= LRP_LR_SEND_DIO_NB) {
      /* We have a default route and have sent enough DIO messages. Stop the
       * reconnection algorithm. */
      stop_reconnect_callback();
      return;
    }
    /* Else, we do not have send enough DIO messages. Maybe a neighbour has
     * not send us a DIO message successfully. We thus continue sending
     * DIO messages. */
  }
  /* Send infinite-rank DIO/BRK message. */
#if !LRP_IS_COORDINATOR
  /* Is a leaf: only use DR. */
  lrp_send_dio(NULL, LRP_DIO_OPTION_DETECT_ALL_SUCCESSORS);
#else /* !LRP_IS_COORDINATOR */
  /* Not a leaf. Should one use LR or DR? */
  if(reconnect_nb_sent < LRP_LR_SEND_DIO_NB ||
     lrp_ipaddr_is_empty(&lrp_state.sink_addr)) {
    /* Use DR */
    if(uip_ds6_defrt_choose() == NULL) {
      /* Node is not connected. Nodes that have the same rank than its previous
       * successor must answer. */
      lrp_send_dio(NULL, LRP_DIO_OPTION_DETECT_ALL_SUCCESSORS);
    } else {
      /* Node is connected. Nodes that have the same rank than its previous
       * successor may not answer. */
      lrp_send_dio(NULL, 0);
    }
  } else {
    /* Use LR */
    SEQNO_INCREASE(lrp_state.node_seqno);
    lrp_state_save();
    ring_size = reconnect_nb_sent - LRP_LR_SEND_DIO_NB;
    if(ring_size > LRP_LR_RING_INFINITE_SIZE) ring_size = LRP_LR_RING_INFINITE_SIZE;
    lrp_send_brk(&lrp_myipaddr, NULL, lrp_state.node_seqno,
                 LRP_METRIC_HOP_COUNT, 0, ring_size);
  }
#endif /* !LRP_IS_COORDINATOR */

  /* Update state */
  reconnect_nb_sent++;
  exp_residuum *= LRP_LR_EXP_PARAM;

  /* Configure the callback timer */
  ctimer_set(&reconnect_timer, LRP_SEND_DIO_INTERVAL - exp_residuum,
             (void (*)(void *)) &reconnect_callback, NULL);
  PRINTF("Local-repair timer reset (%" PRIu32 "ms)\n",
         (LRP_SEND_DIO_INTERVAL - exp_residuum) * 1000 / CLOCK_SECOND);
}
#endif /* !LRP_IS_SINK */

/*---------------------------------------------------------------------------*/
/* Handle an incoming DIO type message. */
void
lrp_handle_incoming_dio(uip_ipaddr_t* neighbor, struct lrp_msg_dio_t* dio)
{
  enum path_length_comparison_result_t plc;

#if !LRP_IS_SINK
  /* Is it the same sink ? */
  if(!lrp_ipaddr_is_empty(&lrp_state.sink_addr) &&
     !lrp_ipaddr_is_empty(&dio->sink_addr) &&
     !uip_ipaddr_cmp(&dio->sink_addr, &lrp_state.sink_addr)) {
    PRINTF("Skip DIO processing: not the same sink (multiple sinks not "
           "supported yet).\n");
    return;
  }
#endif /* !LRP_IS_SINK */

  /* Find link cost between ourself and this neighbor */
  lrp_neighbor_t* nbr = nbr_table_get_from_lladdr(
      lrp_neighbors, (linkaddr_t*) uip_ds6_nbr_lladdr_from_ipaddr(neighbor));

  if(nbr != NULL && nbr->reachability == UNREACHABLE) {
    if(is_still_unreachable(nbr)) {
      PRINTF("Skip DIO processing: neighbor is marked as unreachable.\n");
      return;
    } else {
      PRINTF("Unreachable timer has stopped, trying to use this neighbor again\n");
    }
  }

  if(nbr == NULL || nbr->reachability == UNKNOWN ||
     (dio->metric_type != LRP_METRIC_NONE && dio->metric_type != nbr->link_cost_type)) {
    /* Unknown neighbor, or different metric. Check the link and postpone the
       message processing */
    /* Ensure the either me or the neighbor has a metric ! */
    if(lrp_state.metric_type == LRP_METRIC_NONE && dio->metric_type == LRP_METRIC_NONE) {
      PRINTF("Skip DIO processing: neither us nor the neighbor have a usable metric\n");
      return;
    }
    PRINTF("Postpone DIO processing\n");
    uint8_t metric_type = (dio->metric_type != LRP_METRIC_NONE ? dio->metric_type : lrp_state.metric_type);
    hello_callback_add(neighbor, (hello_callback_f) lrp_handle_incoming_dio,
                       (struct lrp_msg*) dio);
    lrp_delayed_hello(neighbor, metric_type,
        lrp_link_cost(neighbor, metric_type),
        LRP_MSG_FLAG_PLEASE_REPLY);
    return;
  }

#if !LRP_IS_SINK
  /* Is the default route through this neighbor better than our current default
   * route? */
  plc = path_length_compare(
      dio->tree_seqno, dio->metric_type, dio->metric_value + nbr->link_cost_value,
      lrp_state.repair_seqno, lrp_state.metric_type, lrp_state.metric_value);
  if(plc == PLC_NEWER_SEQNO || plc == PLC_SHORTER_METRIC ||
     (plc == PLC_EQUAL && uip_ds6_defrt_choose() == NULL)) {
     if (lrp_state.tree_seqno != 0 && uip_ds6_defrt_choose() == NULL) {
       PRINTF("Trivial local repair finished\n");
       /* We have just finished a trivial local repair => ask all our
       predecessors to recreate their host route, as it has been broken by
       the local repair. */
       PRINTF("Schedule a confined RREQ\n");
       SEQNO_INCREASE(lrp_state.node_seqno);
       lrp_state_save();
       lrp_delayed_rreq(NULL, NULL, lrp_state.node_seqno);
    }
    /* Accept the neighbor as new successor */
    PRINTF("Neighbor ");
    PRINT6ADDR(neighbor);
    PRINTF(" accepted as successor from DIO\n");
    select_default_route(neighbor, nbr->link_cost_value, (struct lrp_msg*)dio);
#if LRP_IS_COORDINATOR
    /* Schedule broadcasting of this new information */
    lrp_delayed_dio(NULL, 0);
#endif /* LRP_IS_COORDINATOR */
    return;
  } else {
    PRINTF("DIO message refused to upstream neighbor selection\n");
  }
#endif /* !LRP_IS_SINK */

#if LRP_IS_COORDINATOR
  /* The neighbor is not selected as successor. Does it need a DIO back? */
#if !LRP_IS_SINK
  /* Ensure we have a default route, before sending any DIO */
  if(uip_ds6_defrt_choose() == NULL) {
    PRINTF("No default route. Won't send DIO back\n");
    return;
  }
#endif /* !LRP_IS_SINK */

  plc = path_length_compare(
      lrp_state.tree_seqno, lrp_state.metric_type,
      lrp_state.metric_value + nbr->link_cost_value,
      dio->tree_seqno, dio->metric_type, dio->metric_value);
  // Note: here, if the metrics types are not compatible,
  // `lrp_state->metric_value + nbr->link_cost_value` does not mean anything.
  // However, in this situation, we do not take care to PLC_EQUAL nor to
  // PLC_*_METRIC returned values, so it doesn't matter.
  if(plc == PLC_NEWER_SEQNO ||
     (lrp_state.metric_type == nbr->link_cost_type &&
      (plc == PLC_SHORTER_METRIC ||
       (plc == PLC_EQUAL && dio->options & LRP_DIO_OPTION_DETECT_ALL_SUCCESSORS)))) {
    PRINTF("Sender node may be interested by our DIO => will send one back\n");
    lrp_delayed_dio(neighbor, 0);
  }
#endif /* LRP_IS_COORDINATOR */
}
/*---------------------------------------------------------------------------*/
/* Handle an incoming BRK type message. */
void
lrp_handle_incoming_brk(uip_ipaddr_t* neighbor, struct lrp_msg_brk_t* brk)
{
#if LRP_IS_COORDINATOR
#if !LRP_IS_SINK
  if(lrp_is_my_global_address(&brk->initial_sender)) {
    PRINTF("Skip BRK processing: it loops back\n");
    return;
  }
#endif /* !LRP_IS_SINK */

  /* Find link cost between ourself and this neighbor */
  lrp_neighbor_t* nbr = nbr_table_get_from_lladdr(
      lrp_neighbors, (linkaddr_t*) uip_ds6_nbr_lladdr_from_ipaddr(neighbor));

  if(nbr != NULL && nbr->reachability == UNREACHABLE) {
    if(is_still_unreachable(nbr)) {
      PRINTF("Skip BRK processing: neighbor is marked as unreachable.\n");
      return;
    } else {
      PRINTF("Unreachable timer has stopped, trying to use this neighbor again\n");
    }
  }

  if(nbr == NULL || nbr->reachability == UNKNOWN || brk->metric_type != nbr->link_cost_type) {
    /* Unknown neighbor. Check the link and postpone the message processing */
    PRINTF("Postpone BRK processing\n");
    hello_callback_add(neighbor, (hello_callback_f) lrp_handle_incoming_brk,
                      (struct lrp_msg*) brk);
    lrp_delayed_hello(neighbor, brk->metric_type,
        lrp_link_cost(neighbor, brk->metric_type),
        LRP_MSG_FLAG_PLEASE_REPLY);
    return;
  }

#if LRP_IS_SINK
  /* Send UPD on the reversed route and exits */
  if(!lrp_brc_add(&brk->initial_sender, brk->node_seqno, neighbor)) {
    PRINTF("Skipping: BRK is worst than a former\n");
    return;
  }
  SEQNO_INCREASE(lrp_state.repair_seqno);
  lrp_state_save();
  lrp_send_upd(&brk->initial_sender, &lrp_state.sink_addr, neighbor,
               lrp_state.tree_seqno, lrp_state.repair_seqno,
               lrp_state.metric_type, 0);

#else /* LRP_IS_SINK */
  if(uip_ds6_defrt_lookup(neighbor) != NULL) {
    /* BRK comes from our default next hop. Should be broadcast, but check the
     * ring size before. */
    if(brk->ring_size == 0) {
      PRINTF("Skipping: BRK's ring is too large\n");
      return;
    }
    if(brk->ring_size != LRP_LR_RING_INFINITE_SIZE) {
      brk->ring_size--;
    }
    lrp_brc_force_add(&brk->initial_sender, brk->node_seqno, neighbor);
    lrp_delayed_brk(&brk->initial_sender, NULL, brk->node_seqno,
                    brk->metric_type, brk->metric_value + nbr->link_cost_value,
                    brk->ring_size);

  } else {
    /* BRK comes from a neighbor broken branch. Forwarding BRK to sink */
    if(!lrp_brc_add(&brk->initial_sender, brk->node_seqno, neighbor)) {
      PRINTF("Skipping: BRK is worst than a former\n");
      return;
    }
    lrp_send_brk(&brk->initial_sender, uip_ds6_defrt_choose(), brk->node_seqno,
                 brk->metric_type, brk->metric_value + nbr->link_cost_value,
                 brk->ring_size);
  }
#endif /* LRP_IS_SINK */
#endif /* LRP_IS_COORDINATOR */
}
/*---------------------------------------------------------------------------*/
/* Handle an incoming UPD type message. */
void
lrp_handle_incoming_upd(uip_ipaddr_t* neighbor, struct lrp_msg_upd_t* upd)
{
#if LRP_IS_COORDINATOR && !LRP_IS_SINK
  /* Is it the same sink ? */
  if(!lrp_ipaddr_is_empty(&lrp_state.sink_addr) &&
     !uip_ipaddr_cmp(&upd->sink_addr, &lrp_state.sink_addr)) {
    PRINTF("Skip UPD processing: not the same sink (multiple sinks not "
           "supported yet).\n");
    return;
  }

  /* Find link cost between ourself and this neighbor */
  lrp_neighbor_t* nbr = nbr_table_get_from_lladdr(
      lrp_neighbors, (linkaddr_t*) uip_ds6_nbr_lladdr_from_ipaddr(neighbor));
  if(nbr == NULL || nbr->reachability == UNKNOWN || nbr->link_cost_type != upd->metric_type) {
    /* Unknown neighbor, or different metric. Check the link and postpone the
       message processing */
    PRINTF("Postpone UPD processing\n");
    hello_callback_add(neighbor, (hello_callback_f) lrp_handle_incoming_upd,
                      (struct lrp_msg*) upd);
    lrp_send_hello(neighbor, upd->metric_type,
        lrp_link_cost(neighbor, upd->metric_type),
        LRP_MSG_FLAG_PLEASE_REPLY);
    return;
  }

  /* Try to use this UPD as default route */
  enum path_length_comparison_result_t plc = path_length_compare(
      upd->repair_seqno, upd->metric_type, upd->metric_value + nbr->link_cost_value,
      lrp_state.repair_seqno, lrp_state.metric_type, lrp_state.metric_value);
  if(plc == PLC_NEWER_SEQNO || plc == PLC_SHORTER_METRIC) {
    /* The offer in the UPD message is better than previous successor. Select
     * it as new successor */

    if(!lrp_is_predecessor(neighbor) && uip_ds6_defrt_lookup(neighbor) == NULL) {
      /* Neighbor is nor a predecessor nor a successor => We are the new subtree
         root. Ask all our predecessors to recreate their host route, as it has
         been broken by the local repair. */
      PRINTF("Schedule a confined RREQ\n");
      SEQNO_INCREASE(lrp_state.node_seqno);
      lrp_state_save();
      lrp_delayed_rreq(NULL, NULL, lrp_state.node_seqno);
    }

    select_default_route(neighbor, nbr->link_cost_value, (struct lrp_msg*)upd);

    if(lrp_is_my_global_address(&upd->lost_node)) {
      /* We are the BRK originator. UPD has reach its final destination */
      PRINTF("Local repair finished\n");
      return;
    }

    /* Find the neighbor to which we have to forward the UPD message */
    uip_ipaddr_t* nexthop = lrp_brc_lookup(&upd->lost_node);
    if(nexthop == NULL) {
      PRINTF("Skip UPD forwarding: No route to transmit UPD towards ");
      PRINT6ADDR(&upd->lost_node);
      PRINTF("\n");
      return;
    }

    /* Forward the UPD message to this neighbor */
    lrp_send_upd(&upd->lost_node, &upd->sink_addr, nexthop,
                 upd->tree_seqno, upd->repair_seqno,
                 upd->metric_type, upd->metric_value + nbr->link_cost_value);
  }
#endif /* LRP_IS_COORDINATOR && !LRP_IS_SINK */
}
/*---------------------------------------------------------------------------*/
/* Handle an incoming HELLO type message */
#define HELLO_CALLBACK_BUFFER_SIZE 2
static struct {
  hello_callback_f callback;
  uip_ipaddr_t neighbor;
  // Buffer large enough to store any LRP message
  uint8_t message[LRP_MAX_MSG_SIZE];
} hello_callback_buf[HELLO_CALLBACK_BUFFER_SIZE];
static void
hello_callback_add(const uip_ipaddr_t* neighbor, const hello_callback_f callback,
                   const struct lrp_msg* message)
{
  static int i = 0;
  // Take a new space. Override last value even if it is used: it is a too old
  // one.
  i = (i + 1) % HELLO_CALLBACK_BUFFER_SIZE;
  hello_callback_buf[i].callback = callback;
  uip_ip6addr_copy(&hello_callback_buf[i].neighbor, neighbor);
  memcpy(&hello_callback_buf[i].message, (void*) message, LRP_MAX_MSG_SIZE);
  // Note: it does not matter if we copy too many memory because it will never
  // overflow of the whole buffer
}
void
lrp_handle_incoming_hello(uip_ipaddr_t* neighbor, struct lrp_msg_hello_t* hello)
{
  if(hello->link_cost_type == LRP_METRIC_NONE) {
    if(lrp_state.metric_type == LRP_METRIC_NONE) return;
    lrp_send_hello(neighbor, lrp_state.metric_type,
                   lrp_link_cost(neighbor, lrp_state.metric_type), LRP_MSG_FLAG_PLEASE_REPLY);
    return;
  }

  uint16_t local_link_cost = lrp_link_cost(neighbor, hello->link_cost_type);

  /* Save the information in the neighbor table */
  lrp_neighbor_t* nbr = nbr_table_get_from_lladdr(
      lrp_neighbors, (linkaddr_t*) uip_ds6_nbr_lladdr_from_ipaddr(neighbor));
  if(nbr == NULL) {
    /* Unknown neighbor, create it */
    PRINTF("Add neighbor ");
    PRINT6ADDR(neighbor);
    PRINTF(" in neighbor table\n");
    nbr = nbr_table_add_lladdr(
        lrp_neighbors, (linkaddr_t*) uip_ds6_nbr_lladdr_from_ipaddr(neighbor));
  }
  nbr->link_cost_type = hello->link_cost_type;
  nbr->link_cost_value = hello->link_cost_value > local_link_cost ?
      hello->link_cost_value : local_link_cost;

  /* Reply if needed */
  if(hello->options & LRP_MSG_FLAG_PLEASE_REPLY) {
    lrp_send_hello(neighbor, hello->link_cost_type, local_link_cost, 0x0);
  }

  /* Call callback if there is one activated for this neighbor */
  int i;
  for(i = 0; i < HELLO_CALLBACK_BUFFER_SIZE; i++) {
    if(uip_ipaddr_cmp(&hello_callback_buf[i].neighbor, neighbor)) {
      PRINTF("Call hello callback\n");
      hello_callback_buf[i].callback(&hello_callback_buf[i].neighbor,
          (struct lrp_msg*) &hello_callback_buf[i].message);
      /* Reset neighbor address to clear the buffer */
      uip_ip6addr(&hello_callback_buf[i].neighbor, 0, 0, 0, 0, 0, 0, 0, 0);
    }
  }
}
/*---------------------------------------------------------------------------*/
/**
 * Activate a (re-)association to the collection tree
 */
#if !LRP_IS_SINK
void
lrp_no_more_default_route(void)
{
#if !LRP_IS_COORDINATOR
  /* Is a leaf: resetting tree-related informations */
  lrp_state_new();
#endif /* !LRP_IS_COORDINATOR */
  reconnect_callback();
}
#endif /* !LRP_IS_SINK */

/*---------------------------------------------------------------------------*/
/* Initiate a global repair. Launch it once at start; then, it will be
 * automatically called again after LRP_MAX_DODAG_LIFETIME time. Or, it may be
 * called to force the global repair. */
#if LRP_IS_SINK
void
global_repair()
{
#if !LRP_MAX_DODAG_LIFETIME
  lrp_state.tree_seqno = SEQNO_INCREASE(lrp_state.repair_seqno);
  lrp_state_save();
  lrp_send_dio(NULL, 0);
#else /* !LRP_MAX_DODAG_LIFETIME */
  static uint32_t gr_32bits_timer = 0;
  static struct ctimer gr_timer = { 0 };

  if(!ctimer_expired(&gr_timer) || gr_32bits_timer == 0) {
    /* GR has been forced or has expired */
    PRINTF("Initiating global repair\n");
    lrp_state.tree_seqno = SEQNO_INCREASE(lrp_state.repair_seqno);
    lrp_state_save();
    lrp_send_dio(NULL, 0);
    gr_32bits_timer = LRP_MAX_DODAG_LIFETIME;
  }

  /* Reinitialize the 32bits timer */
  if(gr_32bits_timer > 0xFFFF) {
    ctimer_set(&gr_timer, 0xFFFF,
               (void (*)(void *)) & global_repair, NULL);
    gr_32bits_timer -= 0xFFFF;
  } else {
    ctimer_set(&gr_timer, (uint16_t)gr_32bits_timer,
               (void (*)(void *)) & global_repair, NULL);
    gr_32bits_timer = 0;
  }
#endif /* !LRP_MAX_DODAG_LIFETIME */
}
#endif /* LRP_IS_SINK */
/* Layer II callback. Used to discover neighbors unreachability */
void
lrp_neighbor_callback(const linkaddr_t *addr, int status, int mutx)
{
#if !UIP_ND6_SEND_NA
  uip_ipaddr_t *nbr_ipaddr = uip_ds6_nbr_ipaddr_from_lladdr((uip_lladdr_t *) addr);
  lrp_neighbor_t *nbr =
      (lrp_neighbor_t *) nbr_table_get_from_lladdr(lrp_neighbors, addr);

  if(nbr == NULL) {
    PRINTF("Add neighbor ");
    PRINTLLADDR((uip_lladdr_t *) addr);
    PRINTF(" in neighbor list\n");
    nbr = nbr_table_add_lladdr(lrp_neighbors, addr);
  }

  if(status == MAC_TX_NOACK) {
    /* Message is not received by neighbor. Count unacked messages */
    nbr->nb_consecutive_noack_msg += 1;
    PRINTF("No ack received from next hop ");
    PRINTLLADDR((uip_lladdr_t *)addr);
    PRINTF(" (counter is %d/%d)\n",
           nbr->nb_consecutive_noack_msg, LRP_MAX_CONSECUTIVE_NOACKED_MESSAGES);

    if(nbr->nb_consecutive_noack_msg >= LRP_MAX_CONSECUTIVE_NOACKED_MESSAGES) {
      /* Neighbor seems to be unreachable */
      PRINTF("Delete routes through it\n");
      uip_ds6_route_rm_by_nexthop(nbr_ipaddr);
#if !LRP_IS_SINK
      /* Was this nexthop the default route ? */
      if(uip_ds6_defrt_lookup(nbr_ipaddr) != NULL) {
        PRINTF("This was the default route. Launch LR algorithm\n");
        uip_ds6_defrt_rm(uip_ds6_defrt_lookup(nbr_ipaddr));
        PROCESS_CONTEXT_BEGIN(&lrp_process);
        lrp_no_more_default_route();
        PROCESS_CONTEXT_END();
      }
#endif /* !LRP_IS_SINK */
      nbr->reachability = UNREACHABLE;
      timer_set(&nbr->unreachable_timer, LRP_NBR_UNREACHABLE_DURATION);
    }

  } else if(status == MAC_TX_OK) {
    /* Resetting counter */
    if(nbr->nb_consecutive_noack_msg != 0) {
      /* The neighbor has not received our last message, but has received this
       * one. It is now reachable */
      PRINTF("Received ack from ");
      PRINTLLADDR((uip_lladdr_t *)addr);
      PRINTF(": reset noack counter");
      PRINTF("\n");
    }
    nbr->nb_consecutive_noack_msg = 0;
    nbr->reachability = REACHABLE;
  }
#endif /* !UIP_ND6_SEND_NA */
}
static uint8_t
is_still_unreachable(lrp_neighbor_t *nbr)
{
  if(nbr->reachability == UNREACHABLE &&
     timer_expired(&nbr->unreachable_timer)) {
    nbr->reachability = UNKNOWN;
    return 0;
  }
  return 1;
}
/*---------------------------------------------------------------------------*/

#endif /* UIP_CONF_IPV6_LRP */
