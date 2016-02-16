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
 *         Messages management
 * \author Chi-Anh La <la@imag.fr>
 * \author Martin Heusse <martin.heusse@imag.fr>
 * \author Audéoud Henry-Joseph <henry-joseph.audeoud@imag.fr>
 */

#if UIP_CONF_IPV6_LRP

#define DEBUG DEBUG_PRINT

#include "net/lrp/lrp.h"
#include "net/lrp/lrp-def.h"
#include "net/lrp/lrp-global.h"
#include "net/lrp/lrp-ct.h"
#include "net/lrp/lrp-routes.h"
#include "net/lrp/lrp-msg.h"
#include "net/ip/uip-debug.h"
#include <string.h>

/*---------------------------------------------------------------------------*/
/* Format and broadcast a RREQ type packet. */
#if LRP_IS_COORDINATOR
void
lrp_send_rreq(const uip_ipaddr_t *searched_addr,
              const uip_ipaddr_t *source_addr,
              const uint16_t source_seqno,
              const uint8_t metric_type,
              const uint16_t metric_value)
{
  struct lrp_msg_rreq_t rm;

  PRINTF("Send RREQ (broadcast) for ");
  PRINT6ADDR(searched_addr);
  PRINTF(" seqno/metric/value=%u/0x%x/%u\n", source_seqno, metric_type, metric_value);

  /* Fill message */
  rm.type = (LRP_RREQ_TYPE << 4) | 0x0;
  rm.addr_len = (0x0 << 4) | LRP_ADDR_LEN_IPV6;
  rm.source_seqno = uip_htons(source_seqno);
  rm.metric_type = metric_type;
  rm.metric_value = metric_value;
  uip_ipaddr_copy(&rm.searched_addr, searched_addr);
  uip_ipaddr_copy(&rm.source_addr, source_addr);

  /* Send packet */
  uip_create_linklocal_lln_routers_mcast(&lrp_udpconn->ripaddr);
  uip_udp_packet_send(lrp_udpconn, &rm, sizeof(struct lrp_msg_rreq_t));
  memset(&lrp_udpconn->ripaddr, 0, sizeof(lrp_udpconn->ripaddr));
}
struct send_rreq_params_t {
  uip_ipaddr_t searched_addr;
  uip_ipaddr_t source_addr;
  uint16_t source_seqno;
  uint8_t metric_type;
  uint16_t metric_value;
};

static void
wrap_send_rreq(struct send_rreq_params_t *params)
{
  lrp_send_rreq(&params->searched_addr, &params->source_addr,
                params->source_seqno, params->metric_type,
                params->metric_value);
}
void
lrp_delayed_rreq(const uip_ipaddr_t *searched_addr,
                 const uip_ipaddr_t *source_addr,
                 const uint16_t source_seqno,
                 const uint8_t metric_type,
                 const uint16_t metric_value)
{
  static struct ctimer delayed_rreq_timer = { 0 };
  static struct send_rreq_params_t params;
  if(ctimer_expired(&delayed_rreq_timer)) {
    uip_ipaddr_copy(&params.searched_addr, searched_addr);
    uip_ipaddr_copy(&params.source_addr, source_addr);
    params.source_seqno = source_seqno;
    params.metric_type = metric_type;
    params.metric_value = metric_value;
    ctimer_set(&delayed_rreq_timer, rand_wait_duration_before_broadcast(),
               (void (*)(void *)) &wrap_send_rreq, &params);
  } else {
    PRINTF("WARN: RREQ to ");
    PRINT6ADDR(searched_addr);
    PRINTF(" dropped: another one is pending\n");
  }
}
#endif /* LRP_IS_COORDINATOR */

/*---------------------------------------------------------------------------*/
/* Format and send a RREP type packet. */
#if !LRP_IS_SINK
void
lrp_send_rrep(const uip_ipaddr_t *dest_addr,
              const uip_ipaddr_t *nexthop,
              const uip_ipaddr_t *source_addr,
              const uint16_t source_seqno,
              const uint8_t metric_type,
              const uint16_t metric_value)
{
  struct lrp_msg_rrep_t rm;

  PRINTF("Send RREP -> ");
  PRINT6ADDR(nexthop);
  PRINTF(" source=");
  PRINT6ADDR(source_addr);
  PRINTF(" dest=");
  PRINT6ADDR(dest_addr);
  PRINTF(" seqno/metric/value=%u/0x%x/%u\n", source_seqno, metric_type, metric_value);

  rm.type = (LRP_RREP_TYPE << 4) | 0x0;
  rm.addr_len = (0x0 << 4) | LRP_ADDR_LEN_IPV6;
  rm.source_seqno = uip_htons(source_seqno);
  rm.metric_type = metric_type;
  rm.metric_value = metric_value;
  uip_ipaddr_copy(&rm.source_addr, source_addr);
  uip_ipaddr_copy(&rm.dest_addr, dest_addr);

  uip_ipaddr_copy(&lrp_udpconn->ripaddr, nexthop);
  uip_udp_packet_send(lrp_udpconn, &rm, sizeof(struct lrp_msg_rrep_t));
  memset(&lrp_udpconn->ripaddr, 0, sizeof(lrp_udpconn->ripaddr));
}
/* Wrapper to use `lrp_send_rrep` as a ctimer callback function */
static void
wrap_send_rrep(void *_)
{
  SEQNO_INCREASE(lrp_state.node_seqno);
  lrp_state_save();
  lrp_send_rrep(&lrp_state.sink_addr, uip_ds6_defrt_choose(), &lrp_myipaddr,
                lrp_state.node_seqno, LRP_METRIC_HOP_COUNT, 0);
}
/* Schedule a RREP message sending later. */
void
lrp_delayed_rrep()
{
  static struct ctimer delayed_rrep_timer = { 0 };
  if(ctimer_expired(&delayed_rrep_timer)) {
    ctimer_set(&delayed_rrep_timer, rand_wait_duration_before_broadcast(),
               &wrap_send_rrep, NULL);
  } else {
    PRINTF("WARN: RREP dropped: another one is pending\n");
  }
}
#endif /* !LRP_IS_SINK */

/*---------------------------------------------------------------------------*/
/* Format and send a RERR type to `nexthop`. */
#if !LRP_IS_SINK
void
lrp_send_rerr(const uip_ipaddr_t *dest_addr,
              const uip_ipaddr_t *addr_in_error,
              const uip_ipaddr_t *nexthop)
{
  struct lrp_msg_rerr_t rm;

  PRINTF("Send RERR -> ");
  PRINT6ADDR(nexthop);
  PRINTF(" address_in_error=");
  PRINT6ADDR(addr_in_error);
  PRINTF("\n");

  rm.type = (LRP_RERR_TYPE << 4) | 0x0;
  rm.addr_len = (0x0 << 4) | LRP_ADDR_LEN_IPV6;
  uip_ipaddr_copy(&rm.addr_in_error, addr_in_error);
  uip_ipaddr_copy(&rm.dest_addr, dest_addr);

  uip_ipaddr_copy(&lrp_udpconn->ripaddr, nexthop);
  uip_udp_packet_send(lrp_udpconn, &rm, sizeof(struct lrp_msg_rerr_t));
  memset(&lrp_udpconn->ripaddr, 0, sizeof(lrp_udpconn->ripaddr));
}
#endif /* !LRP_IS_SINK */

/*---------------------------------------------------------------------------*/
/* Format and send a DIO packet to `destination`, or broadcast if
 * `destination` is NULL */
#if LRP_IS_COORDINATOR
void
lrp_send_dio(uip_ipaddr_t *destination)
{
  struct lrp_msg_dio_t rm;

  PRINTF("Send DIO");
  if(destination == NULL || destination->u8[0] == 0xFF) {
    PRINTF(" (broadcast)");
  } else {
    PRINTF(" -> ");
    PRINT6ADDR(destination);
  }
  if(lrp_state.tree_seqno == 0) {
    PRINTF(" infinite\n");
  } else {
    PRINTF(" seqno/metric/value = %d/0x%x/%d\n",
           lrp_state.tree_seqno, lrp_state.metric_type, lrp_state.metric_value);
  }

  rm.type = (LRP_DIO_TYPE << 4) | 0x0;
  rm.addr_len = (0x0 << 4) | LRP_ADDR_LEN_IPV6;
  rm.tree_seqno = uip_htons(lrp_state.tree_seqno);
  rm.metric_type = lrp_state.metric_type;
  rm.metric_value = lrp_state.metric_value;
  uip_ipaddr_copy(&rm.sink_addr, &lrp_state.sink_addr);

  if(destination == NULL) {
    uip_create_linklocal_lln_routers_mcast(&lrp_udpconn->ripaddr);
  } else {
    uip_ipaddr_copy(&lrp_udpconn->ripaddr, destination);
  }
  uip_udp_packet_send(lrp_udpconn, &rm, sizeof(struct lrp_msg_dio_t));
  memset(&lrp_udpconn->ripaddr, 0, sizeof(lrp_udpconn->ripaddr));
}
/* Schedule a DIO message broadcasting later. Useful to avoid collisions */
void
lrp_delayed_dio(uip_ipaddr_t *destination)
{
  static struct ctimer delayed_dio_timer = { 0 };
  static uip_ipaddr_t params;
  if(ctimer_expired(&delayed_dio_timer)) {
    if(destination == NULL) {
      ctimer_set(&delayed_dio_timer, rand_wait_duration_before_broadcast(),
                 (void (*)(void *)) &lrp_send_dio, NULL);
    } else {
      uip_ipaddr_copy(&params, destination);
      ctimer_set(&delayed_dio_timer, rand_wait_duration_before_broadcast(),
                 (void (*)(void *)) &lrp_send_dio, &params);
    }
  } else {
    PRINTF("WARN: dropping DIO ");
    if(destination != NULL) {
      PRINTF("to ");
      PRINT6ADDR(destination);
    }
    PRINTF(": another one is pending\n");
  }
}
#endif /* LRP_IS_COORDINATOR */

/*---------------------------------------------------------------------------*/
/* Format and send a BRK type message. It will be send to the specified
 * nexthop, or broadcast it if `nexthop` is NULL */
#if LRP_IS_COORDINATOR && !LRP_IS_SINK
void
lrp_send_brk(const uip_ipaddr_t *initial_sender,
             const uip_ipaddr_t *nexthop,
             const uint16_t node_seqno,
             const uint8_t metric_type,
             const uint16_t metric_value,
             const uint8_t ring_size)
{
  struct lrp_msg_brk_t rm;

  PRINTF("Send BRK ");
  if(nexthop == NULL || nexthop->u8[0] == 0xFF) {
    PRINTF("(broadcast) ring=%d", ring_size);
  } else {
    PRINTF("-> ");
    PRINT6ADDR(nexthop);
  }
  PRINTF(" initial_sender=");
  PRINT6ADDR(initial_sender);
  PRINTF("\n");

  rm.type = LRP_BRK_TYPE;
  rm.type = (rm.type << 4) | 0x0;
  rm.addr_len = (0x0 << 4) | LRP_ADDR_LEN_IPV6;
  rm.node_seqno = uip_htons(node_seqno);
  rm.metric_type = metric_type;
  rm.metric_value = metric_value;
  rm.ring_size = ring_size;
  uip_ipaddr_copy(&rm.initial_sender, initial_sender);

  if(nexthop == NULL) {
    uip_create_linklocal_lln_routers_mcast(&lrp_udpconn->ripaddr);
  } else {
    uip_ipaddr_copy(&lrp_udpconn->ripaddr, nexthop);
  } uip_udp_packet_send(lrp_udpconn, &rm, sizeof(struct lrp_msg_brk_t));
  memset(&lrp_udpconn->ripaddr, 0, sizeof(lrp_udpconn->ripaddr));
}
struct send_brk_params_t {
  uip_ipaddr_t initial_sender;
  uip_ipaddr_t nexthop;
  uint16_t node_seqno;
  uint8_t metric_type;
  uint16_t metric_value;
  uint8_t ring_size;
};

static void
wrap_send_brk(struct send_brk_params_t *params)
{
  lrp_send_brk(&params->initial_sender, &params->nexthop, params->node_seqno,
               params->metric_type, params->metric_value, params->ring_size);
}
void
lrp_delayed_brk(const uip_ipaddr_t *initial_sender,
                const uip_ipaddr_t *nexthop,
                const uint16_t node_seqno,
                const uint8_t metric_type,
                const uint16_t metric_value,
                const uint8_t ring_size)
{
  static struct ctimer delayed_brk_timer = { 0 };
  static struct send_brk_params_t params;
  if(ctimer_expired(&delayed_brk_timer)) {
    uip_ipaddr_copy(&params.initial_sender, initial_sender);
    if(nexthop == NULL) {
      uip_create_linklocal_lln_routers_mcast(&params.nexthop);
    } else {
      uip_ipaddr_copy(&params.nexthop, nexthop);
    }
    params.node_seqno = node_seqno;
    params.metric_type = metric_type;
    params.metric_value = metric_value;
    params.ring_size = ring_size;
    ctimer_set(&delayed_brk_timer, rand_wait_duration_before_broadcast(),
               (void (*)(void *)) &wrap_send_brk, &params);
  } else {
    PRINTF("WARN: dropping BRK from ");
    PRINT6ADDR(initial_sender);
    PRINTF(": another one is pending\n");
  }
}
#endif /* LRP_IS_COORDINATOR && !LRP_IS_SINK */

/*---------------------------------------------------------------------------*/
/* Format and send a UPD type message. */
#if LRP_IS_COORDINATOR
void
lrp_send_upd(const uip_ipaddr_t *lost_node,
             const uip_ipaddr_t *sink_addr,
             const uip_ipaddr_t *nexthop,
             const uint16_t tree_seqno,
             const uint16_t repair_seqno,
             const uint8_t metric_type,
             const uint16_t metric_value)
{
  struct lrp_msg_upd_t rm;

  PRINTF("Send UPD -> ");
  PRINT6ADDR(nexthop);
  PRINTF(" lost_node=");
  PRINT6ADDR(lost_node);
  PRINTF("\n");

  rm.type = (LRP_UPD_TYPE << 4) | 0x0;
  rm.addr_len = (0x0 << 4) | LRP_ADDR_LEN_IPV6;
  rm.tree_seqno = uip_htons(tree_seqno);
  rm.repair_seqno = uip_htons(repair_seqno);
  rm.metric_type = metric_type;
  rm.metric_value = metric_value;
  uip_ipaddr_copy(&rm.sink_addr, sink_addr);
  uip_ipaddr_copy(&rm.lost_node, lost_node);

  uip_ipaddr_copy(&lrp_udpconn->ripaddr, nexthop);
  uip_udp_packet_send(lrp_udpconn, &rm, sizeof(struct lrp_msg_upd_t));
  memset(&lrp_udpconn->ripaddr, 0, sizeof(lrp_udpconn->ripaddr));
}
#endif /* LRP_IS_COORDINATOR */

/*---------------------------------------------------------------------------*/
/* Handle an incoming LRP message. */
void
lrp_handle_incoming_msg(void)
{
  uint8_t type = ((struct lrp_msg *)uip_appdata)->type >> 4;
  switch(type) {
  case LRP_RREQ_TYPE:
    lrp_handle_incoming_rreq();
    break;
  case LRP_RREP_TYPE:
    lrp_handle_incoming_rrep();
    break;
  case LRP_RERR_TYPE:
    lrp_handle_incoming_rerr();
    break;
  case LRP_DIO_TYPE:
    lrp_handle_incoming_dio();
    break;
  case LRP_BRK_TYPE:
    lrp_handle_incoming_brk();
    break;
  case LRP_UPD_TYPE:
    lrp_handle_incoming_upd();
    break;
  default:
    PRINTF("Unknown message type\n");
  }
}
#endif /* UIP_CONF_IPV6_LRP */
