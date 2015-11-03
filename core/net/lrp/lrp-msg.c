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

#if WITH_IPV6_LRP

#define DEBUG DEBUG_PRINT

#include "net/lrp/lrp.h"
#include "net/lrp/lrp-def.h"
#include "net/lrp/lrp-global.h"
#include "net/lrp/lrp-ct.h"
#include "net/lrp/lrp-routes.h"
#include "net/lrp/lrp-msg.h"
#include "net/uip-debug.h"
#include <string.h>


/*---------------------------------------------------------------------------*/
/* Format and broadcast a RREQ type packet. */
#if LRP_IS_COORDINATOR
void
lrp_send_rreq(
    const uip_ipaddr_t *searched_addr,
    const uip_ipaddr_t *source_addr,
    const uint16_t source_seqno,
    const uint8_t metric_type,
    const uint16_t metric_value)
{
  struct lrp_msg_rreq rm;

  PRINTF("Send RREQ (broadcast) for ");
  PRINT6ADDR(searched_addr);
  PRINTF(" metric t/v=%x/%u\n", metric_type, metric_value);

  // Fill message
  rm.type = (LRP_RREQ_TYPE << 4) | 0x0;
  rm.addr_len = (0x0 << 4) | LRP_ADDR_LEN_IPV6;
  rm.source_seqno = uip_htons(source_seqno);
  rm.metric_type = metric_type;
  rm.metric_value = metric_value;
  uip_ipaddr_copy(&rm.searched_addr, searched_addr);
  uip_ipaddr_copy(&rm.source_addr, source_addr);

  // Send packet
  uip_create_linklocal_lln_routers_mcast(&lrp_udpconn->ripaddr);
  uip_udp_packet_send(lrp_udpconn, &rm, sizeof(struct lrp_msg_rreq));
  memset(&lrp_udpconn->ripaddr, 0, sizeof(lrp_udpconn->ripaddr));
}
#endif /* LRP_IS_COORDINATOR */


/*---------------------------------------------------------------------------*/
/* Format and send a RREP type packet. */
#if !LRP_IS_SINK
void
lrp_send_rrep(
    const uip_ipaddr_t *dest_addr,
    const uip_ipaddr_t *nexthop,
    const uip_ipaddr_t *source_addr,
    const uint16_t source_seqno,
    const uint8_t metric_type,
    const uint16_t metric_value)
{
  struct lrp_msg_rrep rm;

  PRINTF("Send RREP -> ");
  PRINT6ADDR(nexthop);
  PRINTF(" source=");
  PRINT6ADDR(source_addr);
  PRINTF(" dest=");
  PRINT6ADDR(dest_addr);
  PRINTF(" source_seqno=%u", source_seqno);
  PRINTF(" metric type/value=%x/%u\n", metric_type, metric_value);

  rm.type = (LRP_RREP_TYPE << 4) | 0x0;
  rm.addr_len = (0x0 << 4) | LRP_ADDR_LEN_IPV6;
  rm.source_seqno = uip_htons(source_seqno);
  rm.metric_type = metric_type;
  rm.metric_value = metric_value;
  uip_ipaddr_copy(&rm.source_addr, source_addr);
  uip_ipaddr_copy(&rm.dest_addr, dest_addr);

  uip_ipaddr_copy(&lrp_udpconn->ripaddr, nexthop);
  uip_udp_packet_send(lrp_udpconn, &rm, sizeof(struct lrp_msg_rrep));
  memset(&lrp_udpconn->ripaddr, 0, sizeof(lrp_udpconn->ripaddr));
}

/* Wrapper to use `lrp_send_rrep` as a ctimer callback function */
static void
call_send_rrep(void* nothing)
{
  SEQNO_INCREASE(lrp_state.node_seqno);
  lrp_state_save();
  lrp_send_rrep(&lrp_state.sink_addr, uip_ds6_defrt_choose(), &lrp_myipaddr, lrp_state.node_seqno, LRP_METRIC_HOP_COUNT, 0);
}

/* Schedule a RREP message sending later. */
void
lrp_delayed_rrep()
{
  static struct ctimer delayed_rrep_timer = {0};
  if (!ctimer_expired(&delayed_rrep_timer)) return;
  ctimer_set(&delayed_rrep_timer, rand_wait_duration_before_broadcast(1000),
      (void (*)(void*))&call_send_rrep, NULL);
}
#endif /* !LRP_IS_SINK */


/*---------------------------------------------------------------------------*/
/* Format and send a RERR type to `nexthop`. */
#if !LRP_IS_SINK
void
lrp_send_rerr(
    const uip_ipaddr_t *dest_addr,
    const uip_ipaddr_t *addr_in_error,
    const uip_ipaddr_t *nexthop)
{
  struct lrp_msg_rerr rm;

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
  uip_udp_packet_send(lrp_udpconn, &rm, sizeof(struct lrp_msg_rerr));
  memset(&lrp_udpconn->ripaddr, 0, sizeof(lrp_udpconn->ripaddr));
}
#endif /* !LRP_IS_SINK */


/*---------------------------------------------------------------------------*/
/* Format and send a DIO type packet. */
/* Format and send a DIO packet to `destination`, or broadcast if
 * `destination` is NULL */
#if LRP_IS_COORDINATOR
void
lrp_send_dio(uip_ipaddr_t* destination)
{
  struct lrp_msg_dio rm;

#if !LRP_IS_SINK
  if(uip_ds6_defrt_choose() == NULL) {
    PRINTF("Do not send DIO: no default route\n");
    return;
  }
#endif /* !LRP_IS_SINK */

  PRINTF("Send DIO");
  if(destination == NULL) {
    PRINTF(" (broadcast)\n");
  } else {
    PRINTF(" -> ");
    PRINT6ADDR(destination);
    PRINTF("\n");
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
  uip_udp_packet_send(lrp_udpconn, &rm, sizeof(struct lrp_msg_dio));
  memset(&lrp_udpconn->ripaddr, 0, sizeof(lrp_udpconn->ripaddr));
}

/* Schedule a DIO message broadcasting later. Useful to avoid collisions */
void
lrp_delayed_dio()
{
  static struct ctimer delayed_dio_timer = {0};
  if (!ctimer_expired(&delayed_dio_timer)) return;
  ctimer_set(&delayed_dio_timer, rand_wait_duration_before_broadcast(1000),
      (void (*)(void*))&lrp_send_dio, NULL);
}
#endif /* LRP_IS_COORDINATOR */


/*---------------------------------------------------------------------------*/
/* Format and broadcast a DIS type packet. */
#if !LRP_IS_SINK
void
lrp_send_dis()
{
  struct lrp_msg_dis rm;

  PRINTF("Send DIS (broadcast)\n");

  rm.type = LRP_DIS_TYPE;
  rm.type = (rm.type << 4) | 0x0;
  rm.addr_len = (0x0 << 4) | LRP_ADDR_LEN_IPV6;

  uip_create_linklocal_lln_routers_mcast(&lrp_udpconn->ripaddr);
  uip_udp_packet_send(lrp_udpconn, &rm, sizeof(struct lrp_msg_dis));
  memset(&lrp_udpconn->ripaddr, 0, sizeof(lrp_udpconn->ripaddr));
}
#endif /* !LRP_IS_SINK */


/*---------------------------------------------------------------------------*/
/* Format and send a BRK type message. It will be send to the specified
 * nexthop, or broadcast it if `nexthop` is NULL */
#if LRP_IS_COORDINATOR && !LRP_IS_SINK
void
lrp_send_brk(
    const uip_ipaddr_t *lost_node,
    const uip_ipaddr_t *nexthop,
    const uint16_t node_seqno,
    const uint8_t metric_type,
    const uint16_t metric_value)
{
  struct lrp_msg_brk rm;

  PRINTF("Send BRK ");
  if(nexthop == NULL) {
    PRINTF("(broadcast)");
  } else {
    PRINTF("-> ");
    PRINT6ADDR(nexthop);
  }
  PRINTF(" lost_node=");
  PRINT6ADDR(lost_node);
  PRINTF("\n");

  rm.type = LRP_BRK_TYPE;
  rm.type = (rm.type << 4) | 0x0;
  rm.addr_len = (0x0 << 4) | LRP_ADDR_LEN_IPV6;
  rm.node_seqno = uip_htons(node_seqno);
  rm.metric_type = metric_type;
  rm.metric_value = metric_value;
  uip_ipaddr_copy(&rm.lost_node, lost_node);

  if(nexthop == NULL) {
    uip_create_linklocal_lln_routers_mcast(&lrp_udpconn->ripaddr);
  } else {
    uip_ipaddr_copy(&lrp_udpconn->ripaddr, nexthop);
  }
  uip_udp_packet_send(lrp_udpconn, &rm, sizeof(struct lrp_msg_brk));
  memset(&lrp_udpconn->ripaddr, 0, sizeof(lrp_udpconn->ripaddr));
}
#endif /* LRP_IS_COORDINATOR && !LRP_IS_SINK */


/*---------------------------------------------------------------------------*/
/* Format and send a UPD type message. */
#if LRP_IS_COORDINATOR
void
lrp_send_upd(
    const uip_ipaddr_t *lost_node,
    const uip_ipaddr_t *sink_addr,
    const uip_ipaddr_t *nexthop,
    const uint16_t tree_seqno,
    const uint16_t repair_seqno,
    const uint8_t metric_type,
    const uint16_t metric_value)
{
  struct lrp_msg_upd rm;

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
  uip_udp_packet_send(lrp_udpconn, &rm, sizeof(struct lrp_msg_upd));
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
    case LRP_DIS_TYPE:
      lrp_handle_incoming_dis();
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

#endif /* WITH_IPV6_LRP */
