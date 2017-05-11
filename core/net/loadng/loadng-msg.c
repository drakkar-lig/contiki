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

#if UIP_CONF_IPV6_LOADNG

#define DEBUG DEBUG_PRINT

#include "net/loadng/loadng.h"
#include "net/loadng/loadng-def.h"
#include "net/loadng/loadng-global.h"
#include "net/loadng/loadng-routes.h"
#include "net/loadng/loadng-msg.h"
#include "net/ip/uip-debug.h"
#include <string.h>

#define UIP_IP_BUF ((struct uip_udpip_hdr *)&uip_buf[UIP_LLH_LEN])

/*---------------------------------------------------------------------------*/
/* Format and broadcast a RREQ type packet. */
void
loadng_send_rreq(const uip_ipaddr_t *searched_addr,
              const uip_ipaddr_t *source_addr,
              const uint16_t source_seqno,
              const uint8_t metric_type,
              const uint16_t metric_value)
{
  struct loadng_msg_rreq_t rreq;

  PRINTF("Send RREQ (broadcast) for ");
  PRINT6ADDR(searched_addr);
  PRINTF(" seqno/metric/value=%u/0x%x/%u\n", source_seqno, metric_type, metric_value);

  /* Fill message */
  rreq.type = (LOADNG_RREQ_TYPE << 4) | 0x0;
  rreq.addr_len = (0x0 << 4) | LOADNG_ADDR_LEN_IPV6;
  rreq.source_seqno = uip_htons(source_seqno);
  rreq.metric_type = metric_type;
  rreq.metric_value = uip_htons(metric_value);
  uip_ipaddr_copy(&rreq.searched_addr, searched_addr);
  uip_ipaddr_copy(&rreq.source_addr, source_addr);

  /* Send packet */
  uip_create_linklocal_lln_routers_mcast(&loadng_udpconn->ripaddr);
  uip_udp_packet_send(loadng_udpconn, &rreq, sizeof(struct loadng_msg_rreq_t));
  memset(&loadng_udpconn->ripaddr, 0, sizeof(loadng_udpconn->ripaddr));
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
  loadng_send_rreq(&params->searched_addr, &params->source_addr,
                params->source_seqno, params->metric_type,
                params->metric_value);
}
void
loadng_delayed_rreq(const uip_ipaddr_t *searched_addr,
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
    PRINTF("RREQ to ");
    PRINT6ADDR(searched_addr);
    PRINTF(" dropped: another one is pending\n");
  }
}

/*---------------------------------------------------------------------------*/
/* Format and send a RREP type packet. */
void
loadng_send_rrep(const uip_ipaddr_t *dest_addr,
              const uip_ipaddr_t *nexthop,
              const uip_ipaddr_t *source_addr,
              const uint16_t source_seqno,
              const uint8_t metric_type,
              const uint16_t metric_value)
{
  struct loadng_msg_rrep_t rrep;

  PRINTF("Send RREP -> ");
  PRINT6ADDR(nexthop);
  PRINTF(" source=");
  PRINT6ADDR(source_addr);
  PRINTF(" dest=");
  PRINT6ADDR(dest_addr);
  PRINTF(" seqno/metric/value=%u/0x%x/%u\n", source_seqno, metric_type, metric_value);

  rrep.type = (LOADNG_RREP_TYPE << 4) | 0x0;
  rrep.addr_len = (0x0 << 4) | LOADNG_ADDR_LEN_IPV6;
  rrep.source_seqno = uip_htons(source_seqno);
  rrep.metric_type = metric_type;
  rrep.metric_value = uip_htons(metric_value);
  uip_ipaddr_copy(&rrep.source_addr, source_addr);
  uip_ipaddr_copy(&rrep.dest_addr, dest_addr);

  uip_udp_packet_sendto(loadng_udpconn,
                        &rrep, sizeof(struct loadng_msg_rrep_t),
                        nexthop, loadng_udpconn->rport);
}
struct send_rrep_params_t {
  uip_ipaddr_t dest_addr;
  uip_ipaddr_t nexthop;
  uip_ipaddr_t source_addr;
  uint16_t source_seqno;
  uint8_t metric_type;
  uint16_t metric_value;
};
/* Wrapper to use `loadng_send_rrep` as a ctimer callback function */
static void
wrap_send_rrep(struct send_rrep_params_t *args)
{
  SEQNO_INCREASE(loadng_state.node_seqno);
  loadng_state_save();
  loadng_send_rrep(&args->dest_addr, &args->nexthop, &args->source_addr,
                args->source_seqno, args->metric_type, args->metric_value);
}
/* Schedule a RREP message sending later. */
void
loadng_delayed_rrep(const uip_ipaddr_t *dest_addr,
                 const uip_ipaddr_t *nexthop,
                 const uip_ipaddr_t *source_addr,
                 uint16_t source_seqno,
                 uint8_t metric_type,
                 uint16_t metric_value)
{
  static struct {
    struct ctimer timer;
    struct send_rrep_params_t args;
  } delayed_rrep_buffer[LOADNG_DELAYED_RREP_BUFFER_SIZE];
  int position;

  /* Find an available space into buffer */
  for (position = 0; position < LOADNG_DELAYED_RREP_BUFFER_SIZE; position++) {
    if(ctimer_expired(&delayed_rrep_buffer[position].timer)) break;
  }

  if(position != LOADNG_DELAYED_RREP_BUFFER_SIZE) {
    /* Fill loadng_send_rrep parameters */
    uip_ipaddr_copy(&delayed_rrep_buffer[position].args.dest_addr, dest_addr);
    uip_ipaddr_copy(&delayed_rrep_buffer[position].args.nexthop, nexthop);
    uip_ipaddr_copy(&delayed_rrep_buffer[position].args.source_addr, source_addr);
    delayed_rrep_buffer[position].args.source_seqno = source_seqno;
    delayed_rrep_buffer[position].args.metric_type = metric_type;
    delayed_rrep_buffer[position].args.metric_value = metric_value;
    /* Configure timer */
    ctimer_set(&delayed_rrep_buffer[position].timer, rand_wait_duration_before_broadcast(),
               (void (*)(void *))&wrap_send_rrep, &delayed_rrep_buffer[position].args);
  } else {
    PRINTF("RREP from ");
    PRINT6ADDR(source_addr);
    PRINTF(" dropped: buffer is full\n");
  }
}

/*---------------------------------------------------------------------------*/
/* Format and send a RERR type to `nexthop`. */
void
loadng_send_rerr(const uip_ipaddr_t *dest_addr,
              const uip_ipaddr_t *addr_in_error,
              const uip_ipaddr_t *nexthop)
{
  struct loadng_msg_rerr_t rerr;

  PRINTF("Send RERR -> ");
  PRINT6ADDR(nexthop);
  PRINTF(" address_in_error=");
  PRINT6ADDR(addr_in_error);
  PRINTF("\n");

  rerr.type = (LOADNG_RERR_TYPE << 4) | 0x0;
  rerr.addr_len = (0x0 << 4) | LOADNG_ADDR_LEN_IPV6;
  uip_ipaddr_copy(&rerr.addr_in_error, addr_in_error);
  uip_ipaddr_copy(&rerr.dest_addr, dest_addr);

  uip_udp_packet_sendto(loadng_udpconn,
                        &rerr, sizeof(struct loadng_msg_rerr_t),
                        nexthop, loadng_udpconn->rport);
}

/*---------------------------------------------------------------------------*/
/* Handle an incoming LOADNG message. */
void
loadng_handle_incoming_msg(void)
{
  /* Record neighbor */
  loadng_nbr_add(&((struct uip_udpip_hdr *)&uip_buf[UIP_LLH_LEN])->srcipaddr);
  /* Compute message type */
  uint8_t type = ((struct loadng_msg *)uip_appdata)->type >> 4;
  /* Check message type */
  switch(type) {
  case LOADNG_RREQ_TYPE:
    PRINTF("Received RREQ ");
    PRINT6ADDR(&UIP_IP_BUF->srcipaddr);
    PRINTF(" -> ");
    PRINT6ADDR(&UIP_IP_BUF->destipaddr);
    struct loadng_msg_rreq_t *rreq = (struct loadng_msg_rreq_t *)uip_appdata;
    rreq->source_seqno = uip_ntohs(rreq->source_seqno);
    rreq->metric_value = uip_ntohs(rreq->metric_value);
    PRINTF(" orig=");
    PRINT6ADDR(&rreq->source_addr);
    PRINTF(" searched=");
    PRINT6ADDR(&rreq->searched_addr);
    PRINTF("\n");
    loadng_handle_incoming_rreq(&UIP_IP_BUF->srcipaddr, rreq);
    break;
  case LOADNG_RREP_TYPE:
    PRINTF("Received RREP ");
    PRINT6ADDR(&UIP_IP_BUF->srcipaddr);
    PRINTF(" -> ");
    PRINT6ADDR(&UIP_IP_BUF->destipaddr);
    struct loadng_msg_rrep_t *rrep = (struct loadng_msg_rrep_t *)uip_appdata;
    rrep->source_seqno = uip_ntohs(rrep->source_seqno);
    rrep->metric_value = uip_ntohs(rrep->metric_value);
    PRINTF(" source=");
    PRINT6ADDR(&rrep->source_addr);
    PRINTF(" seqno/metric/value=%u/0x%x/%u",
        uip_ntohs(rrep->source_seqno), rrep->metric_type, rrep->metric_value);
    PRINTF(" dest=");
    PRINT6ADDR(&rrep->dest_addr);
    PRINTF("\n");
    loadng_handle_incoming_rrep(&UIP_IP_BUF->srcipaddr, rrep);
    break;
  case LOADNG_RERR_TYPE:
    PRINTF("Recieved RERR ");
    PRINT6ADDR(&UIP_IP_BUF->srcipaddr);
    PRINTF(" -> ");
    PRINT6ADDR(&UIP_IP_BUF->destipaddr);
    struct loadng_msg_rerr_t *rerr = (struct loadng_msg_rerr_t *)uip_appdata;
    PRINTF(" addr_in_error=");
    PRINT6ADDR(&rerr->addr_in_error);
    PRINTF(" dest=");
    PRINT6ADDR(&rerr->dest_addr);
    PRINTF("\n");
    loadng_handle_incoming_rerr(&UIP_IP_BUF->srcipaddr, rerr);
    break;
  default:
    PRINTF("Unknown message type 0x%x\n", type);
  }
}
#endif /* UIP_CONF_IPV6_LOADNG */
