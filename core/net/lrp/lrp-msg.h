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
 *         Messages managment
 * \author Chi-Anh La <la@imag.fr>
 * \author Martin Heusse <martin.heusse@imag.fr>
 * \author Audéoud Henry-Joseph <henry-joseph.audeoud@imag.fr>
 */

#ifndef __LRP_MSG_H__
#define __LRP_MSG_H__
#if UIP_CONF_IPV6_LRP

#include "net/lrp/lrp-def.h"
#include "net/ip/uip.h"

/*---------------------------------------------------------------------------*/
/* Generic LRP message */
struct lrp_msg {
  uint8_t type;
};

/*---------------------------------------------------------------------------*/
void lrp_handle_incoming_msg(void);

/*-------------------------------------------------------------------*/
/* LRP RREQ message */
#define LRP_RREQ_TYPE     0
struct lrp_msg_rreq_t {
  uint8_t type;
  uint8_t addr_len;
  uip_ipaddr_t searched_addr;
  uip_ipaddr_t source_addr;
  uint16_t source_seqno;
  uint8_t metric_type;
  uint16_t metric_value;
};
#if LRP_IS_COORDINATOR
void lrp_send_rreq(const uip_ipaddr_t *dest,
                   const uip_ipaddr_t *orig,
                   const uint16_t node_seqno,
                   const uint8_t metric_type,
                   const uint16_t metric_value);
void lrp_delayed_rreq(const uip_ipaddr_t *dest,
                      const uip_ipaddr_t *orig,
                      const uint16_t node_seqno,
                      const uint8_t metric_type,
                      const uint16_t metric_value);
#endif /* LRP_IS_COORDINATOR */

/*-------------------------------------------------------------------*/
/* LRP RREP message */
#define LRP_RREP_TYPE     1
struct lrp_msg_rrep_t {
  uint8_t type;
  uint8_t addr_len;
  uip_ipaddr_t dest_addr;
  uip_ipaddr_t source_addr;
  uint16_t source_seqno;
  uint8_t metric_type;
  uint16_t metric_value;
};
#if !LRP_IS_SINK
void lrp_send_rrep(const uip_ipaddr_t *dest,
                   const uip_ipaddr_t *nexthop,
                   const uip_ipaddr_t *source,
                   const uint16_t source_seqno,
                   const uint8_t metric_type,
                   const uint16_t metric_value);
void lrp_delayed_rrep();
#endif /* !LRP_IS_SINK */

/*-------------------------------------------------------------------*/
/* LRP RREP-ACK message */
#define LRP_RACK_TYPE     2
#if LRP_RREP_ACK
struct lrp_msg_rack_t {
  uint8_t type;
  uint8_t addr_len;
  uip_ipaddr_t src_addr;
  uint16_t node_seqno;
};
#endif /* LRP_RREP_ACK */

/*-------------------------------------------------------------------*/
/* LRP RERR message */
#define LRP_RERR_TYPE     3
struct lrp_msg_rerr_t {
  uint8_t type;
  uint8_t addr_len;
  uip_ipaddr_t dest_addr;
  uip_ipaddr_t addr_in_error;
};
#if !LRP_IS_SINK
void lrp_send_rerr(const uip_ipaddr_t *dest_addr,
                   const uip_ipaddr_t *addr_in_error,
                   const uip_ipaddr_t *nexthop);
#endif /* !LRP_IS_SINK */

/*---------------------------------------------------------------------------*/
/* Messages non available on LoadNG */
#if LRP_USE_DIO

/*-------------------------------------------------------------------*/
/* LRP DIO message */
#define LRP_DIO_TYPE      4
struct lrp_msg_dio_t {
  uint8_t type;
  uint8_t addr_len;
  uint16_t tree_seqno;
  uint8_t metric_type;
  uint16_t metric_value;
  uip_ipaddr_t sink_addr;
};
#if LRP_IS_COORDINATOR
void lrp_send_dio(uip_ipaddr_t *destination);
void lrp_delayed_dio(uip_ipaddr_t *destination);
#endif /* LRP_IS_COORDINATOR */

/*-------------------------------------------------------------------*/
/* LRP BRK message */
#define LRP_BRK_TYPE      6
struct lrp_msg_brk_t {
  uint8_t type;
  uint8_t addr_len;
  uint16_t node_seqno;
  uint8_t metric_type;
  uint16_t metric_value;
  uint8_t ring_size;
  uip_ipaddr_t initial_sender;
};
#if LRP_IS_COORDINATOR && !LRP_IS_SINK
void lrp_send_brk(const uip_ipaddr_t *initial_sender,
                  const uip_ipaddr_t *nexthop,
                  const uint16_t node_seqno,
                  const uint8_t metric_type,
                  const uint16_t metric_value,
                  const uint8_t ring_size);
void lrp_delayed_brk(const uip_ipaddr_t *initial_sender,
                     const uip_ipaddr_t *nexthop,
                     const uint16_t node_seqno,
                     const uint8_t metric_type,
                     const uint16_t metric_value,
                     const uint8_t ring_size);
#endif /* LRP_IS_COORDINATOR && !LRP_IS_SINK */

/*-------------------------------------------------------------------*/
/* LRP UPD message */
#define LRP_UPD_TYPE      7
struct lrp_msg_upd_t {
  uint8_t type;
  uint8_t addr_len;
  uint16_t tree_seqno;
  uint16_t repair_seqno;
  uint8_t metric_type;
  uint16_t metric_value;
  uip_ipaddr_t sink_addr;
  uip_ipaddr_t lost_node;
};
#if LRP_IS_COORDINATOR
void lrp_send_upd(const uip_ipaddr_t *lost_node,
                  const uip_ipaddr_t *sink_addr,
                  const uip_ipaddr_t *nexthop,
                  const uint16_t tree_seqno,
                  const uint16_t repair_seqno,
                  const uint8_t metric_type,
                  const uint16_t metric_value);
#endif /* LRP_IS_COORDINATOR */

#endif /* LRP_USE_DIO */

#endif /* UIP_CONF_IPV6_LRP */
#endif /* __LRP_MSG_H__ */
