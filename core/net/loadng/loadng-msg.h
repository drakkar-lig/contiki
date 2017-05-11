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

#ifndef __LOADNG_MSG_H__
#define __LOADNG_MSG_H__
#if UIP_CONF_IPV6_LOADNG

#include "net/loadng/loadng-def.h"
#include "net/ip/uip.h"

/*---------------------------------------------------------------------------*/
/* Generic LOADNG message */
struct loadng_msg {
  uint8_t type;
};
/*---------------------------------------------------------------------------*/
void loadng_handle_incoming_msg(void);
/*-------------------------------------------------------------------*/
/* LOADNG RREQ message */
#define LOADNG_RREQ_TYPE     0
struct loadng_msg_rreq_t {
  uint8_t type;
  uint8_t addr_len;
  uint16_t source_seqno;
  uint8_t _padding;
  uint8_t metric_type;
  uint16_t metric_value;
  uip_ipaddr_t searched_addr;
  uip_ipaddr_t source_addr;
};
void loadng_send_rreq(const uip_ipaddr_t *dest,
                      const uip_ipaddr_t *orig,
                      const uint16_t node_seqno,
                      const uint8_t metric_type,
                      const uint16_t metric_value);
void loadng_delayed_rreq(const uip_ipaddr_t *dest,
                         const uip_ipaddr_t *orig,
                         const uint16_t node_seqno,
                         const uint8_t metric_type,
                         const uint16_t metric_value);
/*-------------------------------------------------------------------*/
/* LOADNG RREP message */
#define LOADNG_RREP_TYPE     1
struct loadng_msg_rrep_t {
  uint8_t type;
  uint8_t addr_len;
  uint16_t source_seqno;
  uint8_t _padding;
  uint8_t metric_type;
  uint16_t metric_value;
  uip_ipaddr_t dest_addr;
  uip_ipaddr_t source_addr;
};
void loadng_send_rrep(const uip_ipaddr_t *dest,
                      const uip_ipaddr_t *nexthop,
                      const uip_ipaddr_t *source,
                      const uint16_t source_seqno,
                      const uint8_t metric_type,
                      const uint16_t metric_value);
void loadng_delayed_rrep(const uip_ipaddr_t *dest_addr,
                         const uip_ipaddr_t *nexthop,
                         const uip_ipaddr_t *source_addr,
                         uint16_t source_seqno,
                         uint8_t metric_type,
                         uint16_t metric_value);
/*-------------------------------------------------------------------*/
/* LOADNG RERR message */
#define LOADNG_RERR_TYPE     3
struct loadng_msg_rerr_t {
  uint8_t type;
  uint8_t addr_len;
  uip_ipaddr_t dest_addr;
  uip_ipaddr_t addr_in_error;
};
void loadng_send_rerr(const uip_ipaddr_t *dest_addr,
                      const uip_ipaddr_t *addr_in_error,
                      const uip_ipaddr_t *nexthop);
/*-------------------------------------------------------------------*/
#define LOADNG_MAX_MSG_SIZE sizeof(union{ \
  struct loadng_msg_rreq_t a; struct loadng_msg_rrep_t b; struct loadng_msg_rerr_t c;})

#endif /* UIP_CONF_IPV6_LOADNG */
#endif /* __LOADNG_MSG_H__ */
