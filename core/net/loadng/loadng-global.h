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
 *         Global definitions for LOADNG internal use
 * \author Chi-Anh La <la@imag.fr>
 * \author Martin Heusse <martin.heusse@imag.fr>
 * \author Audéoud Henry-Joseph <henry-joseph.audeoud@imag.fr>
 */

#ifndef __LOADNG_GLOBAL_H__
#define __LOADNG_GLOBAL_H__
#if UIP_CONF_IPV6_LOADNG

#include "contiki-net.h"
#include "net/loadng/loadng-def.h"
#include "net/loadng/loadng-msg.h"

/*---------------------------------------------------------------------------*/
/* Global variables */
struct uip_udp_conn *loadng_udpconn;

/*---------------------------------------------------------------------------*/
/* IP adresses managment */
#define uip_create_linklocal_lln_routers_mcast(a) \
  uip_ip6addr(a, 0xff02, 0, 0, 0, 0, 0, 0, 0x001b)
#define uip_create_linklocal_empty_addr(a) \
  uip_ip6addr(a, 0, 0, 0, 0, 0, 0, 0, 0)
uint8_t loadng_ipaddr_is_empty(uip_ipaddr_t *addr);

uip_ipaddr_t loadng_myipaddr;

/*---------------------------------------------------------------------------*/
/* Seqno managment */
#define MAX_SEQNO               65534
typedef uint16_t seqno_t;
#define SEQNO_GREATER_THAN(s1, s2) \
  (((s1) != 0) && \
   (((s2) == 0) || \
    (((s1) > (s2)) && ((s1) - (s2) <= (MAX_SEQNO / 2))) || \
    (((s2) > (s1)) && ((s2) - (s1) > (MAX_SEQNO / 2)))))
#define SEQNO_INCREASE(seqno) ((seqno) >= MAX_SEQNO ? (seqno) = 1 : ++(seqno))
#define SEQNO_INCREASE(seqno) ((seqno) >= MAX_SEQNO ? (seqno) = 1 : ++(seqno))

/*---------------------------------------------------------------------------*/
/* Node state managment */
#define STATE_SVFILE            "loadng/state"
struct {
  seqno_t node_seqno;     /* Sequence number of this node */
} loadng_state;

struct {
  uint8_t len;
  uip_ipaddr_t prefix;
} loadng_local_prefix;

void loadng_state_new(void);
#if LOADNG_USE_CFS
void loadng_state_save(void);
void loadng_state_restore(void);
#else /* LOADNG_USE_CFS */
/* Deactivate saving on the non-volatile memory */
#define loadng_state_save()
#define loadng_state_restore() loadng_state_new()
#endif /* LOADNG_USE_CFS */

uint8_t loadng_ipaddr_is_empty(uip_ipaddr_t *);
uint16_t loadng_link_cost(uip_ipaddr_t *link, uint8_t metric_type);
uint8_t loadng_is_my_global_address(uip_ipaddr_t *);
uint8_t loadng_addr_match_local_prefix(uip_ipaddr_t *);
void loadng_nbr_add(uip_ipaddr_t *next_hop);
uint32_t rand_wait_duration_before_broadcast();

enum path_length_comparison_result_t {
  PLC_NEWER_SEQNO,
  PLC_SHORTER_METRIC,
  PLC_EQUAL,
  PLC_LONGER_METRIC,
  PLC_OLDER_SEQNO,
  /** PLC_UNCOMPARABLE_METRICS is used when seqno are equal but metric types are
   * differents. In this situation, the two paths lengths are uncomparable */
  PLC_UNCOMPARABLE_METRICS
};
/** Compare two path lengths.
 *
 * @return one of the PLC_* constants, to indicate if the first is inferior,
 * superior or equal to the second path description.
 */
enum path_length_comparison_result_t path_length_compare(
    uint16_t seqno_1, uint8_t metric_type_1, uint16_t metric_value_1,
    uint16_t seqno_2, uint8_t metric_type_2, uint16_t metric_value_2);
#endif /* UIP_CONF_IPV6_LOADNG */
#endif /* __LOADNG_GLOBAL_H__ */
