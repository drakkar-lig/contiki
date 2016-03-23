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
 *         Global definitions for LRP internal use
 * \author Chi-Anh La <la@imag.fr>
 * \author Martin Heusse <martin.heusse@imag.fr>
 * \author Audéoud Henry-Joseph <henry-joseph.audeoud@imag.fr>
 */

#ifndef __LRP_GLOBAL_H__
#define __LRP_GLOBAL_H__
#if UIP_CONF_IPV6_LRP

#include "contiki-net.h"
#include "net/lrp/lrp-def.h"
#include "net/lrp/lrp-msg.h"

/*---------------------------------------------------------------------------*/
/* Global variables */
struct uip_udp_conn *lrp_udpconn;

/*---------------------------------------------------------------------------*/
/* IP adresses managment */
#define uip_create_linklocal_lln_routers_mcast(a) \
  uip_ip6addr(a, 0xff02, 0, 0, 0, 0, 0, 0, 0x001b)
#define uip_create_linklocal_empty_addr(a) \
  uip_ip6addr(a, 0, 0, 0, 0, 0, 0, 0, 0)
uint8_t lrp_ipaddr_is_empty(uip_ipaddr_t *addr);

uip_ipaddr_t lrp_myipaddr;

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
#define STATE_SVFILE            "lrp/state"
struct {
  uip_ipaddr_t sink_addr; /* Address of the sink we are connected to */
  seqno_t tree_seqno;     /* Sequence number of the tree */
  seqno_t repair_seqno;   /* Repair sequence number */
  seqno_t node_seqno;     /* Sequence number of this node */
  uint16_t metric_value;  /* Distance from this node to the sink */
  uint8_t metric_type;    /* Type of metric used for this network */
} lrp_state;
/* Temporary state. Never exported on the network. It is used to handle soft
 * handover: the connection to the new successor is checked before it is
 * really selected as successor. */
struct {
  uip_ipaddr_t unconfirmed_successor; /* IP address of unconfirmed successor */
  uip_ipaddr_t sink_addr; /* Address of the sink we are connected to */
  seqno_t tree_seqno;     /* Sequence number of the tree */
  seqno_t repair_seqno;   /* Repair sequence number */
  uint16_t metric_value;  /* Distance from this node to the sink */
  uint8_t metric_type;    /* Type of metric used for this network */
  uint8_t msg_type;       /* Type of the message that we'll try to accept */
  uip_ipaddr_t upd_destination; /* Destination of the UPD message. Available only if msg_type is LRP_UPD_TYPE */
} lrp_tmp_state;

struct {
  uint8_t len;
  uip_ipaddr_t prefix;
} lrp_local_prefix;

void lrp_state_new(void);
#if LRP_USE_CFS
void lrp_state_save(void);
void lrp_state_restore(void);
#else /* LRP_USE_CFS */
/* Deactivate saving on the non-volatile memory */
#define lrp_state_save()
#define lrp_state_restore() lrp_state_new()
#endif /* LRP_USE_CFS */

#if !LRP_IS_SINK && LRP_IS_COORDINATOR
void lrp_store_tmp_state(uip_ipaddr_t* unconfirmed_successor, struct lrp_msg* msg);
void lrp_confirm_tmp_state();
#endif /* !LRP_IS_SINK && LRP_IS_COORDINATOR */

uint8_t lrp_ipaddr_is_empty(uip_ipaddr_t *);
uint16_t lrp_link_cost(uip_ipaddr_t *link, uint8_t metric_type);
uint8_t lrp_is_my_global_address(uip_ipaddr_t *);
uint8_t lrp_addr_match_local_prefix(uip_ipaddr_t *);
void lrp_nbr_add(uip_ipaddr_t *next_hop);
uint32_t rand_wait_duration_before_broadcast();
#endif /* UIP_CONF_IPV6_LRP */
#endif /* __LRP_GLOBAL_H__ */
