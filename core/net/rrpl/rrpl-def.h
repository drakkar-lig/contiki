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
 *
 * $Id: rrpl-def.h,v 1.5 2010/05/28 16:33:19 bg- Exp $
 */

/**
 * \file
 *         Definitions for the RRPL ad hoc routing protocol
 * \author 
 *         Chi-Anh La la@imag.fr         
 */

#ifndef __RRPL_DEF_H__
#define __RRPL_DEF_H__


#include "net/uip.h"
#define uip_create_linklocal_lln_routers_mcast(a) uip_ip6addr(a, 0xff02, 0, 0, 0, 0, 0, 0, 0x001b)
#define uip_create_linklocal_empty_addr(a) uip_ip6addr(a, 0, 0, 0, 0, 0, 0, 0, 0)
#define RRPL_UDPPORT            6666
#define RRPL_NET_TRAVERSAL_TIME 10
#define RRPL_RREQ_RETRIES       0
#define RRPL_RREQ_RATELIMIT     0
#define RRPL_R_HOLD_TIME        0
#define RRPL_MAX_DIST           20
#define RRPL_RREP_ACK_TIMEOUT   10
#define RRPL_BLACKLIST_TIME     10
#define RRPL_RSSI_THRESHOLD    -65 // Ana measured value

#ifdef RRPL_CONF_SND_QRY
#define SND_QRY RRPL_CONF_SND_QRY
#else
#define SND_QRY 0
#endif

/* Self multicast OPT to create a default route at all nodes (for sink only) */

#ifdef RRPL_CONF_IS_SINK
#define RRPL_IS_SINK RRPL_CONF_IS_SINK
#else
#define RRPL_IS_SINK 1
#endif

#ifdef RRPL_CONF_IS_COORDINATOR
#define RRPL_IS_COORDINATOR() RRPL_CONF_IS_COORDINATOR()
#else
#define RRPL_IS_COORDINATOR() 0
#endif

#ifdef RRPL_CONF_IS_SKIP_LEAF
#define RRPL_IS_SKIP_LEAF RRPL_CONF_IS_SKIP_LEAF
#else
#define RRPL_IS_SKIP_LEAF 0
#endif

#define RRPL_RREP_ACK           0 
#define RRPL_ADDR_LEN_IPV6      15
#define RRPL_METRIC_HC          0 
#define RRPL_WEAK_LINK          0
#define RRPL_RSVD1              0
#define RRPL_RSVD2              0 
#define RRPL_DEFAULT_ROUTE_LIFETIME  65534

#ifdef RRPL_CONF_RANDOM_WAIT
#define RRPL_RANDOM_WAIT RRPL_CONF_RANDOM_WAIT
#else
#define RRPL_RANDOM_WAIT 1
#endif

#define RRPL_ADDR_LEN_IPV6     15
#define RRPL_RSVD1 0
#define RRPL_RSVD2 0 


/* Generic RRPL message */
struct rrpl_msg {
	uint8_t type;
};


/* RRPL RREQ message */
#define RRPL_RREQ_TYPE     0

struct rrpl_msg_rreq {
	uint8_t type;
	uint8_t addr_len;
	uint16_t seqno;
	uint8_t metric;
	uint8_t route_cost;
	uip_ipaddr_t dest_addr;
	uip_ipaddr_t orig_addr;
};

/* RRPL RREP message */
#define RRPL_RREP_TYPE     1

struct rrpl_msg_rrep {
	uint8_t type;
	uint8_t addr_len;
	uint16_t seqno;
	uint8_t metric;
	uint8_t route_cost;
	uip_ipaddr_t dest_addr;
	uip_ipaddr_t orig_addr;
};

/* RRPL RREP-ACK message */
#define RRPL_RACK_TYPE     2

struct rrpl_msg_rack {
	uint8_t type;
	uint8_t addr_len;
	uip_ipaddr_t src_addr;
	uint16_t seqno;

};

/* RRPL RERR message */
#define RRPL_RERR_TYPE     3

struct rrpl_msg_rerr {
	uint8_t type;
	uint8_t addr_len;
	uip_ipaddr_t src_addr;
	uip_ipaddr_t addr_in_error;

};


/* RRPL OPT message */
#define RRPL_OPT_TYPE      4

struct rrpl_msg_opt {
	uint8_t type;
	uint8_t addr_len;
	uint16_t seqno;
	int8_t rank;
        uint8_t metric;
	uip_ipaddr_t sink_addr;
};

/* RRPL QRY message */
#define RRPL_QRY_TYPE      5

struct rrpl_msg_qry {
	uint8_t type;
	uint8_t addr_len;
};

/* LRL UPD message */
#define RRPL_UPD_TYPE     6

struct rrpl_msg_upd {
	uint8_t type;
	uint8_t addr_len;
	uip_ipaddr_t sink_id;
	uint8_t seq_id;
	uint8_t time_order;
	int8_t rank;
	uint8_t reflect;
	uip_ipaddr_t oid_addr;
};

/* LRL CLR message */
#define RRPL_CLR_TYPE     7

struct rrpl_msg_clr {
	uint8_t type;
	uint8_t addr_len;
	uip_ipaddr_t sink_id;
	uint8_t seq_id;
	uint8_t time_order;
	uip_ipaddr_t oid_addr;
};

#endif /* __RRPL_DEF_H__ */

