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
 * $Id: lrp-def.h,v 1.5 2010/05/28 16:33:19 bg- Exp $
 */

/**
 * \file
 *         Definitions for the LRP ad hoc routing protocol
 * \author
 *         Chi-Anh La la@imag.fr
 */

#ifndef __LRP_DEF_H__
#define __LRP_DEF_H__

#include "net/ip/uip.h"

/* UDP port used for routing control messages */
#define LRP_UDPPORT            6666

/* Typical time for a packet to cross the whole network in one way (ticks) */
#define LRP_NET_TRAVERSAL_TIME 10 * CLOCK_SECOND

/* Frequency of DIO broadcasting (ticks) */
#define SEND_DIO_INTERVAL      480 * CLOCK_SECOND

/* Maximum time between two global repairs (ticks, on 32 bits) */
#define MAX_DODAG_LIFETIME     1800 * CLOCK_SECOND

/* Number of times a QRY has to be sent. After these, if we were associated
 * with a default. 0 to disable QRY sending */
#define SEND_QRY               3

/* Exponential parameter for QRY sending. @see retransmit_qry_brk */
#define QRY_EXP_PARAM          0.90

/* Re-send RREQ n times if no RREP recieved. 0 implies don't retry at all */
#define LRP_RREQ_RETRIES       0

/* Minimum interval between two RREQ transmissions (ticks). 0 to deactivate */
#define LRP_RREQ_MININTERVAL   0

/* RREQ retransmission interval (ticks) */
#define RETRY_RREQ_INTERVAL    5 * CLOCK_SECOND / 1000

/* Spontaneously send a RREP message, when selecting a new successor. RREP will
 * be sent to the new sucessor, not to the sink. */
#define LRP_SEND_SPONTANEOUS_RREP 1

/* Ack routes replies */
#define LRP_RREP_ACK           0

/* Default route lifetime (ticks) */
#define LRP_DEFRT_LIFETIME     0

/* Route retention interval (ticks). 0 for infinite interval */
#define LRP_R_HOLD_TIME        0

/* Route validity check interval (ticks) */
#define RV_CHECK_INTERVAL      10 * CLOCK_SECOND

/* Threshold below which a link is considered as weak */
#define LRP_RSSI_THRESHOLD    -65 // Ana measured value

/* Maximum node's rank */
#define LRP_MAX_RANK           127

/* Maximum distance for a non hop-to-hop routing packet. */
#define LRP_MAX_DIST           20

/* Wait randomly when flooding the network */
#define LRP_RANDOM_WAIT        1

/* If NUD is deactivated, unacked messages are counted, and next hop is deleted
 * when the number of consecutive noacked messages reach this constant. */
#define LRP_MAX_CONSECUTIVE_NOACKED_MESSAGES  9

/* Is a sink node */
#ifdef LRP_CONF_IS_SINK
#define LRP_IS_SINK            LRP_CONF_IS_SINK
#else
#define LRP_IS_SINK            1
#endif

/* Is a coordinator node */
#ifdef LRP_CONF_IS_COORDINATOR
#define LRP_IS_COORDINATOR     LRP_CONF_IS_COORDINATOR
#else
#define LRP_IS_COORDINATOR     1
#endif

/* Use DIO, or keep a LOADng's standard comportment */
#ifdef LRP_CONF_USE_DIO
#define USE_DIO                LRP_CONF_USE_DIO
#else
#define USE_DIO                1
#endif

/* Save seqno into flash, to be able to restore it if node reboots. */
#if !LRP_IS_COORDINATOR
// Non-coordinator nodes does not need SAVE_STATE at all
#define SAVE_STATE             0
#else
#define SAVE_STATE             0
#endif

#if LRP_IS_SINK && !LRP_IS_COORDINATOR
#error The node is sink but not coordinator, which is particularly \
  problematic (and stupid). Please check again your settings.
#endif


/* Generic LRP message */
struct lrp_msg {
  uint8_t type;
};

/* LRP RREQ message */
#define LRP_RREQ_TYPE     0

struct lrp_msg_rreq {
  uint8_t type;
  uint8_t addr_len;
  uint16_t node_seqno;
  uint8_t metric;
  uint8_t route_cost;
  uip_ipaddr_t dest_addr;
  uip_ipaddr_t orig_addr;
};

/* LRP RREP message */
#define LRP_RREP_TYPE     1

struct lrp_msg_rrep {
  uint8_t type;
  uint8_t addr_len;
  uint16_t node_seqno;
  uint8_t metric;
  uint8_t route_cost;
  uip_ipaddr_t dest_addr;
  uip_ipaddr_t orig_addr;
};

/* LRP RREP-ACK message */
#define LRP_RACK_TYPE     2

#if LRP_RREP_ACK
struct lrp_msg_rack {
  uint8_t type;
  uint8_t addr_len;
  uip_ipaddr_t src_addr;
  uint16_t node_seqno;
};
#endif /* LRP_RREP_ACK */

/* LRP RERR message */
#define LRP_RERR_TYPE     3

struct lrp_msg_rerr {
  uint8_t type;
  uint8_t addr_len;
  uip_ipaddr_t src_addr;
  uip_ipaddr_t addr_in_error;
};

/* LRP DIO message */
#define LRP_DIO_TYPE      4

#if USE_DIO
struct lrp_msg_dio {
  uint8_t type;
  uint8_t addr_len;
  uint16_t tree_seqno;
  uint8_t rank;
  uint8_t metric;
  uip_ipaddr_t sink_addr;
};
#endif /* USE_DIO */

/* LRP QRY message */
#define LRP_QRY_TYPE      5

#if USE_DIO
struct lrp_msg_qry {
  uint8_t type;
  uint8_t addr_len;
};
#endif /* USE_DIO */

/* LRP BRK message */
#define LRP_BRK_TYPE      6

struct lrp_msg_brk {
  uint8_t type;
  uint8_t addr_len;
  uint16_t node_seqno;
  uint8_t rank;
  uip_ipaddr_t lost_node;
};

/* LRP UPD message */
#define LRP_UPD_TYPE      7

struct lrp_msg_upd {
  uint8_t type;
  uint8_t addr_len;
  uint16_t tree_seqno;
  uint16_t repair_seqno;
  uint8_t rank;
  uint8_t metric;
  uip_ipaddr_t sink_addr;
  uip_ipaddr_t lost_node;
};

#endif /* __LRP_DEF_H__ */
