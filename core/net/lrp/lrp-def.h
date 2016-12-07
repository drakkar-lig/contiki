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
 *         Definitions for the LRP ad hoc routing protocol
 * \author Chi-Anh La <la@imag.fr>
 * \author Martin Heusse <martin.heusse@imag.fr>
 * \author Audéoud Henry-Joseph <henry-joseph.audeoud@imag.fr>
 */

#ifndef __LRP_DEF_H__
#define __LRP_DEF_H__
#if UIP_CONF_IPV6_LRP

/* UDP port used for routing control messages */
#define LRP_UDPPORT            6666

/* Typical time for a packet to cross the whole network in one way (ticks) */
#define LRP_NET_TRAVERSAL_TIME 10 * CLOCK_SECOND

/* Frequency of DIO broadcasting (ticks) */
#define LRP_SEND_DIO_INTERVAL  ((uint32_t)(480 * CLOCK_SECOND))

/* Maximum time between two global repairs (ticks, on 32 bits). 0 to perform
 * no automatic global repair */
#define LRP_MAX_DODAG_LIFETIME 0

/* Number of times a DIO has to be sent, when starting a LR, before sending
 * BRK. 0 to not send any DIO, and start with BRK */
#define LRP_LR_SEND_DIO_NB     2

/* Exponential parameter for DIO sending. @see retransmit_dio_brk */
#define LRP_LR_EXP_PARAM      0.90

/* Maximal ring size for LR. At start, BRK will be sent with a ring_size of 0.
 * Then, this field will be incremented each retransmission, until it reaches
 * this value. With this value, the BRK message is flooded in the whole
 * subtree, whatever its size. */
#define LRP_LR_RING_INFINITE_SIZE 3

/* Re-send RREQ n times if no RREP recieved. 0 implies don't retry at all */
#define LRP_RREQ_RETRIES       0

/* Minimum interval between two RREQ transmissions (ticks). 0 to deactivate */
#define LRP_RREQ_MININTERVAL   0

/* RREQ retransmission interval (ticks) */
#define LRP_RETRY_RREQ_INTERVAL 5 * CLOCK_SECOND / 1000

/* Ack routes replies */
#define LRP_RREP_ACK           0 /* TODO Manage RREP acks */

/* Default route lifetime (ticks) */
#define LRP_DEFRT_LIFETIME     0

/* Route retention interval (ticks). 0 to never timeout a host route */
#define LRP_ROUTE_HOLD_TIME    0

/* Route validity check interval (ticks) */
#define LRP_ROUTE_VALIDITY_CHECK_INTERVAL 10 * CLOCK_SECOND

/* Threshold below which a link is considered as weak */
#define LRP_RSSI_THRESHOLD    -65 /* Ana measured value */

/* Wait randomly this given time (in ticks) before sending a message, when
 * flooding the network */
#define LRP_RANDOM_WAIT        10 * CLOCK_SECOND

/* If NUD is deactivated, unacked messages are counted, and next hop is deleted
 * when the number of consecutive noacked messages reach this constant. */
#define LRP_MAX_CONSECUTIVE_NOACKED_MESSAGES  3

/* Use contiki filesystem to save state, or do not save state. */
#define LRP_USE_CFS            0

/* The frequency at which the current node host route will be updated if no
 * RREP_ACK has been received. Set it to 0 to deactivate this mechanism. */
#define UPDATE_HOST_ROUTE_DELAY 60 * CLOCK_SECOND

#define LRP_ADDR_LEN_IPV6      15

/* Is a sink node */
#ifndef LRP_IS_SINK
#define LRP_IS_SINK            1
#endif

/* Is a coordinator node */
#ifndef LRP_IS_COORDINATOR
#define LRP_IS_COORDINATOR     1
#endif

#if LRP_IS_SINK && !LRP_IS_COORDINATOR
#error The node is sink but not coordinator, which is particularly \
  problematic (and stupid). Please check again your settings.
#endif

#define LRP_NBR_UNREACHABLE_DURATION  10 * 60 * CLOCK_SECOND

/* Define metric types */
#define LRP_METRIC_HOP_COUNT 0x01
/* Special placeholder metric. Is not comparable. Should always be used with
 * a seqno of 0, in infinite-rank DIOs. */
#define LRP_METRIC_NONE 0x00

#endif /* UIP_CONF_IPV6_LRP */
#endif /* __LRP_DEF_H__ */
