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
 *         Definitions for the LOADNG ad hoc routing protocol
 * \author Chi-Anh La <la@imag.fr>
 * \author Martin Heusse <martin.heusse@imag.fr>
 * \author Audéoud Henry-Joseph <henry-joseph.audeoud@imag.fr>
 */

#ifndef __LOADNG_DEF_H__
#define __LOADNG_DEF_H__
#if UIP_CONF_IPV6_LOADNG

/* UDP port used for routing control messages */
#define LOADNG_UDPPORT            6666

/* Typical time for a packet to cross the whole network in one way (ticks) */
#define LOADNG_NET_TRAVERSAL_TIME 10 * CLOCK_SECOND

/* Re-send RREQ n times if no RREP recieved. 0 implies don't retry at all */
#define LOADNG_RREQ_RETRIES       0

/* Minimum interval between two RREQ transmissions (ticks). 0 to deactivate */
#define LOADNG_RREQ_MININTERVAL   0

/* RREQ retransmission interval (ticks) */
#define LOADNG_RETRY_RREQ_INTERVAL 5 * CLOCK_SECOND / 1000

/* Default route lifetime (ticks) */
#define LOADNG_DEFRT_LIFETIME     0

/* Route retention interval (ticks). 0 to never timeout a host route */
#define LOADNG_ROUTE_HOLD_TIME    0

/* Route validity check interval (ticks) */
#define LOADNG_ROUTE_VALIDITY_CHECK_INTERVAL 10 * CLOCK_SECOND

/* Threshold below which a link is considered as weak */
#define LOADNG_RSSI_THRESHOLD    -65 /* Ana measured value */

/* Wait randomly this given time (in ticks) before sending a message, when
 * flooding the network */
#define LOADNG_RANDOM_WAIT        500 * CLOCK_SECOND / 1000

/* If NUD is deactivated, unacked messages are counted, and next hop is deleted
 * when the number of consecutive noacked messages reach this constant. */
#define LOADNG_MAX_CONSECUTIVE_NOACKED_MESSAGES  3

/* Maximum number of delayed RREP messages stored */
#define LOADNG_DELAYED_RREP_BUFFER_SIZE 3

/* Use contiki filesystem to save state, or do not save state. */
#define LOADNG_USE_CFS            0

#define LOADNG_ADDR_LEN_IPV6      15

/* Define metric types */
#define LOADNG_METRIC_HOP_COUNT 0x01
/* Special placeholder metric. Is not comparable. */
#define LOADNG_METRIC_NONE 0x00

#endif /* UIP_CONF_IPV6_LOADNG */
#endif /* __LOADNG_DEF_H__ */
