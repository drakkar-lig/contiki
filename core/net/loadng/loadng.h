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
 *         LOADNG routing header.
 * \author Chi-Anh La <la@imag.fr>
 * \author Martin Heusse <martin.heusse@imag.fr>
 * \author Audéoud Henry-Joseph <henry-joseph.audeoud@imag.fr>
 */

#ifndef __LOADNG_H__
#define __LOADNG_H__
#if UIP_CONF_IPV6_LOADNG

#include "contiki.h"
#include "net/nbr-table.h"

#ifdef UIP_DS6_ROUTE_STATE_TYPE
#undef UIP_DS6_ROUTE_STATE_TYPE
#endif

/* This is used in uip-ds6-route included further down */
#define UIP_DS6_ROUTE_STATE_TYPE loadng_route_entry_t
typedef struct loadng_route_entry {
  uint16_t seqno;
  uint8_t metric_type;
  uint16_t metric_value;
  uint32_t valid_time;
  uint8_t ack_received;
} loadng_route_entry_t;

NBR_TABLE_DECLARE(loadng_neighbors);

#include "net/ipv6/uip-ds6.h"
#include "net/ipv6/uip-ds6-route.h"
#include "net/linkaddr.h"

/**
 * \brief  Set the local prefix of the network the node is into.
 */
void loadng_set_local_prefix(uip_ipaddr_t *prefix, uint8_t len);

/**
 * \brief   Select and return the nexthop to which send the packet described
 *          by parameters.
 * \return  The nexthop to use, or NULL if the packet has to be discarded
 */
uip_ipaddr_t *loadng_select_nexthop_for(uip_ipaddr_t *source,
                                     uip_ipaddr_t *destination,
                                     uip_lladdr_t *previoushop);

void loadng_neighbor_callback(const linkaddr_t *addr, int status, int mutx);

/**
 * LOADNG process
 */
PROCESS_NAME(loadng_process);

#endif /* UIP_CONF_IPV6_LOADNG */
#endif /* __LOADNG_H__ */
