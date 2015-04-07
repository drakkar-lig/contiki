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
 * $Id: lrp.h,v 1.3 2010/12/13 10:04:59 bg- Exp $
 */

/**
 * \file
 *         LRP routing header.
 * \author
 *         Chi-Anh La la@imag.fr
 */

#ifndef __LRP_H__
#define __LRP_H__

#include "contiki.h"
#ifdef UIP_DS6_ROUTE_STATE_TYPE
#undef UIP_DS6_ROUTE_STATE_TYPE
#endif

// This is used in uip-ds6-route included further down
#define UIP_DS6_ROUTE_STATE_TYPE lrp_route_entry_t
typedef struct lrp_route_entry {
  uint16_t seqno;
  uint8_t route_cost;
  uint32_t valid_time;
  uint8_t ack_received;
} lrp_route_entry_t;

#include "net/ipv6/uip-ds6.h"


void
lrp_set_local_prefix(uip_ipaddr_t *prefix, uint8_t len);

/**
 * \brief   Select and return the nexthop to which send packet.
 * \return  The nexthop to use, or NULL if the packet have to be discarded
 */
uip_ipaddr_t*
lrp_select_nexthop_for(uip_ipaddr_t* source, uip_ipaddr_t* destination,
    uip_lladdr_t* previoushop);

PROCESS_NAME(lrp_process);

#endif /* __LRP_H__ */
