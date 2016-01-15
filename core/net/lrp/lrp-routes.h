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
 *         Routes management
 * \author Chi-Anh La <la@imag.fr>
 * \author Martin Heusse <martin.heusse@imag.fr>
 * \author Audéoud Henry-Joseph <henry-joseph.audeoud@imag.fr>
 */

#ifndef __LRP_ROUTES_H__
#define __LRP_ROUTES_H__
#if UIP_CONF_IPV6_LRP

void lrp_handle_incoming_rreq(void);
void lrp_handle_incoming_rrep(void);
void lrp_handle_incoming_rerr(void);

#if LRP_RREQ_RETRIES && (LRP_IS_SINK || !LRP_USE_DIO)
void rrc_check_expired_rreq(void);
#endif /* LRP_RREQ_RETRIES && (LRP_IS_SINK || !LRP_USE_DIO) */

#if LRP_ROUTE_HOLD_TIME
void lrp_check_expired_route(void);
#endif /* LRP_ROUTE_HOLD_TIME */

#if LRP_IS_COORDINATOR && !LRP_IS_SINK
void lrp_routing_error(uip_ipaddr_t *source, uip_ipaddr_t *destination,
                       uip_lladdr_t *previoushop);
#endif /* LRP_IS_COORDINATOR && !LRP_IS_SINK */

void lrp_request_route_to(uip_ipaddr_t *host);

#endif /* UIP_CONF_IPV6_LRP */
#endif /* __LRP_ROUTES_H__ */
