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
 *         Collection Tree maintenance algorithm.
 * \author Chi-Anh La <la@imag.fr>
 * \author Martin Heusse <martin.heusse@imag.fr>
 * \author Audéoud Henry-Joseph <henry-joseph.audeoud@imag.fr>
 */

#ifndef __LRP_CT_H__
#define __LRP_CT_H__
#if UIP_CONF_IPV6_LRP

#include "net/lrp/lrp-msg.h"

/* Look for an entry into the cache */
uip_ipaddr_t * lrp_brc_lookup(const uip_ipaddr_t *brk_sender);

/* Handle incoming tree maintenance messages */
void lrp_handle_incoming_dio(uip_ipaddr_t* neighbor, struct lrp_msg_dio_t* dio);
void lrp_handle_incoming_brk(uip_ipaddr_t* neighbor, struct lrp_msg_brk_t* brk);
void lrp_handle_incoming_upd(uip_ipaddr_t* neighbor, struct lrp_msg_upd_t* upd);

/* Inform maintenance algorithm that successor is unreachable. */
#if !LRP_IS_SINK
void lrp_no_more_default_route(void);
#endif /* !LRP_IS_SINK */

/* Rebuild the tree with a new sequence number */
#if LRP_IS_SINK
void global_repair(void);
#endif /* LRP_IS_SINK */

#endif /* UIP_CONF_IPV6_LRP */
#endif /* __LRP_CT_H__ */
