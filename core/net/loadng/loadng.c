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
 *         LOADng routing protocol implementation.
 *         The implementation is derived from the implementation of LRP.
 * \author Chi-Anh La <la@imag.fr>
 * \author Martin Heusse <martin.heusse@imag.fr>
 * \author Audéoud Henry-Joseph <henry-joseph.audeoud@imag.fr>
 */

#if UIP_CONF_IPV6_LOADNG

#include "net/loadng/loadng.h"
#include "net/loadng/loadng-def.h"
#include "net/loadng/loadng-routes.h"
#include "net/loadng/loadng-global.h"
#include "net/loadng/loadng-msg.h"
#include "net/linkaddr.h"
#include "contiki.h"
#include "contiki-lib.h"
#include "contiki-net.h"

#include <string.h>

#define DEBUG DEBUG_PRINT
#include "net/ip/uip-debug.h"

#define MAX_PAYLOAD_LEN         50
#define LOADNG_ADDR_LEN_IPV6    15
#define DEFAULT_LOCAL_PREFIX    64
#define UIP_IP_BUF ((struct uip_udpip_hdr *)&uip_buf[UIP_LLH_LEN])

#define LAST_RSSI ((int8_t)cc2420_last_rssi)
/* extern int8_t last_rssi; // for stm32w */
extern signed char cc2420_last_rssi;
static uip_ipaddr_t mcastipaddr;

/** Store informations about a neighbor */
typedef struct {
  uint8_t  link_cost_type;
  uint16_t link_cost_value;
  uint8_t  nb_consecutive_noack_msg;
  enum {
    UNKNOWN = 0,  // Initialization value
    REACHABLE,
    UNREACHABLE
  } reachability;
} loadng_neighbor_t;
/** List of all known neighbors and description to reach them */
NBR_TABLE_GLOBAL(loadng_neighbor_t, loadng_neighbors);

/*---------------------------------------------------------------------------*/
PROCESS(loadng_process, "LOADng process");

/*---------------------------------------------------------------------------*/
static void
get_prefix_from_addr(uip_ipaddr_t *addr, uip_ipaddr_t *prefix, uint8_t len)
{
  uint8_t i;
  loadng_local_prefix.len = len;
  for(i = 0; i < 16; i++) {
    if(i < len / 8) {
      prefix->u8[i] = addr->u8[i];
    } else {
      prefix->u8[i] = 0;
    }
  }
}
/*---------------------------------------------------------------------------*/
static int
get_global_addr(uip_ipaddr_t *addr)
{
  int i;
  int state;

  for(i = 0; i < UIP_DS6_ADDR_NB; i++) {
    state = uip_ds6_if.addr_list[i].state;
    if(uip_ds6_if.addr_list[i].isused &&
       (state == ADDR_TENTATIVE || state == ADDR_PREFERRED)) {
      if(!uip_is_addr_linklocal(&uip_ds6_if.addr_list[i].ipaddr)) {
        memcpy(addr, &uip_ds6_if.addr_list[i].ipaddr, sizeof(uip_ipaddr_t));
        return 1;
      }
    }
  }
  return 0;
}
/*---------------------------------------------------------------------------*/
void
loadng_set_local_prefix(uip_ipaddr_t *prefix, uint8_t len)
{
  uip_ipaddr_copy(&loadng_local_prefix.prefix, prefix);
  loadng_local_prefix.len = len;
}
/*---------------------------------------------------------------------------*/
/* Layer II callback. Used to discover neighbors unreachability */
void
loadng_neighbor_callback(const linkaddr_t *addr, int status, int mutx)
{
#if !UIP_ND6_SEND_NA
  uip_ipaddr_t *nbr_ipaddr = uip_ds6_nbr_ipaddr_from_lladdr((uip_lladdr_t *) addr);
  loadng_neighbor_t *nbr =
      (loadng_neighbor_t *) nbr_table_get_from_lladdr(loadng_neighbors, addr);

  if(nbr == NULL) {
    PRINTF("Add neighbor ");
    PRINTLLADDR((uip_lladdr_t *) addr);
    PRINTF(" in neighbor list\n");
    nbr = nbr_table_add_lladdr(loadng_neighbors, addr, NBR_TABLE_REASON_MAC, NULL);
  }

#if DEBUG & DEBUG_PRINT != 0
  const static char* mac_status_names[] = {"OK", "COLLISION", "NOACK", "DEFERRED", "ERR", "ERR_FATAL"};
  PRINTF("LL: %s from ", mac_status_names[status]);
  PRINTLLADDR((uip_lladdr_t *)addr);
  PRINTF("\n");
#endif

  if(status == MAC_TX_NOACK) {
    /* Message is not received by neighbor. Count unacked messages */
    nbr->nb_consecutive_noack_msg += 1;
    PRINTF("Noack counter is %d/%d\n",
           nbr->nb_consecutive_noack_msg, LOADNG_MAX_CONSECUTIVE_NOACKED_MESSAGES);

    if(nbr->nb_consecutive_noack_msg >= LOADNG_MAX_CONSECUTIVE_NOACKED_MESSAGES) {
      /* Neighbor seems to be unreachable */
      PRINTF("Delete routes through it\n");
      uip_ds6_route_rm_by_nexthop(nbr_ipaddr);
      nbr->reachability = UNREACHABLE;
    }

  } else if(status == MAC_TX_OK) {
    /* Resetting counter */
    if(nbr->nb_consecutive_noack_msg != 0) {
      /* The neighbor has not received our last message, but has received this
       * one. It is now reachable */
      PRINTF("Reset noack counter\n");
      nbr->nb_consecutive_noack_msg = 0;
    }
    nbr->reachability = REACHABLE;
  }
#endif /* !UIP_ND6_SEND_NA */
}
/*---------------------------------------------------------------------------*/
uip_ipaddr_t *
loadng_select_nexthop_for(uip_ipaddr_t *source, uip_ipaddr_t *destination,
                       uip_lladdr_t *previoushop)
{
  uip_ds6_route_t *route_to_dest;
  uip_ipaddr_t *nexthop;

  route_to_dest = uip_ds6_route_lookup(destination);
  nexthop = uip_ds6_route_nexthop(route_to_dest);

  if(nexthop == NULL) {
    /* No host route. Drop packet. */
    nexthop = NULL;
    if (route_to_dest != NULL) {
      uip_ds6_route_rm(route_to_dest);
    }

    if(loadng_is_my_global_address(source)) {
      /* Send RREQ */
      PRINTF("Discarding packet: unknown destination\n");
      /* Change the context to ensure that timers set in this code wake up the
       * LOADNG process, and not the routing process */
      PROCESS_CONTEXT_BEGIN(&loadng_process);
      loadng_request_route_to(destination);
      PROCESS_CONTEXT_END();
    } else {
      /* Send RERR */
      PRINTF("Discarding packet: broken host route\n");
      /* Change the context to ensure that timers set in this code wake up the
       * LOADNG process, and not the routing process */
      PROCESS_CONTEXT_BEGIN(&loadng_process);
      loadng_routing_error(source, destination, previoushop);
      PROCESS_CONTEXT_END();
    }
  } else {
    /* Use provided host route */
    PRINTF("Routing data packet through ");
    PRINT6ADDR(nexthop);
    PRINTF("\n");
  }
  return nexthop;
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(loadng_process, ev, data)
{
  PROCESS_BEGIN();
  PROCESS_PAUSE();
  PRINTF("LOADng process started\n");

  get_global_addr(&loadng_myipaddr);
  get_prefix_from_addr(&loadng_myipaddr,
                       &loadng_local_prefix.prefix, DEFAULT_LOCAL_PREFIX);
  uip_create_linklocal_lln_routers_mcast(&mcastipaddr);
  uip_ds6_maddr_add(&mcastipaddr);

  loadng_state_restore();
  loadng_udpconn = udp_new(NULL, UIP_HTONS(LOADNG_UDPPORT), NULL);
  udp_bind(loadng_udpconn, UIP_HTONS(LOADNG_UDPPORT));
  loadng_udpconn->ttl = 1;
  PRINTF("Created the LOADng UDP socket");
  PRINTF(" (local/remote port %u/%u)\n",
         UIP_HTONS(loadng_udpconn->lport), UIP_HTONS(loadng_udpconn->rport));

#if !UIP_ND6_SEND_NA
  // TODO: add callback to remove routes through this host when deleted
  nbr_table_register(loadng_neighbors, NULL);
#endif /* !UIP_ND6_SEND_NA */

#if LOADNG_ROUTE_HOLD_TIME
  /* Activate route expiration checker */
  loadng_check_expired_route();
#endif /* LOADNG_ROUTE_HOLD_TIME */

#if LOADNG_RREQ_RETRIES
  /* Activate RREQ retransmission */
  rrc_check_expired_rreq();
#endif /* LOADNG_RREQ_RETRIES */

  while(1) {
    PROCESS_YIELD();

    if(ev == tcpip_event) {
      if(uip_newdata()) {
        loadng_handle_incoming_msg();
      }
    }
  }
  PROCESS_END();
}

#endif /* UIP_CONF_IPV6_LOADNG */
/*---------------------------------------------------------------------------*/
