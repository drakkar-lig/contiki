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
 *         The Lightweight Routing Protocol
 *         This protocol is evolved from
 *         the LOADng routing protocol
 *         IETF draft draft-clausen-lln-loadng-00.txt
 *         Version for slotted 802.15.4
 * \author Chi-Anh La <la@imag.fr>
 * \author Martin Heusse <martin.heusse@imag.fr>
 * \author Audéoud Henry-Joseph <henry-joseph.audeoud@imag.fr>
 */

#if UIP_CONF_IPV6_LRP

#include "net/lrp/lrp.h"
#include "net/lrp/lrp-def.h"
#include "net/lrp/lrp-ct.h"
#include "net/lrp/lrp-routes.h"
#include "net/lrp/lrp-global.h"
#include "net/lrp/lrp-msg.h"
#include "contiki.h"
#include "contiki-lib.h"
#include "contiki-net.h"

#include <string.h>

#define DEBUG DEBUG_PRINT
#include "net/ip/uip-debug.h"

#define MAX_PAYLOAD_LEN         50
#define LRP_ADDR_LEN_IPV6       15
#define DEFAULT_LOCAL_PREFIX    64
#define UIP_IP_BUF ((struct uip_udpip_hdr *)&uip_buf[UIP_LLH_LEN])


#define LAST_RSSI ((int8_t) cc2420_last_rssi)
// extern int8_t last_rssi; // for stm32w
extern signed char cc2420_last_rssi;
static uip_ipaddr_t mcastipaddr;

#if !UIP_ND6_SEND_NA
typedef struct {
  uint8_t nb_consecutive_noack_msg;
} lrp_next_hop_t;
NBR_TABLE(lrp_next_hop_t, lrp_next_hops);
#endif /* !UIP_ND6_SEND_NA */

/*---------------------------------------------------------------------------*/
PROCESS(lrp_process, "LRP process");

/*---------------------------------------------------------------------------*/
static void
get_prefix_from_addr(uip_ipaddr_t *addr, uip_ipaddr_t *prefix, uint8_t len)
{
  uint8_t i;
  lrp_local_prefix.len = len;
  for(i = 0; i < 16; i++) {
    if(i < len/8)
    {
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
      if(!uip_is_addr_link_local(&uip_ds6_if.addr_list[i].ipaddr)) {
        memcpy(addr, &uip_ds6_if.addr_list[i].ipaddr, sizeof(uip_ipaddr_t));
        return 1;
      }
    }
  }
  return 0;
}

/*---------------------------------------------------------------------------*/
/* Return true if `addr` is a predecessor, that is, is used as next hop into
 * the routing table */
#if !LRP_IS_SINK && LRP_IS_COORDINATOR
static uint8_t
lrp_is_predecessor(uip_ipaddr_t *addr)
{
  uip_ds6_route_t* r;

  if(addr == NULL) {
    // Unknown neighor, not a predecessor
    return (0==1);
  }

  for(r = uip_ds6_route_head(); r != NULL; r = uip_ds6_route_next(r)) {
    if(memcmp(uip_ds6_route_nexthop(r), addr, sizeof(uip_ipaddr_t)) == 0) {
      // Found as route's next hop => is a predecessor
      return (1==1);
    }
  }
  return (0==1);
}
#endif /* !LRP_IS_SINK && LRP_IS_COORDINATOR */


/*---------------------------------------------------------------------------*/
/* Link-layer callback. Used to discover neighbors unreachability */
#if 0
#if !UIP_ND6_SEND_NA
void
lrp_link_next_hop_callback(const rimeaddr_t *addr, int status, int mutx)
{
  uip_ds6_defrt_t *locdefrt;
  lrp_next_hop_t* nh = (lrp_next_hop_t*) nbr_table_get_from_lladdr(lrp_next_hops, addr);
  uip_ds6_nbr_t* nb = uip_ds6_nbr_ll_lookup((uip_lladdr_t*) addr);

  if(nb == NULL) return; // Unknown neighbor

  if(nh == NULL) {
    nh = nbr_table_add_lladdr(lrp_next_hops, addr);
    nh->nb_consecutive_noack_msg = 0;
  }

  if(status == MAC_TX_NOACK) {
    // Count unacked messages
    nh->nb_consecutive_noack_msg += 1;
    PRINTF("No ack received from next hop ");
    PRINTLLADDR((uip_lladdr_t*)addr);
    PRINTF(" (counter is %d/%d)\n",
        nh->nb_consecutive_noack_msg, LRP_MAX_CONSECUTIVE_NOACKED_MESSAGES);

    // Conditionally remove entry
    if(nh->nb_consecutive_noack_msg >= LRP_MAX_CONSECUTIVE_NOACKED_MESSAGES) {
      PRINTF("Deleting next hop ");
      PRINT6ADDR(uip_ds6_nbr_get_ipaddr(nb));
      printf(" unreachability detected.\n");
      if((locdefrt = uip_ds6_defrt_lookup(uip_ds6_nbr_get_ipaddr(nb))) != NULL) {
        uip_ds6_defrt_rm(locdefrt);
      }
      uip_ds6_route_rm_by_nexthop(uip_ds6_nbr_get_ipaddr(nb));
      uip_ds6_nbr_rm(nb);
      nbr_table_remove(lrp_next_hops, nh);
    }

  } else if(status == MAC_TX_OK) {
    // Resetting counter
    lrp_next_hop_t* nh =
      (lrp_next_hop_t*) nbr_table_get_from_lladdr(lrp_next_hops, addr);
    if(nh != NULL && nh->nb_consecutive_noack_msg != 0) {
      PRINTF("Received ack; resetting noack counter for next hop ");
      PRINTLLADDR((uip_lladdr_t*)addr);
      PRINTF("\n");
      nh->nb_consecutive_noack_msg = 0;
    }
  }
}
#endif /* !UIP_ND6_SEND_NA */
#endif


/*---------------------------------------------------------------------------*/
void
lrp_set_local_prefix(uip_ipaddr_t *prefix, uint8_t len)
{
  uip_ipaddr_copy(&lrp_local_prefix.prefix, prefix);
  lrp_local_prefix.len = len;
}

/*---------------------------------------------------------------------------*/
uip_ipaddr_t*
lrp_select_nexthop_for(uip_ipaddr_t* source, uip_ipaddr_t* destination,
    uip_lladdr_t* previoushop)
{
  uip_ds6_route_t *route_to_dest;
  uip_ipaddr_t *nexthop;

  route_to_dest = uip_ds6_route_lookup(destination);
#if LRP_USE_DIO && LRP_IS_COORDINATOR && !LRP_IS_SINK
  // Do not forward through default route a packet that comes from higher
  if(!lrp_is_my_global_address(source) &&
      !lrp_is_predecessor(uip_ds6_nbr_ipaddr_from_lladdr(previoushop))) {
    // The previous hop is higher
    if(route_to_dest == NULL) {
      PRINTF("Discarding packet: previous and next hop are higher\n");
      // Change the context to ensure that timers set in this code wake up the
      // LRP process, and not the routing process
      PROCESS_CONTEXT_BEGIN(&lrp_process);
      lrp_routing_error(source, destination, previoushop);
      PROCESS_CONTEXT_END();
      return NULL;
    }
  }
#endif /* LRP_USE_DIO && LRP_IS_COORDINATOR && !LRP_IS_SINK */

  if(route_to_dest == NULL) {
    // No host route
#if LRP_IS_SINK
    // Send RREQ
    PRINTF("Discarding packet: unknown destination\n");
    // Change the context to ensure that timers set in this code wake up the
    // LRP process, and not the routing process
    PROCESS_CONTEXT_BEGIN(&lrp_process);
    lrp_request_route_to(destination);
    PROCESS_CONTEXT_END();
    return NULL;
#else
    // Use default route instead
    nexthop = uip_ds6_defrt_choose();
    if(uip_ds6_nbr_lladdr_from_ipaddr(nexthop) == NULL) {
      PRINTF("Discarding packet: no default route\n");
      // No more successor, deleting default route.
      uip_ds6_defrt_rm(uip_ds6_defrt_lookup(nexthop));
      // Change the context to ensure that timers set in this code wake up the
      // LRP process, and not the routing process
      PROCESS_CONTEXT_BEGIN(&lrp_process);
      lrp_no_more_default_route();
      PROCESS_CONTEXT_END();
      return NULL;
    }
#endif /* LRP_IS_SINK */
  } else {
    // Use provided host route
    nexthop = uip_ds6_route_nexthop(route_to_dest);
  }

#if LRP_IS_COORDINATOR
  if(route_to_dest != NULL && !route_to_dest->state.ack_received) {
    PRINTF("Discarding packet: used route is not acked\n");
    // FIXME: remove the route? Send RERR?
    return NULL;
  }
#endif /* LRP_IS_COORDINATOR */

  if(nexthop == NULL) {
    // The nexthop is not in neighbour table
    PRINTF("Discarding packet: nexthop in routing table is not in "
        "neighbour table\n");
    uip_ds6_route_rm(route_to_dest);
  } else {
    PRINTF("Routing through ");
    PRINT6ADDR(nexthop);
    if(route_to_dest == NULL) {
      PRINTF(" (default route)\n");
    } else {
      PRINTF(" (host route)\n");
    }
  }
  return nexthop;
}

/*---------------------------------------------------------------------------*/
PROCESS_THREAD(lrp_process, ev, data)
{
  PROCESS_BEGIN();
  PRINTF("LRP process started\n");
#if LRP_IS_SINK
  PRINTF("This node is a sink\n");
#elif LRP_IS_COORDINATOR
  PRINTF("This node is a coordinator\n");
#else
  PRINTF("This node is a leaf\n");
#endif

  get_global_addr(&lrp_myipaddr);
  get_prefix_from_addr(&lrp_myipaddr, &lrp_local_prefix.prefix, DEFAULT_LOCAL_PREFIX);
  uip_create_linklocal_lln_routers_mcast(&mcastipaddr);
  uip_ds6_maddr_add(&mcastipaddr);

  lrp_state_restore();
  lrp_udpconn = udp_new(NULL, UIP_HTONS(LRP_UDPPORT), NULL);
  udp_bind(lrp_udpconn, UIP_HTONS(LRP_UDPPORT));
  lrp_udpconn->ttl = 1;
  PRINTF("Created an UDP socket");
  PRINTF(" (local/remote port %u/%u)\n",
        UIP_HTONS(lrp_udpconn->lport), UIP_HTONS(lrp_udpconn->rport));

#if !UIP_ND6_SEND_NA
  nbr_table_register(lrp_next_hops, NULL);
#endif /* !UIP_ND6_SEND_NA */

#if LRP_ROUTE_HOLD_TIME
  // Activate route expiration checker
  lrp_check_expired_route();
#endif /* LRP_ROUTE_HOLD_TIME */

#if LRP_RREQ_RETRIES && (LRP_IS_SINK || !LRP_USE_DIO)
  // Activate RREQ retransmission
  rrc_check_expired_rreq();
#endif /* LRP_RREQ_RETRIES && (LRP_IS_SINK || !LRP_USE_DIO) */

#if !LRP_IS_SINK
  // Start sending DIS to find nodes just around
  lrp_no_more_default_route();
#endif
#if LRP_IS_SINK
  // Start sending DIO to build tree
  global_repair();
#endif

  while(1) {
    PROCESS_YIELD();

    if(ev == tcpip_event) {
      if(uip_newdata()) {
        lrp_handle_incoming_msg();
      }
    }
  }
  PROCESS_END();
}

#endif /* UIP_CONF_IPV6_LRP */
/*---------------------------------------------------------------------------*/
