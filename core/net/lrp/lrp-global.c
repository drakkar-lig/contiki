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
 *         Collection Tree maintenance algorithm
 * \author Chi-Anh La <la@imag.fr>
 * \author Martin Heusse <martin.heusse@imag.fr>
 * \author Audéoud Henry-Joseph <henry-joseph.audeoud@imag.fr>
 */

#if UIP_CONF_IPV6_LRP

#define DEBUG DEBUG_PRINT

#include "net/lrp/lrp.h"
#include "net/lrp/lrp-global.h"
#include "net/lrp/lrp-ct.h"
#include "net/lrp/lrp-def.h"
#include "net/ip/uip-debug.h"
#include "contiki-net.h"
#include "cfs/cfs.h"
#include <string.h>

/*---------------------------------------------------------------------------*/
/* State saving managment. If macro LRP_USE_CFS is set to true, the variable
 * `lrp_state` content is stored into the file system to save its value beyond
 * reboots. */
void
lrp_state_new(void)
{
#if LRP_IS_SINK
  uip_ipaddr_copy(&lrp_state.sink_addr, &lrp_myipaddr);
  lrp_state.tree_seqno = 1;
  lrp_state.metric_type = LRP_METRIC_HOP_COUNT;
  lrp_state.metric_value = 0;
#else
  uip_ip6addr(&lrp_state.sink_addr, 0, 0, 0, 0, 0, 0, 0, 0);
  lrp_state.tree_seqno = 0;
  lrp_state.metric_type = ~0;
  lrp_state.metric_value = ~0;
#endif
  lrp_state.repair_seqno = lrp_state.tree_seqno;
  lrp_state.node_seqno = 1;
}
#if LRP_USE_CFS
void
lrp_state_save(void)
{
  int fd, written = 0, rcode;
  fd = cfs_open(STATE_SVFILE, CFS_WRITE);
  if(fd != -1) {
    do {
      rcode = cfs_write(fd, ((uint8_t *)&lrp_state) + written,
                        sizeof(lrp_state) - written);
      written += rcode;
    } while(rcode != -1 && written != sizeof(lrp_state));
    cfs_close(fd);
  }

  if(fd == -1 || rcode == -1) {
    PRINTF("Error: Unable to save state into \"" STATE_SVFILE "\"\n");
  } else {
    PRINTF("State saved\n");
  }
}
void
lrp_state_restore(void)
{
  int fd, read = 0, rcode;
  fd = cfs_open(STATE_SVFILE, CFS_READ);
  if(fd != -1) {
    do {
      rcode = cfs_read(fd, ((uint8_t *)&lrp_state) + read,
                       sizeof(lrp_state) - read);
      read += rcode;
    } while(rcode != -1 && read != sizeof(lrp_state));
    cfs_close(fd);
  }

  if(fd != -1 && rcode != -1) {
    PRINTF("State restored\n");
    return;
  }

  PRINTF("Creating new state\n");
  lrp_state_new();
}
#endif /* LRP_USE_CFS */

/*---------------------------------------------------------------------------*/
#if !LRP_IS_SINK && LRP_IS_COORDINATOR
void
lrp_store_tmp_state(uip_ipaddr_t* unconfirmed_successor, struct lrp_msg* msg)
{
  /* Save state in lrp_tmp_state */
  if(msg->type == LRP_DIO_TYPE) {
    PRINTF("Saving temporary state from DIO\n");
    memcpy(&lrp_tmp_state.msg, msg, sizeof(struct lrp_msg_dio_t));
  } else if(msg->type == LRP_UPD_TYPE) {
    PRINTF("Saving temporary state from UPD\n");
    memcpy(&lrp_tmp_state.msg, msg, sizeof(struct lrp_msg_upd_t));
  } else {
    PRINTF("WARNING: Unexpected message type %x when saving temporary state\n", msg->type);
    return;
  }
  uip_ipaddr_copy(&lrp_tmp_state.unconfirmed_successor, unconfirmed_successor);
}
void
lrp_confirm_tmp_state(uip_ipaddr_t *nexthop)
{
  uip_ds6_defrt_t* defrt;

  /* Change state */
  PRINTF("Updating LRP state\n");
  if(lrp_tmp_state.msg.msg.type == LRP_DIO_TYPE) {
    uip_ipaddr_copy(&lrp_state.sink_addr, &lrp_tmp_state.msg.dio.sink_addr);
    lrp_state.tree_seqno   = lrp_tmp_state.msg.dio.tree_seqno;
    lrp_state.repair_seqno = lrp_tmp_state.msg.dio.tree_seqno;
    lrp_state.metric_type  = lrp_tmp_state.msg.dio.metric_type;
    lrp_state.metric_value = lrp_tmp_state.msg.dio.metric_value + lrp_link_cost(&lrp_tmp_state.unconfirmed_successor, lrp_tmp_state.msg.dio.metric_type);
  } else if(lrp_tmp_state.msg.msg.type == LRP_UPD_TYPE) {
    uip_ipaddr_copy(&lrp_state.sink_addr, &lrp_tmp_state.msg.upd.sink_addr);
    lrp_state.tree_seqno   = lrp_tmp_state.msg.upd.tree_seqno;
    lrp_state.repair_seqno = lrp_tmp_state.msg.upd.repair_seqno;
    lrp_state.metric_type  = lrp_tmp_state.msg.upd.metric_type;
    lrp_state.metric_value = lrp_tmp_state.msg.upd.metric_value + lrp_link_cost(&lrp_tmp_state.unconfirmed_successor, lrp_tmp_state.msg.upd.metric_type);
  }
  lrp_state_save();

  /* Remove previous default route */
  defrt = uip_ds6_defrt_lookup(uip_ds6_defrt_choose());
  if(defrt != NULL) {
    uip_ds6_defrt_rm(defrt);
  }

  /* Flush routes through new default route */
  uip_ds6_route_rm_by_nexthop(&lrp_tmp_state.unconfirmed_successor);

  /* Record new default route */
  PRINTF("New default route. Successor is ");
  PRINT6ADDR(&lrp_tmp_state.unconfirmed_successor);
  PRINTF("\n");
  lrp_nbr_add(&lrp_tmp_state.unconfirmed_successor);
  defrt = uip_ds6_defrt_add(&lrp_tmp_state.unconfirmed_successor, LRP_DEFRT_LIFETIME);
  stimer_set(&defrt->lifetime, LRP_DEFRT_LIFETIME);

  /* Broadcast the current state */
  lrp_delayed_dio(NULL, 0);

  /* Forward UPD further */
  if(lrp_tmp_state.msg.msg.type == LRP_UPD_TYPE) {
    lrp_forward_upd(&lrp_tmp_state.msg.upd);
  }

  /* Flush lrp_tmp_state */
  memset(&lrp_tmp_state.unconfirmed_successor, 0, sizeof(uip_ipaddr_t));
}
#endif /* !LRP_IS_SINK && LRP_IS_COORDINATOR */

/*---------------------------------------------------------------------------*/
uint8_t
lrp_ipaddr_is_empty(uip_ipaddr_t *addr)
{
  uint8_t i;
  for(i = 0; i < 8; i++) {
    if(((uint16_t *)addr)[i] != 0x0000) {
      return 0 == 1;
    }
  }
  return 1 == 1;
}
/*---------------------------------------------------------------------------*/
/* Return the link cost between this node and the next_hop, depending on the
 * metric type. */
uint16_t
lrp_link_cost(uip_ipaddr_t *link, uint8_t metric_type)
{
  switch(metric_type) {
    case LRP_METRIC_NONE:
      return 0;
    default:
      PRINTF("WARNING: unknown metric type (%x)."
             "Using hop count instead.\n", metric_type);
      /* Consider the metric is HOP_COUNT */
    case LRP_METRIC_HOP_COUNT:
      return 1;
  }
  return 1;
}
/*---------------------------------------------------------------------------*/
uint8_t
lrp_is_my_global_address(uip_ipaddr_t *addr)
{
  int i;
  int state;

  for(i = 0; i < UIP_DS6_ADDR_NB; i++) {
    state = uip_ds6_if.addr_list[i].state;
    if(uip_ds6_if.addr_list[i].isused &&
       (state == ADDR_TENTATIVE || state == ADDR_PREFERRED)) {
      if(uip_ipaddr_cmp(addr, &uip_ds6_if.addr_list[i].ipaddr)) {
        return 1;
      }
    }
  }
  return 0;
}
/*---------------------------------------------------------------------------*/
#if LRP_IS_SINK
uint8_t
lrp_addr_match_local_prefix(uip_ipaddr_t *host)
{
  return uip_ipaddr_prefixcmp(&lrp_local_prefix.prefix, host,
                              lrp_local_prefix.len);
}
#endif /* LRP_IS_SINK */

/*---------------------------------------------------------------------------*/
/* Signal to neighbor table a new neighbor. If node cannot send NA
 * (!UIP_ND6_SEND_NA), then remote lladdr is automatically computed. Else,
 * neighbor is entred as "incomplete" entry, and NS/NA will be performed to
 * confirm neighbor presence and get its lladdr. */
void
lrp_nbr_add(uip_ipaddr_t *next_hop)
{
#if !UIP_ND6_SEND_NA
  uip_lladdr_t nbr_lladdr;
  uip_ipaddr_t *def_nexthop;
#endif
  uip_ds6_nbr_t *nbr = uip_ds6_nbr_lookup(next_hop);

  if(nbr == NULL) {
    PRINTF("Adding ");
    PRINT6ADDR(next_hop);
    PRINTF(" to neighbor table");
#if !UIP_ND6_SEND_NA
    /* it's my responsability to create+maintain neighbor */
    PRINTF(" (without NA),");
    memcpy(&nbr_lladdr, &next_hop->u8[8],
           UIP_LLADDR_LEN);
    nbr_lladdr.addr[0] ^= 2;
    PRINTF(" with lladdress ");
    PRINTLLADDR(&nbr_lladdr);
    PRINTF("\n");
    uip_ds6_nbr_add(next_hop, &nbr_lladdr, 0, NBR_REACHABLE);
/*    nbr->nscount = 1; */
#else /* !UIP_ND6_SEND_NA */
    PRINTF(" (waiting for a NA)\n");
    uip_ds6_nbr_add(next_hop, NULL, 0, NBR_INCOMPLETE);
#endif /* !UIP_ND6_SEND_NA */
  }
#if !UIP_ND6_SEND_NA
  /* Put back default route neighbor in table if it was discarded: we have to
   * keep it. */
  def_nexthop = uip_ds6_defrt_choose();
  if(def_nexthop != NULL) {
    if(uip_ds6_nbr_lladdr_from_ipaddr(def_nexthop) == NULL) {
      /* Put it back in the table */
      PRINTF("Re-installing default route next-hop in neighbor table\n");
      memcpy(&nbr_lladdr, &def_nexthop->u8[8],
             UIP_LLADDR_LEN);
      nbr_lladdr.addr[0] ^= 2;
      uip_ds6_nbr_add(def_nexthop, &nbr_lladdr, 0, NBR_REACHABLE);
    }
  }
#endif /* !UIP_ND6_SEND_NA */
}
/*---------------------------------------------------------------------------*/
/* Return a random duration (in ticks). `scale` is the interval (in
 * milliseconds) where the random duration must be taken into. */
uint32_t
rand_wait_duration_before_broadcast()
{
  return (random_rand() % 256) * LRP_RANDOM_WAIT / 256;
}
#endif /* UIP_CONF_IPV6_LRP */
