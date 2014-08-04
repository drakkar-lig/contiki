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
 * $Id: rrpl.c,v 1.37 2010/01/20 09:58:16 chianhla Exp $
 */

/**
 * \file
 *         This protocol is evolved from 
 *         the LOADng routing protocol 
 *         IETF draft draft-clausen-lln-loadng-00.txt
 *         Version for slotted 802.15.4 
 * \author 
 *         Chi-Anh La la@imag.fr         
 *         Martin Heusse Martin.Heusse@imag.fr
 */

#include "contiki.h"
#include "contiki-lib.h"
#include "net/rrpl/rrpl-def.h"
#include "net/rrpl/rrpl.h"
#include "contiki-net.h"


#include <string.h>

#if WITH_IPV6_RRPL

#define DEBUG 1
#include "net/uip-debug.h"

#define QRY_INTERVAL 5 * CLOCK_SECOND
#define QRY_NB 5

#define RRPL_MIN_INC            1
#define RRPL_MIN_TIME_ORDER     0
#define RRPL_MAX_RANK           127

#define SEND_INTERVAL		100 * CLOCK_SECOND
#define RETRY_CHECK_INTERVAL	5 * CLOCK_SECOND
#define RV_CHECK_INTERVAL	10 * CLOCK_SECOND
#define MAX_SEQNO 65534
#define MAX_PAYLOAD_LEN		50
#define DEFAULT_PREFIX_LEN	128
#define DEFAULT_LOCAL_PREFIX    64
#define DEFAULT_OPT_SEQ_SKIP    4
extern uip_ds6_route_t uip_ds6_routing_table[UIP_DS6_ROUTE_NB];
#define UIP_IP_BUF ((struct uip_udpip_hdr *)&uip_buf[UIP_LLH_LEN])
#define SEQNO_GREATER_THAN(s1, s2)                   \
          (((s1 > s2) && (s1 - s2 <= (MAX_SEQNO/2))) \
        || ((s2 > s1) && (s2 - s1 > (MAX_SEQNO/2))))
#if RRPL_RREQ_RATELIMIT
static struct timer next_time;
#endif

#if SND_QRY
static struct etimer eqryt;
#endif // SND_QRY

static enum {
  COMMAND_NONE,
  COMMAND_SEND_RREQ,
  COMMAND_SEND_RERR,
} command;
#define LAST_RSSI cc2420_last_rssi 
// extern int8_t last_rssi; // for stm32w
extern signed char cc2420_last_rssi ;
static struct ctimer sendmsg_ctimer;
static uint16_t my_hseqno, my_seq_id;
static uint8_t my_time_order, my_reflect, my_def_time_order;
static int8_t my_rank;
static uint8_t my_weaklink;
static int8_t my_parent_rssi;
static uint16_t local_prefix_len;
static uint8_t opt_seq_skip_counter;
uip_ipaddr_t local_prefix;
uip_ipaddr_t ipaddr, myipaddr, mcastipaddr;
uip_ipaddr_t orig_addr, dest_addr, rreq_addr, def_rt_addr, my_sink_id, my_oid_addr;
static struct uip_udp_conn *udpconn;
static uip_ipaddr_t rerr_bad_addr, rerr_src_addr, rerr_next_addr;
static uint8_t in_rrpl_call=0 ; // make sure we don't trigger a rreq from within rrpl

static uint8_t qry_left_to_send=0 ;

static void update_uplink(void);
static uint8_t is_prefered_parent(int8_t r, uint8_t t, uint8_t rf, uip_ipaddr_t *la);
static void change_default_route(uip_ipaddr_t* new_uplink);
static void send_upd(uip_ipaddr_t *addr);
static void enable_qry();
/*---------------------------------------------------------------------------*/
PROCESS(rrpl_process, "RRPL process");
/*---------------------------------------------------------------------------*/


/* Route lookup without triggering RREQ ! */
/*---------------------------------------------------------------------------*/
static uip_ds6_route_t *
rrpl_route_lookup(uip_ipaddr_t *addr)
{
  uip_ds6_route_t *r;
  uip_ds6_route_t *found_route;
  uint8_t longestmatch;

  PRINTF("rrpl_route_lookup: Looking up route for ");
  PRINT6ADDR(addr);
  PRINTF("\n");


  found_route = NULL;
  longestmatch = 0;
  for(r = uip_ds6_route_head();
      r != NULL;
      r = uip_ds6_route_next(r)) {
    if(r->length >= longestmatch &&
       uip_ipaddr_prefixcmp(addr, &r->ipaddr, r->length)) {
      longestmatch = r->length;
      found_route = r;
    }
  }

  if(found_route != NULL) {
    PRINTF("rrpl_route_lookup: Found route: ");
    PRINT6ADDR(addr);
    PRINTF(" via ");
    PRINT6ADDR(uip_ds6_route_nexthop(found_route));
    PRINTF("\n");
  } else {
    PRINTF("rrpl_route_lookup: No route found\n");
  }

  return found_route;
}
/*---------------------------------------------------------------------------*/



/* Implementation of route validity time check and purge */

static void
rrpl_check_expired_route(uint16_t interval)
{ 
  uip_ds6_route_t *r; 
    
  for(r = uip_ds6_route_head();
  r != NULL;
  r = uip_ds6_route_next(r)) {

    if(r->state.valid_time <= interval) {
      uip_ds6_route_rm(r);
    } else {
      r->state.valid_time -= interval; 
    }
  }

}
/*---------------------------------------------------------------------------*/



/* Implementation of route flush */

static void
rrpl_flush_routes()
{
  uip_ds6_route_t *r;

  PRINTF("FLUSHING ROUTES \n");
  for(r = uip_ds6_route_head();
  r != NULL;
  r = uip_ds6_route_next(r)) {
    uip_ds6_route_rm(r);
  }

}

/*---------------------------------------------------------------------------*/
/* Implementation of request forwarding cache to avoid multiple forwarding */
#define FWCACHE 2

static struct {
  uip_ipaddr_t orig;
  uint16_t seqno;
} fwcache[FWCACHE];

static int
fwc_lookup(const uip_ipaddr_t *orig, const uint16_t *seqno)
{
  unsigned n = (((uint8_t *)orig)[0] + ((uint8_t *)orig)[15]) % FWCACHE;
  return fwcache[n].seqno == *seqno && uip_ipaddr_cmp(&fwcache[n].orig, orig);
}

static void
fwc_add(const uip_ipaddr_t *orig, const uint16_t *seqno)
{
  unsigned n = (((uint8_t *)orig)[0] + ((uint8_t *)orig)[15]) % FWCACHE;
  fwcache[n].seqno = *seqno;
  uip_ipaddr_copy(&fwcache[n].orig, orig);
}


/*---------------------------------------------------------------------------*/
/* Implementation of route request cache for RRPL_RREQ_RETRIES and RRPL_NET_TRAVERSAL_TIME */
#define RRCACHE 2

static struct {
  uip_ipaddr_t dest;
  uint16_t expire_time;
  uint8_t request_time;
} rrcache[RRCACHE];

static int
rrc_lookup(const uip_ipaddr_t *dest)
{
  unsigned n = (((uint8_t *)dest)[0] + ((uint8_t *)dest)[15]) % RRCACHE;
  return uip_ipaddr_cmp(&rrcache[n].dest, dest);
}

static void
rrc_remove(const uip_ipaddr_t *dest)
{
  unsigned n = (((uint8_t *)dest)[0] + ((uint8_t *)dest)[15]) % RRCACHE;
  if(uip_ipaddr_cmp(&rrcache[n].dest, dest))
  {
     memset(&rrcache[n].dest, 0, sizeof(&rrcache[n].dest));
     rrcache[n].expire_time = 0;
     rrcache[n].request_time = 0;
  }
}

static void
rrc_add(const uip_ipaddr_t *dest)
{
  unsigned n = (((uint8_t *)dest)[0] + ((uint8_t *)dest)[15]) % RRCACHE;
  rrcache[n].expire_time = RRPL_NET_TRAVERSAL_TIME;
  rrcache[n].request_time = 1;
  uip_ipaddr_copy(&rrcache[n].dest, dest);
}

static void
rrc_check_expired_rreq(uint16_t interval)
{ 
  int i;
  for(i = 0; i < RRCACHE; ++i){  
     rrcache[i].expire_time -= interval; 
     if(rrcache[i].expire_time <=0){
          rrpl_request_route_to(&rrcache[i].dest);
          rrcache[i].request_time++;
          if(rrcache[i].request_time == RRPL_RREQ_RETRIES){  
             rrc_remove(&rrcache[i].dest);
          } else {
             rrcache[i].expire_time = RRPL_NET_TRAVERSAL_TIME;   
          } 
     } 
  }

}


/*---------------------------------------------------------------------------*/
/* Implementation of link list for rrpl */
#define LINK_MAXNUM 5

static struct {
  uip_ipaddr_t linkaddr;
  int8_t rank;
  uint8_t time_order;
  uint8_t reflect;
  uint8_t uplink;
  uint8_t prefered_uplink;
  uint8_t ack_ok;
} linklist[LINK_MAXNUM];


static void
link_remove(const uip_ipaddr_t *laddr)
{
  uint8_t n;
  uip_ds6_defrt_t *defrt;
  for(n=0;n<LINK_MAXNUM;++n)
  {
     if(uip_ipaddr_cmp(&linklist[n].linkaddr, laddr))
     {
        memset(&linklist[n].linkaddr, 0, sizeof(linklist[n].linkaddr));
        linklist[n].rank = RRPL_MAX_RANK;
        linklist[n].time_order = RRPL_MIN_TIME_ORDER;
        linklist[n].uplink = 0;
        linklist[n].prefered_uplink = 0;
        //remove defrt?
        defrt = uip_ds6_defrt_lookup(&linklist[n].linkaddr);
        if(defrt !=  NULL){ 
          uip_ds6_defrt_rm(defrt);
        }
     }
 
  }
}

static void
link_add(const uip_ipaddr_t *laddr, int8_t rank, uint8_t timer_order, uint8_t reflect, uint8_t ack_ok)
{
  uint8_t n, i, found;
  i = LINK_MAXNUM + 1;
  found = 0;

  for(n=0;n<LINK_MAXNUM;++n)
  { 
    if(linklist[n].rank ==  RRPL_MAX_RANK && i>n){
       i = n;
    }
    if(uip_ipaddr_cmp(&linklist[n].linkaddr, laddr))
    {
       found = 1;
       break;
    } 
  }  
  if(!found && i!=(LINK_MAXNUM + 1)){
    n = i;
  } 
  PRINTF("rrpl: touching link at pos %u \n", n);
  linklist[n].rank = rank;
  linklist[n].time_order = timer_order;
  linklist[n].reflect = reflect;
  linklist[n].ack_ok = ack_ok;
  uip_ipaddr_copy(&linklist[n].linkaddr, laddr);

  update_uplink();  
}

static void
update_rank(const uip_ipaddr_t *laddr, int8_t rank){
  uint8_t n;
  
  for(n=0;n<LINK_MAXNUM;++n){
    if(uip_ipaddr_cmp(&linklist[n].linkaddr, laddr)){
      linklist[n].rank = rank;
      break;
    }
  }
}

static void update_uplink(void){
  uint8_t n;
  uip_ds6_defrt_t *defrt;
  PRINTF("update_uplink\n");
  rrpl_link_print();
  for(n = 0; n < LINK_MAXNUM; ++n){  
      if((linklist[n].rank<RRPL_MAX_RANK && linklist[n].time_order < my_time_order) || (linklist[n].time_order == my_time_order && (linklist[n].reflect < my_reflect || (linklist[n].reflect == my_reflect && linklist[n].rank < my_rank)))){
       linklist[n].uplink = 1;
       if(is_prefered_parent(linklist[n].rank, linklist[n].time_order, linklist[n].reflect, &linklist[n].linkaddr))
        {
          linklist[n].prefered_uplink = 1;
          change_default_route(&linklist[n].linkaddr);
        }
     } else {
        linklist[n].uplink = 0;
        linklist[n].prefered_uplink = 0; 
        defrt = uip_ds6_defrt_lookup(&linklist[n].linkaddr);
        if(defrt !=  NULL){ 
            uip_ds6_defrt_rm(defrt);
        }
     }
  }
}
static uint8_t
link_check_reversal_cond()
{ 
  if(RRPL_IS_SINK)
     return 0;
  uint8_t i, n=0;
  for(i = 0; i < LINK_MAXNUM; ++i){  
     if(linklist[i].rank !=  RRPL_MAX_RANK){
        if(linklist[i].uplink)
          return 0;
        n++;
     } 
  }
  return n;
}


static int8_t
calculate_rank()
{  
  if(RRPL_IS_SINK)
    return 1;
  uint8_t i, t;
  int8_t r; 
  r = my_rank;
  t = my_time_order;
  for(i = 0; i < LINK_MAXNUM; ++i){  
     if(linklist[i].uplink) { 
        if(linklist[i].time_order < t) {
          r = linklist[i].rank;
          t = linklist[i].time_order;
        } else if (linklist[i].time_order == t && linklist[i].rank < r) {
          r = linklist[i].rank;  
        } 
     } 
  }
  if(r==RRPL_MAX_RANK)
  {
  //PRINTF("rrpl: no up link\n");
    return r;
  }
  PRINTF("computed rank:%d\n", (r + RRPL_MIN_INC));   

  if(t==0)   
     return (r + RRPL_MIN_INC);
  else
     return (r - RRPL_MIN_INC);
}

static uint8_t
ipaddr_lt(const uip_ipaddr_t *l1, const uip_ipaddr_t *l2){
  int i;
  for (i=0;i<16;i++){
    if(((uint8_t *)l1)[i] < ((uint8_t *)l2)[i])
      return 1;
  }
  return 0;
}


static uint8_t
is_prefered_parent(int8_t r, uint8_t t, uint8_t rf, uip_ipaddr_t *la)
{ 
  uint8_t i;
  uint8_t def_rt_ok=0;
  for(i = 0; i < LINK_MAXNUM; ++i){  
     if(linklist[i].uplink) { 
        if(linklist[i].time_order < t) {
          return 0;
        } else if (linklist[i].time_order == t){ 
           if(linklist[i].reflect < rf)
                 return 0;
           if(linklist[i].rank < r)
                 return 0; 
           // chooses smallest address
//            if(ipaddr_lt(&linklist[i].linkaddr, la))
//                  return 0; 
           if(uip_ip6addr_cmp(&linklist[i].linkaddr,&def_rt_addr))
            def_rt_ok=1;
        } 
     } 
  }
  // Keep current next hop if still there
  if(!uip_ip6addr_cmp(la,&def_rt_addr) && def_rt_ok)
    return 0;
  return 1; 
}

/*---------------------------------------------------------------------------*/
void init_linklist(int8_t keep_current)
{
  uint8_t i;
  //PRINTF("rrpl: init link list values\n"); 
  for(i = 0; i < LINK_MAXNUM; ++i){
    if(!(keep_current && linklist[i].prefered_uplink)){
     linklist[i].rank =  RRPL_MAX_RANK;
     linklist[i].time_order = RRPL_MIN_TIME_ORDER;
     memset(&linklist[i].linkaddr, 0, sizeof(&linklist[i].linkaddr));
     linklist[i].uplink = 0;
     linklist[i].prefered_uplink = 0;
    }
  }
  
}
/*---------------------------------------------------------------------------*/
void
rrpl_link_print(void)
{
  PRINTF("rrpl: Print link entry: ");
  PRINT6ADDR(&myipaddr);
  PRINTF(" RANK [%d] | ", my_rank);
  uint8_t i;
  for(i = 0; i < LINK_MAXNUM; ++i){
    if(linklist[i].rank != RRPL_MAX_RANK){   
       PRINT6ADDR(&linklist[i].linkaddr);
       PRINTF(" U=%u ", linklist[i].uplink);
       PRINTF(" R=%d ", linklist[i].rank);
       PRINTF(" T=%u ", linklist[i].time_order);
       PRINTF(" P=%u ", linklist[i].prefered_uplink);
       PRINTF(" | "); 
    }  
  }
  PRINTF("\n");

}

/*---------------------------------------------------------------------------*/
static void
process_link_reversal(uint8_t t, int8_t r, uint8_t reflect, uip_ipaddr_t *oid)
{
  PRINTF("process_link_reversal()\n");
  if(t > my_time_order || (reflect && t == my_time_order)){ 
     my_time_order = t;
     my_rank = r - 1;
     my_reflect = reflect;
     uip_ipaddr_copy(&my_oid_addr, oid);
     //if(my_time_order > my_def_time_order){ //reflect
     //   my_reflect = 1;
     //   my_rank = 0;
     //}
     update_uplink();

     if(link_check_reversal_cond()){ //reflect
        PRINTF("rrpl: Relect detected\n");
        //my_time_order++; 
        //my_def_time_order = my_time_order;
        //my_rank = 0;
        //uip_ipaddr_copy(&my_oid_addr, &myipaddr);
        my_reflect = 1;
        my_rank = 0;
        update_uplink();
     }

  } else if(t == my_time_order) {
     PRINTF("same time order, increment time order NOW\n");
     my_time_order++;
     my_def_time_order = my_time_order;
     my_rank = 0;
     uip_ipaddr_copy(&my_oid_addr, &myipaddr);
     update_uplink();
  }

  ctimer_set(&sendmsg_ctimer, random_rand() / 1000,
           (void (*)(void *))send_upd, NULL);
  
}


static void
lost_defrt_whatnow(){
  PRINTF("lost_defrt_whatnow()\n");
  // first see if we have a backup solution
  update_uplink();
  if(calculate_rank()==RRPL_MAX_RANK){
    enable_qry();
  }
  else{
    if(link_check_reversal_cond()){
      process_link_reversal(my_time_order, my_rank, my_reflect, &myipaddr);
    }
  }
}

/*---------------------------------------------------------------------------*/
void
uip_ds6_route_print(void)
{
  uip_ds6_route_t *locroute = NULL;


  PRINTF("RRPL: Print route entry: ");
  PRINT6ADDR(&myipaddr);
  
for(locroute = uip_ds6_route_head();
  locroute != NULL;
  locroute = uip_ds6_route_next(locroute)) {
    PRINTF(" DEST "); 
    PRINT6ADDR(&locroute->ipaddr);
    PRINTF("/%u ", locroute->length);
    PRINTF(" NEXT ");  
    PRINT6ADDR(uip_ds6_route_nexthop(locroute));
    PRINTF(" HC %u ", locroute->state.route_cost);
    PRINTF(" | "); 
  }
  PRINTF("\n");

}

static inline uint8_t get_weaklink(uint8_t metric){
  return (metric & 0x0f) ;
}
static inline uint8_t parent_weaklink(int8_t rssi){
  return ((rssi > RRPL_RSSI_THRESHOLD) ? 0 : 1) ;
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

static void uip_rrpl_nbr_add(uip_ipaddr_t* next_hop){
  PRINTF("uip_rrpl_nbr_add:");
  PRINT6ADDR(next_hop);
  PRINTF("\n");
#if !UIP_ND6_SEND_NA
  uip_ds6_nbr_t *nbr = NULL;
  // it's my responsability to create+maintain neighbor
  nbr = uip_ds6_nbr_lookup(next_hop);
  
  if (nbr==NULL){
    PRINTF("adding nbr from rrpl\n");
    uip_lladdr_t nbr_lladdr;
    memcpy(&nbr_lladdr, &next_hop->u8[8],
           UIP_LLADDR_LEN);

    nbr_lladdr.addr[0] ^= 2;
    nbr = uip_ds6_nbr_add(next_hop, &nbr_lladdr, 0, NBR_REACHABLE);
//    nbr->nscount = 1;

  }
  else{
    PRINT6ADDR(&nbr->ipaddr);
    PRINTF("\n");
  }
  
#endif /* !UIP_ND6_SEND_NA */
}

void rrpl_rand_wait(){
#if RRPL_RANDOM_WAIT == 1
      PRINTF("waiting rand time\n");
      clock_wait(random_rand()%50 * CLOCK_SECOND / 100);
      PRINTF("done waiting rand time\n");
#endif
}

static uip_ds6_route_t* uip_rrpl_route_add(uip_ipaddr_t* orig_addr, uint8_t length,
            uip_ipaddr_t* next_hop,uint8_t route_cost,uint16_t seqno)
{

  struct uip_ds6_route *rt;
  
  in_rrpl_call=1;

  PRINTF("uip_rrpl_route_add() --- nexthop :");
  PRINT6ADDR(next_hop);
  PRINTF(" to: ");
  PRINT6ADDR(orig_addr);
  PRINTF(" \n ");
  uip_rrpl_nbr_add(next_hop);
 
  rt = uip_ds6_route_add(orig_addr, length, next_hop);
  PRINTF("passed add route\n");
  
  if(rt){
    rt->state.route_cost=route_cost ;
    rt->state.seqno=seqno ;
    rt->state.valid_time = RRPL_R_HOLD_TIME ;

    in_rrpl_call=0;

    return rt ;
  }
  else{ 
    in_rrpl_call=0;
    return NULL ;
  }
}

/*---------------------------------------------------------------------------*/
static void
enable_qry()
{
#if SND_QRY
  if(qry_left_to_send<=0){
    qry_left_to_send=QRY_NB;
    etimer_set(&eqryt, (((QRY_NB-qry_left_to_send)<<1)*QRY_INTERVAL*(random_rand()%50))/50);
  }
#endif // SND_QRY
}

/*---------------------------------------------------------------------------*/
static void
send_qry()
{
  
  char buf[MAX_PAYLOAD_LEN];
  PRINTF("RRPL: Send QRY from ");
  PRINT6ADDR(&myipaddr);
  PRINTF("\n"); 

  struct rrpl_msg_qry *rm = (struct rrpl_msg_qry *)buf;

  rm->type = RRPL_QRY_TYPE;
  rm->type = (rm->type << 4) | RRPL_RSVD1;
  rm->addr_len = RRPL_RSVD2; 
  rm->addr_len = (rm->type << 4) | RRPL_ADDR_LEN_IPV6;
  udpconn->ttl = 1;
  uip_create_linklocal_lln_routers_mcast(&udpconn->ripaddr);
  uip_udp_packet_send(udpconn, buf, sizeof(struct rrpl_msg_qry));
  memset(&udpconn->ripaddr, 0, sizeof(udpconn->ripaddr));
  qry_left_to_send--;
  if(qry_left_to_send>0){
    etimer_set(&eqryt, (QRY_INTERVAL*(random_rand()%50))/50);
  }
}

/*---------------------------------------------------------------------------*/
static void
send_upd(uip_ipaddr_t *addr)
{ printf("rrpl_SEND_MSG_UPD\n");
  if(my_rank == RRPL_MAX_RANK)
     return;
  char buf[MAX_PAYLOAD_LEN];
  PRINTF("rrpl: Send UPD");
  //PRINT6ADDR(addr); /* addr can be multicast addr */
  PRINTF(" from ");
  PRINT6ADDR(&myipaddr);
  PRINTF("\n"); 

  struct rrpl_msg_upd *rm = (struct rrpl_msg_upd *)buf;

  rm->type = RRPL_UPD_TYPE;
  rm->type = (rm->type << 4) | RRPL_RSVD1;
  rm->addr_len = RRPL_RSVD2; 
  rm->addr_len = (rm->type << 4) | RRPL_ADDR_LEN_IPV6;
  if((int)RRPL_IS_SINK){
     uip_ipaddr_copy(&rm->sink_id, &myipaddr);
  } else {
     uip_ipaddr_copy(&rm->sink_id, &my_sink_id);
  }
  rm->seq_id = my_seq_id;
  rm->time_order = my_time_order;
  rm->rank = my_rank;
  rm->reflect = my_reflect;
  uip_ipaddr_copy(&rm->oid_addr, &my_oid_addr);
  udpconn->ttl = 1;
  if(addr != NULL){
     uip_ipaddr_copy(&udpconn->ripaddr, addr);
  } else {
     uip_create_linklocal_lln_routers_mcast(&udpconn->ripaddr);
  } 
  //PRINTF("rrpl: UPD length %u\n", sizeof(struct rrpl_msg_upd));
  uip_udp_packet_send(udpconn, buf, sizeof(struct rrpl_msg_upd));
  memset(&udpconn->ripaddr, 0, sizeof(udpconn->ripaddr));
}

/*---------------------------------------------------------------------------*/
static void
send_clr(void)
{ printf("rrpl_SEND_MSG_CLR\n");
  char buf[MAX_PAYLOAD_LEN];
  //PRINTF("rrpl: Send CLR for ");
  //PRINTF(" from ");
  //PRINT6ADDR(&myipaddr);
  //PRINTF("\n"); 

  struct rrpl_msg_clr *rm = (struct rrpl_msg_clr *)buf;

  rm->type = RRPL_CLR_TYPE;
  rm->type = (rm->type << 4) | RRPL_RSVD1;
  rm->addr_len = RRPL_RSVD2; 
  rm->addr_len = (rm->type << 4) | RRPL_ADDR_LEN_IPV6;	

  rm->seq_id = my_seq_id;
  rm->time_order = my_time_order;
  uip_ipaddr_copy(&rm->oid_addr, &my_oid_addr);
  udpconn->ttl = 1;
  uip_create_linklocal_lln_routers_mcast(&udpconn->ripaddr);
 
  //PRINTF("rrpl: CLR length %u\n", sizeof(struct rrpl_msg_clr));
  uip_udp_packet_send(udpconn, buf, sizeof(struct rrpl_msg_clr));
  memset(&udpconn->ripaddr, 0, sizeof(udpconn->ripaddr));
}

/*---------------------------------------------------------------------------*/
#if RDC_LAYER_ID == ID_mac_802154_rdc_driver
void
#else
static void
#endif /* RDC_LAYER_ID == ID_mac_802154_rdc_driver */
send_opt()
{
  if(!RRPL_IS_COORDINATOR())
     return; //no OPT from device
  char buf[MAX_PAYLOAD_LEN];

  if(my_time_order>0){
    // No OPT in link reversal process!
    PRINTF("Time order > 0, aborting\n");
    return;
  }

  if(((int)RRPL_IS_SINK!=1)&& (uip_ds6_defrt_lookup(&def_rt_addr) == NULL))
  { 
    // No next hop, schedule to send qry
    lost_defrt_whatnow();
    return; //wait for sink OPT
  }

  PRINTF("RRPL: Send OPT from ");
  PRINT6ADDR(&myipaddr);
  PRINTF("\n"); 

  struct rrpl_msg_opt *rm = (struct rrpl_msg_opt *)buf;

  rm->type = RRPL_OPT_TYPE;
  rm->type = (rm->type << 4) | RRPL_RSVD1;
  rm->addr_len = RRPL_RSVD2; 
  rm->addr_len = (rm->type << 4) | RRPL_ADDR_LEN_IPV6;	
  rm->seqno = my_seq_id;
  rm->rank = my_rank;
  rm->metric = RRPL_METRIC_HC;
  rm->metric = (rm->metric << 4) | (my_weaklink + parent_weaklink(my_parent_rssi));
  if((int)RRPL_IS_SINK){
     uip_ipaddr_copy(&rm->sink_addr, &myipaddr);
  } else {
     uip_ipaddr_copy(&rm->sink_addr, &my_sink_id);
  }
  udpconn->ttl = 1;
  uip_create_linklocal_lln_routers_mcast(&udpconn->ripaddr);
//   PRINTF("RRPL: OPT length %u\n", sizeof(struct rrpl_msg_opt));
// #if RDC_LAYER_ID == ID_mac_802154_rdc_driver  
//   tcpip_set_outputfunc(output_802154);
//   uip_udp_packet_send(udpconn, buf, sizeof(struct rrpl_msg_opt));
//   tcpip_set_outputfunc(output);
// #else
  uip_udp_packet_send(udpconn, buf, sizeof(struct rrpl_msg_opt));
// #endif /* RDC_LAYER_ID == ID_mac_802154_rdc_driver */
  memset(&udpconn->ripaddr, 0, sizeof(udpconn->ripaddr));
#if RRPL_IS_SINK
  if(opt_seq_skip_counter >= DEFAULT_OPT_SEQ_SKIP){
    opt_seq_skip_counter = 0;
    my_seq_id++;
    if(my_seq_id > MAX_SEQNO)
      my_seq_id = 1;
  } else {
        opt_seq_skip_counter++;
  }
 	
#endif
}
/*---------------------------------------------------------------------------*/
static void
send_rreq()
{
  
  char buf[MAX_PAYLOAD_LEN];
  PRINTF("RRPL: Send RREQ for ");
  PRINT6ADDR(&rreq_addr);
  PRINTF(" from ");
  PRINT6ADDR(&myipaddr);
  PRINTF("\n"); 

  struct rrpl_msg_rreq *rm = (struct rrpl_msg_rreq *)buf;

  rm->type = RRPL_RREQ_TYPE;
  rm->type = (rm->type << 4) | RRPL_RSVD1;
  rm->addr_len = RRPL_RSVD2; 
  rm->addr_len = (rm->type << 4) | RRPL_ADDR_LEN_IPV6;
  my_hseqno++;
  if(my_hseqno>MAX_SEQNO)
    my_hseqno = 1; 		
  rm->seqno = my_hseqno;
  rm->metric = RRPL_METRIC_HC;
  rm->metric = (rm->metric << 4) | RRPL_WEAK_LINK;
  rm->route_cost = 0;
  uip_ipaddr_copy(&rm->dest_addr, &rreq_addr);
  uip_ipaddr_copy(&rm->orig_addr, &myipaddr);
  udpconn->ttl = RRPL_MAX_DIST;
  uip_create_linklocal_lln_routers_mcast(&udpconn->ripaddr);
  PRINTF("RRPL: RREQ length %u\n", sizeof(struct rrpl_msg_rreq));
  uip_udp_packet_send(udpconn, buf, sizeof(struct rrpl_msg_rreq));
  memset(&udpconn->ripaddr, 0, sizeof(udpconn->ripaddr));
 
}
/*---------------------------------------------------------------------------*/
static void
send_rrep(uip_ipaddr_t *dest, uip_ipaddr_t *nexthop, uip_ipaddr_t *orig,
	  uint16_t *seqno, unsigned hop_count)
{ 
  char buf[MAX_PAYLOAD_LEN];
  struct rrpl_msg_rrep *rm = (struct rrpl_msg_rrep *)buf;
  PRINTF("RRPL: Send RREP for orig ");
  PRINT6ADDR(orig);
  PRINTF(" dest ");
  PRINT6ADDR(dest);
  PRINTF(" nexthop ");
  PRINT6ADDR(nexthop);
  PRINTF(" hopcount=%u\n", hop_count);
  
  rm->type = RRPL_RREP_TYPE;
  rm->type = (rm->type << 4) | RRPL_RSVD1;
  rm->addr_len = RRPL_RSVD2; 
  rm->addr_len = (rm->type << 4) | RRPL_ADDR_LEN_IPV6;
  rm->seqno = *seqno;
  rm->metric = RRPL_METRIC_HC;
  rm->metric = (rm->metric << 4) | RRPL_WEAK_LINK;
  rm->route_cost = hop_count;
  uip_ipaddr_copy(&rm->orig_addr, orig);
  uip_ipaddr_copy(&rm->dest_addr, dest);
  udpconn->ttl = RRPL_MAX_DIST;
  uip_ipaddr_copy(&udpconn->ripaddr, nexthop);
  PRINTF("RRPL: RREP length: %u\n", sizeof(struct rrpl_msg_rrep)); 
  uip_udp_packet_send(udpconn, buf, sizeof(struct rrpl_msg_rrep));
  memset(&udpconn->ripaddr, 0, sizeof(udpconn->ripaddr));
  
}

/*---------------------------------------------------------------------------*/
static void
send_rerr(uip_ipaddr_t *src, uip_ipaddr_t *dest, uip_ipaddr_t *nexthop)
{ 
  char buf[MAX_PAYLOAD_LEN];
  struct rrpl_msg_rerr *rm = (struct rrpl_msg_rerr *)buf;
  PRINTF("RRPL: Send RERR towards src: ");
  PRINT6ADDR(src);
  PRINTF(" for address in error: ");
  PRINT6ADDR(dest);
  PRINTF(" nexthop: ");
  PRINT6ADDR(nexthop);
  PRINTF("\n");
  rm->type = RRPL_RERR_TYPE;
  rm->type = (rm->type << 4) | RRPL_RSVD1;
  rm->addr_len = RRPL_RSVD2; 
  rm->addr_len = (rm->type << 4) | RRPL_ADDR_LEN_IPV6;
  uip_ipaddr_copy(&rm->addr_in_error, dest);
  uip_ipaddr_copy(&rm->src_addr, src);
  udpconn->ttl = RRPL_MAX_DIST;
  uip_ipaddr_copy(&udpconn->ripaddr, nexthop);
  PRINTF("RRPL: RERR length: %u\n", sizeof(struct rrpl_msg_rerr)); 
  uip_udp_packet_send(udpconn, buf, sizeof(struct rrpl_msg_rerr));
  memset(&udpconn->ripaddr, 0, sizeof(udpconn->ripaddr));
}
/*---------------------------------------------------------------------------*/
static void
send_rack(uip_ipaddr_t *src, uip_ipaddr_t *nexthop, uint16_t seqno)
{ 
  char buf[MAX_PAYLOAD_LEN];
  struct rrpl_msg_rack *rm = (struct rrpl_msg_rack *)buf;
  PRINTF("RRPL: Send RACK for src ");
  PRINT6ADDR(src);
  PRINTF(" nexthop ");
  PRINT6ADDR(nexthop);
  PRINTF("\n");
  rm->type = RRPL_RACK_TYPE;
  rm->type = (rm->type << 4) | RRPL_RSVD1;
  rm->addr_len = RRPL_RSVD2; 
  rm->addr_len = (rm->type << 4) | RRPL_ADDR_LEN_IPV6;
  uip_ipaddr_copy(&rm->src_addr, src);
  rm->seqno = seqno;
  udpconn->ttl = RRPL_MAX_DIST;
  uip_ipaddr_copy(&udpconn->ripaddr, nexthop);
  PRINTF("RRPL: RACK length: %u\n", sizeof(struct rrpl_msg_rack)); 
  uip_udp_packet_send(udpconn, buf, sizeof(struct rrpl_msg_rack));
  memset(&udpconn->ripaddr, 0, sizeof(udpconn->ripaddr));
}
/*---------------------------------------------------------------------------*/
static void
handle_incoming_rreq(void)
{
  struct rrpl_msg_rreq *rm = (struct rrpl_msg_rreq *)uip_appdata;
  uip_ipaddr_t dest_addr, orig_addr;

  PRINTF("RRPL: RREQ ");
  PRINT6ADDR(&UIP_IP_BUF->srcipaddr);
  PRINTF(" -> ");
  PRINT6ADDR(&UIP_IP_BUF->destipaddr);
  PRINTF(" ttl=%u ", UIP_IP_BUF->ttl);
  PRINTF(" hop=%u ", rm->route_cost);
  PRINTF(" seq=%u ", rm->seqno);
  PRINTF(" orig ");
  PRINT6ADDR(&rm->orig_addr);
  PRINTF(" dest ");
  PRINT6ADDR(&rm->dest_addr);
  PRINTF("\r\n");

  if(rrpl_is_my_global_address(&rm->orig_addr)) {
    PRINTF("RRPL: RREQ loops back, not processing\n");
    return;			
  }


  /* Do not add reverse route while receiving RREQ
  rt = rrpl_route_lookup(&rm->orig_addr);

  if(rt == NULL){
    PRINTF("RRPL: Inserting route from RREQ\n");
    rt = uip_ds6_route_add(&rm->orig_addr, DEFAULT_PREFIX_LEN,
            &UIP_IP_BUF->srcipaddr, rm->route_cost, rm->seqno, RRPL_R_HOLD_TIME);
  } else if(SEQNO_GREATER_THAN(rm->seqno,rt->state.seqno) 
            || (rm->seqno==rt->state.seqno && rm->route_cost < rt->state.route_cost)){
    PRINTF("RRPL: Update route from RREQ\n");
    uip_ipaddr_copy(&rt->nexthop, &UIP_IP_BUF->srcipaddr);
    rt->state.seqno = rm->seqno;
    rt->state.route_cost = rm->route_cost;
    rt->state.valid_time = RRPL_R_HOLD_TIME;
  } else {
    PRINTF("RRPL: Not a better route for inserting (RREQ)\n");
  }
    
  */

  if(rrpl_is_my_global_address(&rm->dest_addr)) { /* RREQ for our address */
    PRINTF("RRPL: RREQ for our address\n");
    uip_ipaddr_copy(&dest_addr, &rm->orig_addr);
    uip_ipaddr_copy(&orig_addr, &rm->dest_addr);
    my_hseqno++;
    if(my_hseqno>MAX_SEQNO)
	my_hseqno = 1; 	
    send_rrep(&dest_addr, &UIP_IP_BUF->srcipaddr, &orig_addr, &my_hseqno, 0); 
  } else if (RRPL_IS_COORDINATOR()) {  //only coordinator forward RREQ
    if(UIP_IP_BUF->ttl > 1) { /* TTL still valid for forwarding */

      /* Have we seen this RREQ before? */
      if(fwc_lookup(&rm->orig_addr, &rm->seqno)) {
        PRINTF("RRPL: RREQ cached, not forward\n");
        return;
      }
      fwc_add(&rm->orig_addr, &rm->seqno);

      PRINTF("RRPL: RREQ forward\n");
      rm->route_cost++;
      udpconn->ttl = UIP_IP_BUF->ttl - 1;
      uip_create_linklocal_lln_routers_mcast(&udpconn->ripaddr);
      rrpl_rand_wait();
      uip_udp_packet_send(udpconn, rm, sizeof(struct rrpl_msg_rreq));
      memset(&udpconn->ripaddr, 0, sizeof(udpconn->ripaddr));
    }
  }
}
/*---------------------------------------------------------------------------*/
static void
handle_incoming_rrep(void)
{
  struct rrpl_msg_rrep *rm = (struct rrpl_msg_rrep *)uip_appdata;
  struct uip_ds6_route *rt;
  uip_ipaddr_t *nexthop;
  /* No multicast RREP: drop */
  if(uip_ipaddr_cmp(&UIP_IP_BUF->destipaddr, &mcastipaddr)) {
    return;
  }
  PRINTF("RRPL: RREP ");
  PRINT6ADDR(&UIP_IP_BUF->srcipaddr);
  PRINTF(" -> ");
  PRINT6ADDR(&UIP_IP_BUF->destipaddr);
  PRINTF(" ttl=%u ", UIP_IP_BUF->ttl);
  PRINTF(" hop=%u ", rm->route_cost);
  PRINTF(" seq=%u ", rm->seqno);
  PRINTF(" orig ");
  PRINT6ADDR(&rm->orig_addr);
  PRINTF(" dest ");
  PRINT6ADDR(&rm->dest_addr);
  PRINTF("\r\n");

  rt = rrpl_route_lookup(&rm->orig_addr);

  /* New forward route? */
  if(rt == NULL){
    PRINTF("RRPL: Inserting route from RREP\n");
    rt=uip_rrpl_route_add(&rm->orig_addr, DEFAULT_PREFIX_LEN,
            &UIP_IP_BUF->srcipaddr,rm->route_cost,rm->seqno);
    if(rt){            
#if RRPL_RREP_ACK
      rt->state.ack_received = 0; /* Pending route for ACK */
#else
      rt->state.ack_received = 1; 
#endif
    }
  }
  else if(SEQNO_GREATER_THAN(rm->seqno,rt->state.seqno) 
          || (rm->seqno==rt->state.seqno && rm->route_cost < rt->state.route_cost)){
    PRINTF("RRPL: Update route from RREP\n");
    uip_ds6_route_rm(rt);
    uip_rrpl_route_add(&rm->orig_addr, DEFAULT_PREFIX_LEN,
            &UIP_IP_BUF->srcipaddr,rm->route_cost,rm->seqno);
  } else {
    PRINTF("RRPL: Not a better route for inserting (RREP)\n");
  }

  /* Forward RREP towards originator? */
  if(uip_ipaddr_cmp(&rm->dest_addr, &myipaddr)) {
    PRINTF("RRPL: Received RREP to our own RREQ\n");
#if RRPL_RREQ_RETRIES
    //remove route request cache
    rrc_remove(&rm->orig_addr);
#endif
  } else {
    //rt = rrpl_route_lookup(&rm->dest_addr);
    nexthop = uip_ds6_defrt_choose();
    if(nexthop == NULL) {
      PRINTF("RRPL: RREP received, but no default route to originator\n");
      // No ACK and RREP forwarding
      return;
    }
    // Send ACK
#if RRPL_RREP_ACK
    send_rack(&rm->orig_addr, &UIP_IP_BUF->srcipaddr, rm->seqno);
#endif    

    PRINTF("RRPL: Forward RREP to ");
    PRINT6ADDR(nexthop);
    PRINTF("\n");
    rm->route_cost++;
    udpconn->ttl = 1;
    uip_ipaddr_copy(&udpconn->ripaddr, nexthop);
    uip_udp_packet_send(udpconn, rm, sizeof(struct rrpl_msg_rrep));
    memset(&udpconn->ripaddr, 0, sizeof(udpconn->ripaddr));
    
  }
}

/*---------------------------------------------------------------------------*/
static void
handle_incoming_rack(void)
{
  struct rrpl_msg_rack *rm = (struct rrpl_msg_rack *)uip_appdata;
  struct uip_ds6_route *rt;


  PRINTF("RRPL: RACK ");
  PRINT6ADDR(&UIP_IP_BUF->srcipaddr);
  PRINTF(" -> ");
  PRINT6ADDR(&UIP_IP_BUF->destipaddr);
  PRINTF(" ttl=%u ", UIP_IP_BUF->ttl);
  PRINTF(" seq=%u ", rm->seqno);
  PRINTF(" src ");
  PRINT6ADDR(&rm->src_addr);
  PRINTF("\r\n");

  rt = rrpl_route_lookup(&rm->src_addr);

  /* No route? */
  if(rt == NULL){
    PRINTF("RRPL: Receved RACK for non-existing route\n");
  } else {
    rt->state.ack_received = 1; /* Make pending route valid */
  }
  
}
/*---------------------------------------------------------------------------*/
static void
handle_incoming_rerr(void)
{
  struct rrpl_msg_rerr *rm = (struct rrpl_msg_rerr *)uip_appdata;
  struct uip_ds6_route *rt_in_err;
  struct uip_ds6_route *rt;
  uip_ds6_defrt_t *defrt;
  
  #if USE_OPT
  uip_ipaddr_t mcastLoadAddr;
  uip_create_linklocal_lln_routers_mcast(&mcastLoadAddr);
  #endif //USE_OPT


  
  PRINTF("RRPL: RERR ");
  PRINT6ADDR(&UIP_IP_BUF->srcipaddr);
  PRINTF(" -> ");
  PRINT6ADDR(&UIP_IP_BUF->destipaddr);
  PRINTF(" ttl=%u ", UIP_IP_BUF->ttl);
  PRINTF(" towards ");
  PRINT6ADDR(&rm->src_addr);
  PRINTF(" addr in error : ");
  PRINT6ADDR(&rm->addr_in_error);
  PRINTF("\r\n");

  rt_in_err = rrpl_route_lookup(&rm->addr_in_error);
  rt = rrpl_route_lookup(&rm->src_addr);

  // It may happen that the address in error is mine... Stop here !
  if(rrpl_is_my_global_address(&rm->addr_in_error)){
    return ;
  }

  /* No route? */
  if(rt_in_err == NULL){
    PRINTF("RRPL: Received RERR for non-existing route\n");
  }
  else{
    uip_ds6_route_rm(rt_in_err); /* Remove route */
  }

  #if USE_OPT
  // if the RERR comes from a default router and it's for me, send spontaneous RREP
  defrt=uip_ds6_defrt_lookup(&UIP_IP_BUF->srcipaddr);
  if(defrt!=NULL && rrpl_is_my_global_address(&rm->src_addr)){
    PRINTF("send RREP\n");
    my_hseqno++;
    send_rrep(&my_sink_id, &defrt->ipaddr, &myipaddr, &my_hseqno, 0);
    return;
  }
  // otherwise, if there is a matching tupple, send along default route
  
  #endif //USE_OPT
  // Draft draft-clausen-lln-rrpl-10#section-14.3 : still forward even if no matching routing tupple found
  if(rt != NULL){
    send_rerr(&rm->src_addr, &rm->addr_in_error, uip_ds6_route_nexthop(rt));
  } /* Forward RERR to nexthop */
  #if USE_OPT 
  // If the RERR was multicast and I had a route, send along default route
  // If not multicast, send along default route
  else if(!uip_ipaddr_cmp(&UIP_IP_BUF->destipaddr,&mcastLoadAddr) || rt_in_err != NULL){
    if(!rrpl_is_my_global_address(&rm->src_addr))
      send_rerr(&rm->src_addr, &rm->addr_in_error, uip_ds6_defrt_choose());
  }
  #endif //USE_OPT
     
}
/*---------------------------------------------------------------------------*/
static void
change_default_route(uip_ipaddr_t* new_uplink)
{
  uip_ds6_defrt_t *defrt;
  PRINTF("Call change_default_route TO ");
  PRINT6ADDR(new_uplink);
  PRINTF(" FROM ");
  PRINT6ADDR(&def_rt_addr);
  PRINTF("\n");

  // add default route 
  defrt = uip_ds6_defrt_lookup(&def_rt_addr);
  // First check if we are actually changing of next hop!
  if(defrt !=  NULL){ 
    if(!uip_ip6addr_cmp(&defrt->ipaddr,new_uplink)){
      PRINTF("Actually changing of defrt next hop!\n");
      uip_ds6_defrt_rm(defrt);//remove route
    }
    else {
      // We just need to refresh the route 
//Wrong place to do this: this function is called when receiving a packet from other nodes
//       PRINTF("Refreshing route\n");
//       stimer_set(&defrt->lifetime, RRPL_DEFAULT_ROUTE_LIFETIME);
      // bugfix
        PRINTF("Same def rt: ");
        
        PRINT6ADDR(&def_rt_addr);
        PRINTF("\n");
        uip_ds6_nbr_t * neigh;
        neigh = uip_ds6_nbr_lookup(&def_rt_addr);
        PRINTF("state:%d", neigh->state);
         PRINTF("\n");
       
      // bugfix
      return;
      }
  }
  else if(uip_ip6addr_cmp(&def_rt_addr,new_uplink)){
    // At this point, it appears that we are not changing of next hop, but the defrt is NULL, 
    // So the neighbor is in fact gone. Either send an UPD, or wait for OPT with new SEQ
    PRINTF("Removing stale default route link:");
    PRINT6ADDR(&def_rt_addr);
    PRINTF("\n");
    link_remove(&def_rt_addr);
    uip_create_linklocal_empty_addr(&def_rt_addr);
    
    return;
  }
  // OK, so it seems we are changing of parent. Like, really...
  // Flush all routes. If I'm changing of parent, It means this new parent does not know about
  // the nodes below me anyway, so better not keep stale entries.
  // Moreover, keeping old entries and changing parents can break the loop avoidance mechanism.
  rrpl_flush_routes();

  in_rrpl_call=1;
  
  PRINTF("RRPL: call uip_rrpl_nbr_add\n");
  uip_rrpl_nbr_add(new_uplink);

  
  uip_ds6_defrt_add(new_uplink, RRPL_DEFAULT_ROUTE_LIFETIME);
  uip_ipaddr_copy(&def_rt_addr, new_uplink);
  in_rrpl_call=0;
}
/*---------------------------------------------------------------------------*/
static void
handle_incoming_opt(void)
{   
  struct rrpl_msg_opt *rm = (struct rrpl_msg_opt *)uip_appdata;
  PRINTF("RRPL: OPT ");
  PRINT6ADDR(&UIP_IP_BUF->srcipaddr);
  PRINTF(" -> ");
  PRINT6ADDR(&UIP_IP_BUF->destipaddr);
  PRINTF(" ttl=%u ", UIP_IP_BUF->ttl);
  PRINTF(" rank=%d ", rm->rank);
  PRINTF(" seq=%d ", rm->seqno);
  PRINTF(" rssi=%i ", (int8_t)LAST_RSSI);
  PRINTF("\r\n");

  if(uip_ipaddr_cmp(&UIP_IP_BUF->srcipaddr, &myipaddr)) {
    PRINTF("RRPL: OPT loops back, not processing\n");
    return;			
  } 

  if(SEQNO_GREATER_THAN(rm->seqno,my_seq_id)){
    /* First OPT */
    PRINTF("RRPL: New OPT sequence number received\n");
    my_seq_id = rm->seqno;
    my_rank=RRPL_MAX_RANK;
    // Start from scratch, except for current next hop -- if it's there
    init_linklist((my_time_order == 0)?1:0);
    if(uip_ip6addr_cmp(&UIP_IP_BUF->srcipaddr,&def_rt_addr)){
      // take rank directly from opt
      update_rank(&UIP_IP_BUF->srcipaddr, rm->rank);
    }
    my_time_order = 0;
    my_reflect = 0;
    my_rank=calculate_rank(); // Start from the rank of current route
  } else if(! rm->seqno == my_seq_id )
    {return;} // Ignoring past seq_no
    
  if(rm->rank+RRPL_MIN_INC<my_rank) // The rank can only go down
    my_rank=rm->rank+RRPL_MIN_INC;
  link_add(&UIP_IP_BUF->srcipaddr, rm->rank, 0, 0,1);
  //my_weaklink = get_weaklink(rm->metric); Should be calculate_weak_link()!!
  rrpl_link_print();
}

/*---------------------------------------------------------------------------*/
static void
handle_incoming_upd(void)
{
  struct rrpl_msg_upd *rm = (struct rrpl_msg_upd *)uip_appdata;
  PRINTF("rrpl: UPD ");
  //PRINT6ADDR(&UIP_IP_BUF->srcipaddr);
  PRINTF(" -> ");
  //PRINT6ADDR(&UIP_IP_BUF->destipaddr);
  PRINTF(" ttl=%u ", UIP_IP_BUF->ttl);
  PRINTF(" rank=%d ", rm->rank);
  PRINTF(" time=%u ", rm->time_order);
  PRINTF(" reflect=%u ", rm->reflect);
  //PRINTF(" id ");
  //PRINT6ADDR(&UIP_IP_BUF->srcipaddr);
  PRINTF(" oid ");
  PRINT6ADDR(&rm->oid_addr);
  //PRINTF(" sink_id ");
  //PRINT6ADDR(&rm->sink_id);
  PRINTF("\r\n");

  if(uip_ipaddr_cmp(&UIP_IP_BUF->srcipaddr, &myipaddr)) {
    PRINTF("rrpl: UPD loops back, not processing\n");
    return;			
  }


  /* First UPD */
  if(rm->seq_id > my_seq_id){
    PRINTF("rrpl: No DODAG, joining the DODAG in received UPD\n");
    init_linklist(0);
    my_rank = RRPL_MAX_RANK; /* Reset rank */
    uip_ipaddr_copy(&my_sink_id, &rm->sink_id);
    my_seq_id = rm->seq_id;
    my_time_order = rm->time_order;
    my_reflect = rm->reflect;
    uip_ipaddr_copy(&my_oid_addr, &rm->oid_addr);
    link_add(&UIP_IP_BUF->srcipaddr, rm->rank, rm->time_order, rm->reflect,1); 
    my_rank = calculate_rank();
    //NOTE: no OPT at all for UPD
    //ctimer_set(&sendmsg_ctimer, random_rand() / 1000,
    //           (void (*)(void *))send_upd, NULL); 
  } else {///if(link_lookup(&UIP_IP_BUF->srcipaddr)){ // link exists
    //PRINTF("rrpl: Update link from OPT\n");
    //link_add(&UIP_IP_BUF->srcipaddr, rm->rank, rm->time_order);
  //} else {
    //PRINTF("rrpl: Add new link from OPT\n");
    link_add(&UIP_IP_BUF->srcipaddr, rm->rank, rm->time_order, rm->reflect,1); 
  }
  PRINTF("rrpl: Update rank from received UPD r=%d\n", my_rank);
  ANNOTATE("R=%u t=%u\n", my_rank, my_time_order);  
 
  rrpl_link_print();
  if(uip_ipaddr_cmp(&rm->oid_addr, &myipaddr) && rm->reflect) {
   PRINTF("rrpl: Reflect detected with own OID: send CLR\n");
       ctimer_set(&sendmsg_ctimer, random_rand() / 1000,
              (void (*)(void *))send_clr, NULL);
   my_rank = RRPL_MAX_RANK;
   return;			
  }

  //TODO: if rank decrease: ie move closer toward root: send UPD, if not keep current rank?
  //TODO maintain route: check cond of no uplink
  if(link_check_reversal_cond()){
     process_link_reversal(rm->time_order, rm->rank, rm->reflect, &rm->oid_addr);
  }
}

/*---------------------------------------------------------------------------*/
static void
handle_incoming_clr(void)
{
  struct rrpl_msg_clr *rm = (struct rrpl_msg_clr *)uip_appdata;
  PRINTF("rrpl: CLR ");
  //PRINT6ADDR(&UIP_IP_BUF->srcipaddr);
  //PRINTF(" -> ");
  //PRINT6ADDR(&UIP_IP_BUF->destipaddr);
  //PRINTF(" ttl=%u ", UIP_IP_BUF->ttl);
  //PRINTF(" time=%u ", rm->time_order);
  //PRINTF(" id ");
  //PRINT6ADDR(&UIP_IP_BUF->srcipaddr);
  //PRINTF(" oid ");
  //PRINT6ADDR(&rm->oid_addr);
  //PRINTF(" sink_id ");
  //PRINT6ADDR(&rm->sink_id);
  PRINTF("\r\n");

  if(uip_ipaddr_cmp(&UIP_IP_BUF->srcipaddr, &myipaddr)) {
    //PRINTF("rrpl: CLR loops back, not processing\n");
    return;			
  }
  
  
  link_remove(&UIP_IP_BUF->srcipaddr);
  
  update_uplink();
  if(!RRPL_IS_SINK){
    if(my_rank != RRPL_MAX_RANK)
    {
      ctimer_set(&sendmsg_ctimer, random_rand() / 1000,
               (void (*)(void *))send_clr, NULL);
      my_rank = RRPL_MAX_RANK; 
    }
  }
}


/*---------------------------------------------------------------------------*/
static void
print_local_addresses(void)
{
  int i;
  uint8_t state;

  PRINTF("RRPL IPv6 addresses: \n");
  for(i = 0; i < UIP_DS6_ADDR_NB; i++) {
    state = uip_ds6_if.addr_list[i].state;
    if(uip_ds6_if.addr_list[i].isused &&
       (state == ADDR_TENTATIVE || state == ADDR_PREFERRED)) {
      PRINTF("- ");
      PRINT6ADDR(&uip_ds6_if.addr_list[i].ipaddr);
      PRINTF("\n");
    }
  }
}
/*---------------------------------------------------------------------------*/

static void
tcpip_handler(void)
{
  
  uint8_t type;
  if(uip_newdata()) {

  
    struct rrpl_msg *m = (struct rrpl_msg *)uip_appdata;
    type = m->type >> 4;
    PRINTF("RRPL: Packet type %u\n", type);
    if(type==RRPL_RREQ_TYPE){
      PRINTF("RRPL: Received RREQ\n");
      handle_incoming_rreq();
    } else
    if(type==RRPL_RREP_TYPE){
      PRINTF("RRPL: Received RREP\n");
      handle_incoming_rrep();
    } else
    if(type==RRPL_RERR_TYPE){
      PRINTF("RRPL: Received RERR\n");
      handle_incoming_rerr();
    } else
    if(type==RRPL_RACK_TYPE){
      PRINTF("RRPL: Received RACK\n");
      handle_incoming_rack();
    }
    if(type==RRPL_OPT_TYPE){
      PRINTF("RRPL: Received OPT\n");
      handle_incoming_opt();
    }
    if(type==RRPL_QRY_TYPE){
      PRINTF("RRPL: Received QRY -- Send OPT\n");
      rrpl_rand_wait();
      send_opt(); // fixme: should be upd?
    }
    if(type==RRPL_UPD_TYPE){
      PRINTF("RRPL: Received UPD\n");
      handle_incoming_upd();
    }
    if(type==RRPL_CLR_TYPE){
      PRINTF("RRPL: Received UPD\n");
      handle_incoming_clr();
    }
  }
}
/*---------------------------------------------------------------------------*/
uint8_t rrpl_addr_matches_local_prefix(uip_ipaddr_t *host){
  return uip_ipaddr_prefixcmp(&local_prefix, host, local_prefix_len);
}


/*---------------------------------------------------------------------------*/
void
rrpl_request_route_to(uip_ipaddr_t *host)
{

  if(in_rrpl_call){
    return;
  }
#if !RRPL_IS_SINK && USE_OPT
  // Schedule QRY transmission: if we are here, it's because we've lost our default next hop
  if((uip_ds6_defrt_lookup(&def_rt_addr) == NULL)){
    PROCESS_CONTEXT_BEGIN(&rrpl_process);
    lost_defrt_whatnow();
    PROCESS_CONTEXT_END(&rrpl_process) ;
  }
  return ; //only sink sends RREQ
#endif
  if(!rrpl_addr_matches_local_prefix(host)) {
    PRINTF("no RREQ for non-local address\n");
    //no local prefix matches this addr, no RREQ for non-local address
    return ;
  } 
#if RRPL_RREQ_RATELIMIT
  if(!timer_expired(&next_time)) {
     PRINTF("RRPL: RREQ exceeds rate limit"); 
     return ;
  }
#endif

  PRINTF("RRPL: Request for route "); 
  PRINT6ADDR(host);
  PRINTF("\n");
  if(uip_ds6_addr_lookup(host)==NULL)
  {
    uip_ipaddr_copy(&rreq_addr, host);
    command = COMMAND_SEND_RREQ;
    process_post(&rrpl_process, PROCESS_EVENT_MSG, NULL);
#if RRPL_RREQ_RETRIES
    if(!rrc_lookup(&rreq_addr))
    {
   	rrc_add(&rreq_addr);
    }
#endif
  }
  else{
    PRINTF("RRPL: Request for our address. Do nothing\n"); 
  }
#if RRPL_RREQ_RATELIMIT
  timer_set(&next_time, CLOCK_SECOND/RRPL_RREQ_RATELIMIT); 
#endif
}
/*---------------------------------------------------------------------------*/
void
rrpl_no_route(uip_ipaddr_t *dest, uip_ipaddr_t *src)
{
  struct uip_ds6_route *rt = NULL;
  uip_ipaddr_t nexthop;
  uip_ipaddr_t *nexthptr=&nexthop;
  rt = rrpl_route_lookup(src);
  PRINTF("rrpl_no_route(): dest:"); PRINT6ADDR(dest); PRINTF(" src:");PRINT6ADDR(src);PRINTF("\n");
  if(rt == NULL){
    PRINTF("rt is NULL\n");
    #if USE_OPT
    // multicast RERR so the neighbors are notified -- this is helpful if a node has lost memory
    uip_create_linklocal_lln_routers_mcast(nexthptr);
    PRINTF("send to: "); PRINT6ADDR(nexthptr);PRINTF("\n");
    #else
    PRINTF("RRPL: Send a RERR with no route source address\n"); 
    return;
    #endif //USE_OPT
  }
  else{
    nexthptr=uip_ds6_route_nexthop(rt);
  }
  uip_ipaddr_copy(&rerr_bad_addr, dest);
  uip_ipaddr_copy(&rerr_src_addr, src);
  uip_ipaddr_copy(&rerr_next_addr, nexthptr);
  command = COMMAND_SEND_RERR;
  process_post(&rrpl_process, PROCESS_EVENT_MSG, NULL);
}
/*---------------------------------------------------------------------------*/
void
rrpl_set_local_prefix(uip_ipaddr_t *prefix, uint8_t len)
{
  uip_ipaddr_copy(&local_prefix, prefix);
  local_prefix_len = len;
}
/*---------------------------------------------------------------------------*/
void 
get_prefix_from_addr(uip_ipaddr_t *addr, uip_ipaddr_t *prefix, uint8_t len)
{
  uint8_t i;
  local_prefix_len = len; 
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
uint8_t rrpl_is_my_global_address(uip_ipaddr_t *addr){
  int i;
  int state;

  for(i = 0; i < UIP_DS6_ADDR_NB; i++) {
    state = uip_ds6_if.addr_list[i].state;
    if(uip_ds6_if.addr_list[i].isused &&
       (state == ADDR_TENTATIVE || state == ADDR_PREFERRED)) {
       if (uip_ipaddr_cmp(addr, &uip_ds6_if.addr_list[i].ipaddr)){
          return 1 ;
       }
    }  
  }
  return 0;
}

/*---------------------------------------------------------------------------*/
PROCESS_THREAD(rrpl_process, ev, data)
{
  static struct etimer et;
  

  PROCESS_BEGIN();
  PRINTF("RRPL process started\n");
#if RRPL_IS_SINK
  my_seq_id = 1;
  my_rank = 1;
  my_weaklink = 0;
  my_parent_rssi = 126;
  opt_seq_skip_counter = 0;
#else
  my_seq_id = 0;
  my_rank = RRPL_MAX_RANK;
  my_weaklink = 255;
  my_parent_rssi = -126;
#endif
  PRINTF("RRPL is sink:%d \n",(int)RRPL_IS_SINK);
  init_linklist(0);
  my_time_order=0;
  my_hseqno = 1;
  print_local_addresses();
  get_global_addr(&myipaddr);
  get_prefix_from_addr(&myipaddr, &local_prefix, DEFAULT_LOCAL_PREFIX);  
  uip_create_linklocal_lln_routers_mcast(&mcastipaddr);
  uip_create_linklocal_empty_addr(&def_rt_addr);
  uip_ds6_maddr_add(&mcastipaddr);
  /* new connection UDP */
  udpconn = udp_new(NULL, UIP_HTONS(RRPL_UDPPORT), NULL);
  udp_bind(udpconn, UIP_HTONS(RRPL_UDPPORT));

  PRINTF("RRPL: Created an UDP socket  ");
  PRINTF(" local/remote port %u/%u\n",
	UIP_HTONS(udpconn->lport), UIP_HTONS(udpconn->rport));

  if (RRPL_IS_COORDINATOR()) {
    PRINTF("RRPL: Set timer for OPT multicast %lu\n", SEND_INTERVAL);
    etimer_set(&et, SEND_INTERVAL);
    memset(&ipaddr, 0, sizeof(ipaddr));
  }
#if RRPL_RREQ_RETRIES
  PRINTF("RRPL: Set timer for RREQ retry %u\n", RETRY_CHECK_INTERVAL);
  etimer_set(&dfet, RETRY_CHECK_INTERVAL);
#endif
#if RRPL_RREQ_RATELIMIT
  timer_set(&next_time, CLOCK_SECOND/RRPL_RREQ_RATELIMIT); 
#endif
#if RRPL_R_HOLD_TIME
  PRINTF("RRPL: Set timer for route validity time check %u\n", RV_CHECK_INTERVAL);
  etimer_set(&rv, RV_CHECK_INTERVAL);
#endif
  while(1) {
    PROCESS_YIELD();
    
    if(ev == tcpip_event) {
      tcpip_handler();
    }

#if RRPL_IS_COORDINATOR()
    if(etimer_expired(&et)) {
      send_opt();
//       uip_ds6_route_print();
      etimer_restart(&et); 
    }
#endif

#if SND_QRY && ! RRPL_IS_SINK
    if(etimer_expired(&eqryt)) {
      if(uip_ds6_defrt_lookup(&def_rt_addr) == NULL){
        // Still no route, snd qry and reschedule 
        PRINTF("etimer qry expired, send QRY\n");
        send_qry();
      }
    }
#endif // SND_QRY

#if RRPL_RREQ_RETRIES
    if(etimer_expired(&dfet)) {
      rrc_check_expired_rreq(RETRY_CHECK_INTERVAL);
      etimer_restart(&dfet); 
    }
#endif
#if RRPL_R_HOLD_TIME
    if(etimer_expired(&rv)) {
      rrpl_check_expired_route(RV_CHECK_INTERVAL);
      etimer_restart(&rv); 
    }
#endif

    if(ev == PROCESS_EVENT_MSG) {
        if(command == COMMAND_SEND_RREQ) {
            PRINTF("RRPL: Send RREQ\n");
            
            ctimer_set(&sendmsg_ctimer, random_rand()%50 * CLOCK_SECOND / 1000,
                     (void (*)(void *))send_rreq, NULL);  
	} else if (command == COMMAND_SEND_RERR) {
	  send_rerr(&rerr_src_addr, &rerr_bad_addr, &rerr_next_addr);
	}
	command = COMMAND_NONE;
	
    } 

  
  }

  PROCESS_END();
}

#endif /*WITH_IPV6_RRPL*/

/*---------------------------------------------------------------------------*/
