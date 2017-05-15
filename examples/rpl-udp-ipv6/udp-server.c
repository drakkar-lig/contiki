/*
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
 */
/*
 * This file describe a UDP server.
 *
 * Its comportement is to receive a packet from all clients and to answer to
 * them. It is also the RPL sink.
 */

#include "contiki.h"
#include "contiki-net.h"

#include <string.h>

#define DEBUG DEBUG_PRINT
#include "net/ip/uip-debug.h"

#define UIP_IP_BUF   ((struct uip_ip_hdr *)&uip_buf[UIP_LLH_LEN])

#if UIP_CONF_IPV6_RPL
#include "net/rpl/rpl.h"
#endif

static struct uip_udp_conn *server_conn;

PROCESS(udp_server_process, "UDP server process");
AUTOSTART_PROCESSES(&udp_server_process);
/*---------------------------------------------------------------------------*/
#if UIP_CONF_IPV6_RPL
static void
create_rpl_dag(uip_ipaddr_t *ipaddr)
{
  struct uip_ds6_addr *root_if;
  root_if = uip_ds6_addr_lookup(ipaddr);
  if(root_if != NULL) {
    rpl_dag_t *dag;
    uip_ipaddr_t prefix;

    rpl_set_root(RPL_DEFAULT_INSTANCE, ipaddr);
    dag = rpl_get_any_dag();
    uip_ip6addr(&prefix, 0xaaaa, 0, 0, 0, 0, 0, 0, 0);
    rpl_set_prefix(dag, &prefix, 64);
    PRINTF("created a new RPL dag\n");
  } else {
    PRINTF("failed to create a new RPL DAG\n");
  }
}
#endif
/*---------------------------------------------------------------------------*/
#define MAX_PAYLOAD_LEN  40
static char buf[MAX_PAYLOAD_LEN];
static void
tcpip_handler(void)
{
  static int seq_id = 0;

  if(uip_newdata()) {
    ((char *)uip_appdata)[uip_datalen()] = '\0';
    PRINTF("Server received '%s' from ", (char *)uip_appdata);
    PRINT6ADDR(&UIP_IP_BUF->srcipaddr);
    PRINTF("\n");

    /* Ensure we answer with the correct IP address. Contiki does not keep
     * track of the local IP address of sockets ; and the server have more
     * than one address (minima aaaa::1 and the EUI-64-based one). */
    uip_ipaddr_copy(&server_conn->ripaddr, &UIP_IP_BUF->srcipaddr);

    sprintf(buf, "Hello from the server! (%d)", ++seq_id);

    PRINTF("Responding with message: '%s'\n", buf);

    uip_udp_packet_send(server_conn, buf, strlen(buf));

    /* Restore server connection to allow data from any node */
    memset(&server_conn->ripaddr, 0, sizeof(server_conn->ripaddr));
  }
}
/*---------------------------------------------------------------------------*/
static void
print_local_addresses(void)
{
  int i;
  PRINTF("My IPv6 addresses: ");
  for(i = 0; i < UIP_DS6_ADDR_NB; i++) {
    PRINT6ADDR(&uip_ds6_if.addr_list[i].ipaddr);
    if     (uip_ds6_if.addr_list[i].state == ADDR_PREFERRED)  PRINTF("(P)");
    else if(uip_ds6_if.addr_list[i].state == ADDR_TENTATIVE)  PRINTF("(T)");
    else if(uip_ds6_if.addr_list[i].state == ADDR_DEPRECATED) PRINTF("(D)");
    PRINTF("; ");
  }
  PRINTF("\n");
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(udp_server_process, ev, data)
{
  uip_ipaddr_t ipaddr;

  PROCESS_BEGIN();
  PRINTF("UDP server process started\n");

  /* Listen aaaa::<EUI64> address */
  uip_ip6addr(&ipaddr, 0xaaaa, 0, 0, 0, 0, 0, 0, 0);
  uip_ds6_set_addr_iid(&ipaddr, &uip_lladdr);
  uip_ds6_addr_add(&ipaddr, 0, ADDR_AUTOCONF);

  uip_ip6addr(&ipaddr, 0xaaaa, 0, 0, 0, 0, 0, 0, 1);
  uip_ds6_addr_add(&ipaddr, 0, ADDR_AUTOCONF);

  print_local_addresses();

#ifdef CHANNEL
  /* Set channel */
  if (NETSTACK_RADIO.set_value(RADIO_PARAM_CHANNEL, CHANNEL) == RADIO_RESULT_OK) {
    int value;
    NETSTACK_RADIO.get_value(RADIO_PARAM_CHANNEL, &value);
    PRINTF("Using channel %d\n", value);
  } else {
    PRINTF("WARN: Unable to set the radio channel\n");
  }
#endif

#ifdef TX_POWER
  /* Set the TX power */
  if (NETSTACK_RADIO.set_value(RADIO_PARAM_TXPOWER, TX_POWER) == RADIO_RESULT_OK) {
    int value;
    NETSTACK_RADIO.get_value(RADIO_PARAM_TXPOWER, &value);
    PRINTF("Using TX_PWR %ddBm\n", value);
  } else {
    PRINTF("WARN: Unable to set the radio TX power\n");
  }
#endif

#if UIP_CONF_IPV6_RPL
  create_rpl_dag(&ipaddr);
#endif

  /* New connection with remote host */
  server_conn = udp_new(NULL, UIP_HTONS(3001), NULL);
  udp_bind(server_conn, UIP_HTONS(3000));
  PRINTF("Listening clients on UDP port %u\n", UIP_HTONS(server_conn->lport));

  while(1) {
    PROCESS_YIELD();

    /* Incoming client packet */
    if(ev == tcpip_event) {
      tcpip_handler();
    }
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
