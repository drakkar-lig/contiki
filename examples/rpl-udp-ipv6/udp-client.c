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
 * This file describe a UDP client.
 *
 * Its comportement is to send a packet one time every SEND_INTERVAL, with a
 * jitter (SEND_JITTER), to the destination [aaaa::1]:3000.
 */

#include "contiki.h"
#include "contiki-net.h"

#include <string.h>
#include <stdbool.h>
#include <inttypes.h>

#include "net/ip/uip.h"
#define DEBUG DEBUG_PRINT
#include "net/ip/uip-debug.h"

#define SEND_INTERVAL    300 * CLOCK_SECOND
#define SEND_JITTER      30 * CLOCK_SECOND

static struct uip_udp_conn *client_conn;
static uip_ipaddr_t server_ipaddr;
/*---------------------------------------------------------------------------*/
PROCESS(udp_client_process, "UDP client process");
AUTOSTART_PROCESSES(&udp_client_process);
/*---------------------------------------------------------------------------*/
static void
tcpip_handler(void)
{
  char *str;

  if(uip_newdata()) {
    str = uip_appdata;
    str[uip_datalen()] = '\0';
    PRINTF("Response from the server: '%s'\n", str);
  }
}
/*---------------------------------------------------------------------------*/
#define MAX_PAYLOAD_LEN  40
static char buf[MAX_PAYLOAD_LEN];
static void
timeout_handler(void)
{
  static uint16_t seq_id = 0;
  uip_ipaddr_t my_ipaddr = {{ 0 }};
  int i;
  for(i = 0; i < UIP_DS6_ADDR_NB; i++)
    if(uip_ds6_if.addr_list[i].isused &&
       uip_ds6_if.addr_list[i].state == ADDR_PREFERRED)
      uip_ipaddr_copy(&my_ipaddr, &uip_ds6_if.addr_list[i].ipaddr);

  sprintf(buf, "Hello %" PRIu16 " from client %02x%02x", ++seq_id, my_ipaddr.u8[14], my_ipaddr.u8[15]);

  PRINTF("Client sending to: ");
  PRINT6ADDR(&server_ipaddr);
  PRINTF(" (msg: %s)\n", buf);

  uip_udp_packet_sendto(client_conn, buf, strlen(buf), &server_ipaddr, UIP_HTONS(3000));
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
PROCESS_THREAD(udp_client_process, ev, data)
{
  static struct etimer et;
  uip_ipaddr_t ipaddr;

  PROCESS_BEGIN();
  PRINTF("UDP client process started\n");

  /* Listen aaaa::<EUI64> address */
  uip_ip6addr(&ipaddr, 0xaaaa, 0, 0, 0, 0, 0, 0, 0);
  uip_ds6_set_addr_iid(&ipaddr, &uip_lladdr);
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

  /* New connection with remote host */
  uip_ip6addr(&server_ipaddr, 0xaaaa, 0, 0, 0, 0, 0, 0, 1);
  client_conn = udp_new(NULL, UIP_HTONS(3000), NULL);
  udp_bind(client_conn, UIP_HTONS(3001));
  PRINTF("Created a connection with the server [");
  PRINT6ADDR(&server_ipaddr);
  PRINTF("]:%u (local port %u)\n",
         UIP_HTONS(client_conn->rport), UIP_HTONS(client_conn->lport));

  /* First packet is sent randomly between 0 and SEND_INTERVAL */
  etimer_set(&et,  random_rand() % SEND_INTERVAL);

  /* Main loop */
  while(1) {
    PROCESS_YIELD();

    /* Send packet event */
    if(etimer_expired(&et)) {
      /* Outgoing packet */
      timeout_handler();
      /* Reset timer, taking jitter into account */
      etimer_set(&et, SEND_INTERVAL + (random_rand() % SEND_JITTER) - SEND_JITTER / 2);
    }

    /* Incoming server packet */
    if(ev == tcpip_event) {
      tcpip_handler();
    }
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
