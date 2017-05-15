#ifndef __PROJECT_CONF_H__
#define __PROJECT_CONF_H__

#undef NETSTACK_CONF_MAC
#define NETSTACK_CONF_MAC     csma_driver

#undef NETSTACK_CONF_RDC
#define NETSTACK_CONF_RDC     contikimac_driver

#define UIP_CONF_ROUTER           1
#define UIP_CONF_ND6_SEND_NA      0
#define UIP_CONF_ND6_SEND_RA      0
#define RESOLV_CONF_SUPPORTS_MDNS 0
#define WITH_UIP6                 1
#define UIP_CONF_DS6_ADDR_NBU     3
#define RPL_CONF_OF               rpl_mrhof

#undef UIP_CONF_MAX_ROUTES
#define UIP_CONF_MAX_ROUTES 50

#undef NBR_TABLE_CONF_MAX_NEIGHBORS
#define NBR_TABLE_CONF_MAX_NEIGHBORS 20

#ifndef CHANNEL
#define CHANNEL 23
#endif

#ifndef TX_POWER
#define TX_POWER 3
#endif

#endif /* __PROJECT_CONF_H__ */
