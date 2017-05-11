#ifndef __PROJECT_CONF_H__
#define __PROJECT_CONF_H__

#undef NETSTACK_CONF_MAC
//#define NETSTACK_CONF_MAC     csma_driver
#define NETSTACK_CONF_MAC     nullmac_driver

#undef NETSTACK_CONF_RDC
//#define NETSTACK_CONF_RDC     contikimac_driver
#define NETSTACK_CONF_RDC     nullrdc_driver

#define WITH_UIP6 1
#define UIP_CONF_DS6_ADDR_NBU 3

//* Normal
#define RF2XX_TX_POWER           PHY_POWER_5dBm
#define RF2XX_RX_RSSI_THRESHOLD  RF2XX_PHY_RX_THRESHOLD__m101dBm
// */

/* Deaf
#define RF2XX_TX_POWER           PHY_POWER_5dBm
#define RF2XX_RX_RSSI_THRESHOLD  RF2XX_PHY_RX_THRESHOLD__m48dBm
// */

/* Dumb
#define RF2XX_TX_POWER           PHY_POWER_m30dBm
#define RF2XX_RX_RSSI_THRESHOLD  RF2XX_PHY_RX_THRESHOLD__m101dBm
// */


#endif /* __PROJECT_CONF_H__ */
