#ifndef __PROJECT_CONF_H__
#define __PROJECT_CONF_H__

#undef NETSTACK_CONF_MAC
#define NETSTACK_CONF_MAC     csma_driver
//#define NETSTACK_CONF_MAC     nullmac_driver

#undef NETSTACK_CONF_RDC
#define NETSTACK_CONF_RDC     contikimac_driver
//#define NETSTACK_CONF_RDC     nullrdc_driver


#endif /* __PROJECT_CONF_H__ */