This is an implementation of LRP, derived from the AODV of contiki. It adds the
construction of a collection tree by means of sending DIO messages, as RPL's
ones.

LRP is enabled when the macro `WITH_IPV6_LRP`==1. (Obviously, one needs to set
`UIP_CONF_IPV6_RPL`=0)

LRP is the process `lrp_process`. It needs to be started! Eg. add in the
contiki-main.c file: `process_start(&lrp_process, NULL);`

`LRP_USE_DIO`: this macro is for the code that is specific to cases where we use
collection tree. If set to false, then LRP works as LOADng.

`LRP_IS_COORDINATOR`: If set to 1, this node will periodically re-send DIO
messages -- set to 0 for a leaf node that will not relay traffic.

`LRP_IS_SINK`: this node will act as a sink -- the LBR should do this (other
nodes start transmitting DIO once they get one from the parent). This cannot be
used with `LRP_IS_COORDINATOR` set to false.

Set `UIP_ND6_SEND_NA` to 1 if you want to use NS/NA, set it to 0 and LRP
determines the link layer address from the link local address (and vice-versa).
Obviously, the objective is to get rid of NS/NA, unless you use nullmac, for
instance.

Many other constants are available and documented in `lrp-def.h`.


So a typical Makefile could look like this:

    CFLAGS += -DWITH_IPV6_LRP=1
    CFLAGS += -DUIP_CONF_IPV6_RPL=0
    
    CFLAGS += -DLRP_IS_COORDINATOR=1
    CFLAGS += -DLRP_IS_SINK=0 # Set to 1 at the sink!
    CFLAGS += -DLRP_USE_DIO=1
    
    #CFLAGS += -DUIP_CONF_ND6_SEND_NA=0
    CFLAGS += -DRESOLV_CONF_SUPPORTS_MDNS=0
    CFLAGS += -DUIP_CONF_ROUTER=1
