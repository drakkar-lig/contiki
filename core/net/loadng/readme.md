This is an implementation of LOADNG, derived from the LRP implementation in
contiki.

LOADNG is enabled when the macro `UIP_CONF_IPV6_LOADNG=1`. (Obviously, one needs
to set `UIP_CONF_IPV6_RPL=0`)

LOADNG is the process `loadng_process`. It needs to be started! Eg. add in the
contiki-main.c file: `process_start(&loadng_process, NULL);`

Set `UIP_ND6_SEND_NA` to 1 if you want to use NS/NA, set it to 0 and LOADNG
determines the link layer address from the link local address (and vice-versa).
Obviously, the objective is to get rid of NS/NA, unless you use nullmac, for
instance.

Many other constants are available and documented in `loadng-def.h`.


So a typical Makefile could look like this:

    CFLAGS += -DUIP_CONF_IPV6_LOADNG=1
    CFLAGS += -DUIP_CONF_IPV6_RPL=0

    #CFLAGS += -DUIP_CONF_ND6_SEND_NA=0
    CFLAGS += -DRESOLV_CONF_SUPPORTS_MDNS=0
    CFLAGS += -DUIP_CONF_ROUTER=1
