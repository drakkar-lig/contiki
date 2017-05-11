# Example using the "Lightweight Routing Protocol"

This example shows a simple usecase of LOADNG. Source code of LOADNG is in
`core/net/loadng/`. To make LOADNG active and RPL inactive, `CONTIKI_WITH_RPL`
is set to 0 and `CONTIKI_WITH_LOADNG` to 1 in the Makefile.

There are three programs that may be flashed in sensors memory, depending on
the sensor role :

* `udp-server` is the sink program. One must have one and only one sensor of
  this type during the experiment, as LOADNG does not yet support multiple-sink
  situations. It must be compiled with flags `LOADNG_IS_SINK` and
  `LOADNG_IS_COORDINATOR` set to 1.

* `udp-client` is the client program. It will send data packets (containing a
  hello message) to the server. The node must be compiled with `LOADNG_IS_SINK`
  set to 0, and `LOADNG_IS_COORDINATOR` may be set to either 0 or 1.

  * The IP address of the sink node is currently hardcoded. It is defined by
    macro `UDP_CONNECTION_ADDR`, and should be set to the correct value.

* `relay` is a router-only node. It won't send data packet from itself at all,
  but will cooperate in the LOADNG network structure. `LOADNG_IS_SINK` must be
  set to 0, and `LOADNG_IS_COORDINATOR` should be set to 1.

*WARNING*: because we have to change `LOADNG_IS_{COORDINATOR,SINK}` values, all
`core/net/loadng/` files must be rebuilt when compiling code for another
program. To compile the three examples, you may want to use the `recompile.sh`
bash script.
