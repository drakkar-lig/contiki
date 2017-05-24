#!/bin/bash

lrp() {
  for node in client server; do
    make BIG=y UIP_CONF_IPV6_LRP=1 udp-$node &&\
      scp udp-$node.iotlab-m3 iotlab-grenoble:experiments/use_cases/olrp/configurations/itc_big/ &&\
      make clean ||\
      exit 1
  done
  #for node in client server; do
  #  make DEAF=y UIP_CONF_IPV6_LRP=1 udp-$node &&\
  #    scp udp-$node.iotlab-m3 iotlab-strasbourg:experiments/use_cases/olrp/configurations/itc_deaf/ &&\
  #    make clean ||\
  #    exit 1
  #done
  #for node in client server; do
  #  make MUTED=y UIP_CONF_IPV6_LRP=1 udp-$node &&\
  #    scp udp-$node.iotlab-m3 iotlab-strasbourg:experiments/use_cases/lrp/configurations/itc_muted/ &&\
  #    make clean ||\
  #    exit 1
  #done

  #make DEAF=y DEAF_40=y UIP_CONF_IPV6_LRP=1 udp-client &&\
  #  scp udp-client.iotlab-m3 iotlab-strasbourg:experiments/use_cases/lrp/configurations/itc_deaf/udp-client-40.iotlab-m3 &&\
  #  make clean ||\
  #  exit 1

  #make MUTED=y MUTED_40=y UIP_CONF_IPV6_LRP=1 udp-client &&\
  #  scp udp-client.iotlab-m3 iotlab-strasbourg:experiments/use_cases/lrp/configurations/itc_muted/udp-client-40.iotlab-m3 &&\
  #  make clean ||\
  #  exit 1

  #make MUTED=y MUTED_33=y UIP_CONF_IPV6_LRP=1 udp-client &&\
  #  scp udp-client.iotlab-m3 iotlab-strasbourg:experiments/use_cases/lrp/configurations/itc_muted/udp-client-33.iotlab-m3 &&\
  #  make clean ||\
  #  exit 1
}

olrp() {
  for node in client server; do
    make BIG=y UIP_CONF_IPV6_LRP=1 udp-$node &&\
      scp udp-$node.iotlab-m3 iotlab-grenoble:experiments/use_cases/olrp/configurations/itc_big/ &&\
      make clean ||\
      exit 1
  done
  for node in client server; do
    make DEAF=y UIP_CONF_IPV6_LRP=1 udp-$node &&\
      scp udp-$node.iotlab-m3 iotlab-strasbourg:experiments/use_cases/olrp/configurations/itc_deaf/ &&\
      make clean ||\
      exit 1
  done
  for node in client server; do
    make MUTED=y UIP_CONF_IPV6_LRP=1 udp-$node &&\
      scp udp-$node.iotlab-m3 iotlab-strasbourg:experiments/use_cases/olrp/configurations/itc_muted/ &&\
      make clean ||\
      exit 1
  done

  make DEAF=y DEAF_40=y UIP_CONF_IPV6_LRP=1 udp-client &&\
    scp udp-client.iotlab-m3 iotlab-strasbourg:experiments/use_cases/olrp/configurations/itc_deaf/udp-client-40.iotlab-m3 &&\
    make clean ||\
    exit 1

  make MUTED=y MUTED_40=y UIP_CONF_IPV6_LRP=1 udp-client &&\
    scp udp-client.iotlab-m3 iotlab-strasbourg:experiments/use_cases/olrp/configurations/itc_muted/udp-client-40.iotlab-m3 &&\
    make clean ||\
    exit 1

  make MUTED=y MUTED_33=y UIP_CONF_IPV6_LRP=1 udp-client &&\
    scp udp-client.iotlab-m3 iotlab-strasbourg:experiments/use_cases/olrp/configurations/itc_muted/udp-client-33.iotlab-m3 &&\
    make clean ||\
    exit 1
}

if [ "$(basename $(git symbolic-ref HEAD))" = "itc" ]; then
  echo Compiling LRP
  lrp || exit 1
elif [ "$(basename $(git symbolic-ref HEAD))" = "lrp-iotlab-before" ]; then
  echo Compiling oLRP
  olrp || exit 1
fi

