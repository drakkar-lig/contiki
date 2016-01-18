#!/bin/bash
#

# Move to this example's directory
OLD_WD="$(pwd)"
cd "$(dirname "$0")"

if test -f Makefile.target; then
  EXTENSION="$(cat Makefile.target | cut -d' ' -f3)"
else
  EXTENSION=sky
fi
OBJECT_FILES=$(echo obj_${EXTENSION}/{tcpip,lrp*}.{d,o})
EXECUTABLES=$(echo ./{relay,udp-client,udp-server}.${EXTENSION})

if ! make -q udp-server; then
  echo "Compiling udp-server"
  make udp-server || exit 1
  rm -f $OBJECT_FILES
fi

if ! make -q udp-client; then
  echo "Compiling udp-client"
  make udp-client || exit 1
  rm -f $OBJECT_FILES
fi

if ! make -q relay; then
  echo "Compiling relay"
  make relay || exit 1
  rm -f $OBJECT_FILES
fi

touch $EXECUTABLES

# First argument (optionnal) describe the directory where we have to put
# executables
if [ "$1" != "" ]; then
  # Destination directory is relative to OLD_WD
  if test "${1:0:1}" = /; then
    DIR="$1"
  else
    DIR="$OLD_WD/$1"
  fi
  if [ -d "$DIR" ]; then
    echo Moving executables to "'$1'"
    cp ${EXECUTABLES} "$DIR"/
  else
    echo >&2 "'$1' n'est pas un dossier…"
  fi
fi
