#!/bin/bash
#

# Move to this example's directory
cd "$(dirname "$0")"

# Set TARGET variable correctly
if test -z "$TARGET"; then
  if test -f Makefile.target; then
    TARGET="$(cat Makefile.target | cut -d' ' -f3)"
  else
    TARGET=sky
  fi
fi

# Files we do not want to keep after compilation, because they contain
# compiled code that depend on LRP_IS_SINK and LRP_IS_COORDINATOR
# macros.
LRP_OBJECT_FILES=$(echo obj_${TARGET}/lrp*.{d,o})

# Compile code, but remove LRP object files just after
if ! make -q udp-server >/dev/null; then
  make udp-server || exit 1
  rm -f $LRP_OBJECT_FILES
fi

if ! make -q udp-client >/dev/null; then
  make udp-client || exit 1
  rm -f $LRP_OBJECT_FILES
fi

if ! make -q relay >/dev/null; then
  make relay || exit 1
  rm -f $LRP_OBJECT_FILES
fi
