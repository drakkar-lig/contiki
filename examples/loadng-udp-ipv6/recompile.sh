#!/bin/bash
#

shopt -s extglob

# Move to this example's directory
cd "$(dirname "$0")" || exit

# Set TARGET variable correctly
if test -z "$TARGET"; then
  if test -f Makefile.target; then
    TARGET="$(cut -d' ' -f3 Makefile.target)"
  else
    TARGET=native
  fi
fi
export TARGET

# Files we do not want to keep after compilation, because they contain
# compiled code that depend on LOADNG_IS_SINK and LOADNG_IS_COORDINATOR
# macros.
LOADNG_OBJECT_FILES="obj_${TARGET}"/'loadng*.@(d|o)'

# Compile code, but remove LOADNG object files just after
if ! make -q udp-server >/dev/null; then
  make udp-server || exit 1
  rm -v $LOADNG_OBJECT_FILES
fi

if ! make -q udp-client >/dev/null; then
  make udp-client || exit 1
  rm -v $LOADNG_OBJECT_FILES
fi

if ! make -q relay >/dev/null; then
  make relay || exit 1
  rm -f "$LOADNG_OBJECT_FILES"
fi
