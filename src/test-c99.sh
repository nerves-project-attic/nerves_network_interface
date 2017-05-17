#!/bin/sh

if [ -z $CC ]; then
  CC=cc
fi

# See Makefile
printf '#include <arpa/inet.h>\n#include <net/if.h>\n#include <linux/if.h>\nint main(int argc,char*argv[]) { return IFF_UP; }' | $CC -std=c99 -D_XOPEN_SOURCE=600 -o /dev/null -xc - 2>/dev/null && printf "yes"

