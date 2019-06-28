#!/bin/bash

## This script acts as a wrapper around the netif binary. It should be run like this:
## ./netif_wrapper /path/to/netif/ netif_arg1 netif_arg2 netif_arg3

## run all args, which is netif and its args
"$@" &

## get pid of netif
pid=$!

while read line ; do
  :
done

## Kill the pid after (if it's still alive) to stop a zombie process occurring.
if ps -p $pid > /dev/null
then
  kill -KILL $pid
fi