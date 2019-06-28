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

## Kill the pid after to stop a zombie process occurring.
kill -KILL $pid