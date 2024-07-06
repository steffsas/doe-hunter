#!/bin/bash
# this file is used to scan the entire ipv4 address space for open ports on 53 udp
# todo: make this more generic, so that it can be used from any directory

# should provide argument interface name
if [ $# -eq 0 ]; then
    echo "No arguments provided. Please provide the interface name."
    exit 1
fi

# check if the interface exists
ip addr | grep $1 &> /dev/null
if [ $? -ne 0 ]; then
    echo "Interface $1 does not exist."
    exit 1
fi

zmap \
-M udp \
   	-p 53 \
   	-b "/data/zmap/blocklist.conf" \
   	-i $1 \
   	--probe-args="file:/data/zmap/dns_53_queryAinit.raiun.de.pkt" \
   	-o "/data/zmap/results/run-$(date +'%Y-%m-%d').txt" \
   	--verbosity 5 \
    	0.0.0.0/0 &> "/data/zmap/logs/run-$(date +'%Y-%m-%d').log"