#!/bin/bash
# this file is used to scan the entire ipv4 address space for open ports on 53 udp
# todo: make this more generic, so that it can be used from any directory

zmap \
	-M udp \
   	-p 53 \
   	-b "/data/zmap/blocklist.conf" \
	-G "4a:07:de:5e:0c:1f" \
   	-i $1 \
   	--probe-args="file:/data/zmap/dns_53_queryAinit.raiun.de.pkt" \
   	-o "/data/zmap/results/run-$(date +'%Y-%m-%d').txt" \
   	--verbosity 5 \
    	0.0.0.0/0 &> "/data/zmap/logs/run-$(date +'%Y-%m-%d').log"