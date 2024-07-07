#!/bin/bash
# this file is used to scan the entire ipv4 address space for open ports on 53 udp
# todo: make this more generic, so that it can be used from any directory

tailFile="/data/ipv4/run-$(date +'%Y-%m-%d').log.pipe"

# mkfifo
mkfifo "${tailFile}"

zmap \
	-M udp \
   	-p 53 \
   	-b "/data/zmap/blocklist.conf" \
	-G "4a:07:de:5e:0c:1f" \
   	-i "enp3s0" \
   	--probe-args="file:/data/zmap/dns_53_queryAinit.raiun.de.pkt" \
	--status-updates-file="/data/zmap/logs/status-$(date +'%Y-%m-%d').log" \
   	-o "${tailFile}" \
   	--verbosity 5 \
    	8.8.8.8/32 2> "/data/zmap/logs/error-$(date +'%Y-%m-%d').log.pipe"