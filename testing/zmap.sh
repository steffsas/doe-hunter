#!/bin/bash
# this file is used to scan the entire ipv4 address space for open ports on 53 udp
# todo: make this more generic, so that it can be used from any directory
logDir="/data/zmap/logs"
outputDir="/data/ipv4"

# we encounter less resolvers when we use a probe file that resolves a domain name 
# that is most probably not in the cache of the resolver, thus the resolver needs more time to resolve the domain
# probe="/data/zmap/dns_53_queryAinit.raiun.de.pkt"
probe="/data/zmap/dns_53_queryAwww.google.com.pkt"
blocklist="/data/zmap/blocklist.conf"

# interface="wlp3s0"
interface="enp5s0"

#gateway="cc:4e:24:d0:f1:80"
gateway="98:9b:cb:cc:c0:2a"

date=$(date +'%Y-%m-%d')

namedPipe="${outputDir}/run-${date}.pipe"
statusFile="${logDir}/status-${date}.log"

# mkfifo (make named pipe)
# we use named pipes because they are a simple way to communicate between processes
# an output to a "normal" file will make zmap quit after a while when in parallel the same file is tailed by another process
# see also https://man7.org/linux/man-pages/man7/pipe.7.html and https://linux.die.net/man/3/mkfifo
mkfifo "${namedPipe}"
# touch "${namedPipe}"

# scan the ipv4 address space, output to named pipe so other processes can read it
zmap \
	-M udp \
   	-p 53 \
   	-b "${blocklist}" \
	-G "${gateway}" \
   	-i "${interface}" \
   	--probe-args="file:${probe}" \
   	--verbosity 5 \
    	"0.0.0.0/0"

echo "stopped at $(date +'%Y-%m-%d %H:%M:%S')" >> "${statusFile}"

# remove named pipe
rm "${namedPipe}"
