package lib

import (
	"fmt"
	"net"
)

func GetFullHostFromHostPort(host string, port int) string {
	ip := net.ParseIP(host)
	if ip == nil || ip.To4() != nil {
		// host is not an IP address, so we just combine it like it is a hostname
		return fmt.Sprintf("%s:%d", host, port)
	} else {
		// host is an IPv6 address
		return fmt.Sprintf("[%s]:%d", host, port)
	}
}
