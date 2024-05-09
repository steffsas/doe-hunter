package helper

import (
	"fmt"
	"net"
)

func GetFullHostFromHostPort(host string, port int) string {
	return net.JoinHostPort(host, fmt.Sprintf("%d", port))
}
