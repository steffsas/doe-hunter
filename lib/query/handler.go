package query

import (
	"crypto/tls"
	"net"
	"time"

	"github.com/miekg/dns"
)

type QueryHandlerDNS interface {
	Query(host string, query *dns.Msg, protocol string, timeout time.Duration, tlsConfig *tls.Config) (answer *dns.Msg, rtt time.Duration, err error)
}

type DefaultQueryHandlerDNS struct {
	dialerUDP *net.Dialer
	dialerTCP *net.Dialer
}

func (df *DefaultQueryHandlerDNS) Query(host string, query *dns.Msg, protocol string, timeout time.Duration, tlsConfig *tls.Config) (*dns.Msg, time.Duration, error) {
	c := &dns.Client{
		Timeout:   timeout,
		TLSConfig: tlsConfig,
		Net:       protocol,
	}

	if protocol == "udp" {
		c.Dialer = df.dialerUDP
	} else {
		c.Dialer = df.dialerTCP
	}

	// because Dialer may override dns.Client's timeout
	c.Dialer.Timeout = timeout

	return c.Exchange(query, host)
}

func NewDefaultQueryHandler(config *QueryConfig) *DefaultQueryHandlerDNS {
	qh := &DefaultQueryHandlerDNS{
		dialerUDP: &net.Dialer{},
		dialerTCP: &net.Dialer{},
	}

	if config != nil {
		qh.dialerUDP.LocalAddr = &net.UDPAddr{
			IP:   config.LocalAddr,
			Port: 0,
		}

		qh.dialerTCP.LocalAddr = &net.TCPAddr{
			IP:   config.LocalAddr,
			Port: 0,
		}
	}

	return qh
}
