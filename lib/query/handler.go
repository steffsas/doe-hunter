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

func (df *DefaultQueryHandlerDNS) Query(host string, query *dns.Msg, protocol string, timeout time.Duration, tlsConfig *tls.Config) (answer *dns.Msg, rtt time.Duration, err error) {
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

	answer, rtt, err = c.Exchange(query, host)

	return
}

func NewDefaultQueryHandler(config *QueryConfig) *DefaultQueryHandlerDNS {
	qh := &DefaultQueryHandlerDNS{}

	if config != nil {
		dialerUDP := &net.Dialer{}
		dialerUDP.LocalAddr = &net.UDPAddr{
			IP:   config.LocalAddr,
			Port: 0,
		}

		dialerTCP := &net.Dialer{}
		dialerTCP.LocalAddr = &net.TCPAddr{
			IP:   config.LocalAddr,
			Port: 0,
		}

		qh.dialerUDP = dialerUDP
		qh.dialerTCP = dialerTCP
	}

	return qh
}
