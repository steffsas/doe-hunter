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
	dialer *net.Dialer
}

func (df *DefaultQueryHandlerDNS) Query(host string, query *dns.Msg, protocol string, timeout time.Duration, tlsConfig *tls.Config) (answer *dns.Msg, rtt time.Duration, err error) {
	c := &dns.Client{
		Timeout:   timeout,
		TLSConfig: tlsConfig,
		Net:       protocol,
		Dialer:    df.dialer,
	}

	// because Dialer may override dns.Client's timeout
	c.Dialer.Timeout = timeout

	answer, rtt, err = c.Exchange(query, host)

	return
}

func NewDefaultQueryHandler(config *QueryConfig) *DefaultQueryHandlerDNS {
	dialer := &net.Dialer{}
	if config != nil {
		dialer.LocalAddr = &net.UDPAddr{
			IP:   config.LocalAddr,
			Port: 0,
		}
	}
	return &DefaultQueryHandlerDNS{
		dialer: dialer,
	}
}
