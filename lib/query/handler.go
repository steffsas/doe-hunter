package query

import (
	"crypto/tls"
	"time"

	"github.com/miekg/dns"
)

type QueryHandlerDNS interface {
	Query(host string, query *dns.Msg, protocol string, timeout time.Duration, tlsConfig *tls.Config) (answer *dns.Msg, rtt time.Duration, err error)
}

type DefaultQueryHandlerDNS struct{}

func (df *DefaultQueryHandlerDNS) Query(host string, query *dns.Msg, protocol string, timeout time.Duration, tlsConfig *tls.Config) (answer *dns.Msg, rtt time.Duration, err error) {
	c := new(dns.Client)
	c.Net = protocol
	c.TLSConfig = tlsConfig
	c.Timeout = timeout
	answer, rtt, err = c.Exchange(query, host)

	return
}

func NewDefaultQueryHandler() *DefaultQueryHandlerDNS {
	return &DefaultQueryHandlerDNS{}
}
