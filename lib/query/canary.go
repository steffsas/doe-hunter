package query

import (
	"github.com/miekg/dns"
)

func NewCanaryQuery(canaryDomain string, host string) *ConventionalDNSQuery {
	q := NewConventionalQuery()

	// note that enabling DNSSEC does not make sense here since _dns.resolver.arpa. is a locally persevered zone without any trust anchor
	// clients have to validate the response by themselves anyway
	q.QueryMsg.SetQuestion(canaryDomain, dns.TypeA)
	q.QueryMsg.RecursionDesired = true

	// set the host
	q.Host = host
	q.Port = DEFAULT_DNS_PORT

	return q
}

func NewCanaryQueryHandler(config *QueryConfig) *ConventionalDNSQueryHandler {
	return NewConventionalDNSQueryHandler(config)
}
