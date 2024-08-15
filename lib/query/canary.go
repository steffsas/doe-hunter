package query

import (
	"github.com/miekg/dns"
)

func NewCanaryQuery(canaryDomain string, host string) *ConventionalDNSQuery {
	q := NewConventionalQuery()

	// note that enabling DNSSEC does not make sense here since _dns.resolver.arpa. is a locally persevered zone without any trust anchor
	// clients have to validate the response by themselves anyway
	q.QueryMsg.SetQuestion(canaryDomain, dns.TypeA)
	// this is important since most authoritative servers will not respond to a query with RD set
	q.QueryMsg.RecursionDesired = false

	// set the host
	q.Host = host
	q.Port = DEFAULT_DNS_PORT

	return q
}

func NewCanaryQueryHandler(config *QueryConfig) *ConventionalDNSQueryHandler {
	return NewConventionalDNSQueryHandler(config)
}
