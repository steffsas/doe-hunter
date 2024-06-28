package query

import (
	"github.com/miekg/dns"
)

func NewDDRQuery() *ConventionalDNSQuery {
	q := NewConventionalQuery()

	// note that enabling DNSSEC does not make sense here since _dns.resolver.arpa. is a locally persevered zone without any trust anchor
	// clients have to validate the response by themselves anyway
	q.QueryMsg.SetQuestion("_dns.resolver.arpa.", dns.TypeSVCB)
	// this is important since most authoritative servers will not respond to a query with RD set
	q.QueryMsg.RecursionDesired = false

	return q
}

func NewDDRQueryHandler(config *QueryConfig) *ConventionalDNSQueryHandler {
	return NewConventionalDNSQueryHandler(config)
}
