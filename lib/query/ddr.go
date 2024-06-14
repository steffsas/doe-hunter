package query

import (
	"github.com/miekg/dns"
)

func NewDDRQuery() *ConventionalDNSQuery {
	q := NewConventionalQuery()

	q.QueryMsg.SetQuestion("_dns.resolver.arpa.", dns.TypeSVCB)
	// this is important since most authoritative servers will not respond to a query with RD set
	q.QueryMsg.RecursionDesired = false

	return q
}

func NewDDRQueryHandler(config *QueryConfig) *ConventionalDNSQueryHandler {
	return NewConventionalDNSQueryHandler(config)
}
