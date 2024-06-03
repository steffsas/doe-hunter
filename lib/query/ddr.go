package query

import (
	"github.com/miekg/dns"
)

func NewDDRQuery() *ConventionalDNSQuery {
	q := NewConventionalQuery()

	q.QueryMsg.SetQuestion("_dns.resolver.arpa.", dns.TypeSVCB)
	q.QueryMsg.RecursionDesired = false

	return q
}

func NewDDRQueryHandler(config *QueryConfig) *ConventionalDNSQueryHandler {
	return NewConventionalDNSQueryHandler(config)
}
