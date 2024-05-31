package query

import (
	"github.com/miekg/dns"
)

func NewDDRQuery() *ConventionalDNSQuery {
	q := NewConventionalQuery()

	q.QueryMsg.SetQuestion("_dns.resolver.arpa.", dns.TypeSVCB)
	q.QueryMsg.RecursionDesired = false

	prepareDefaultQuery(q.QueryMsg)

	return q
}

func NewDDRQueryHandler() *ConventionalDNSQueryHandler {
	return NewConventionalDNSQueryHandler()
}
