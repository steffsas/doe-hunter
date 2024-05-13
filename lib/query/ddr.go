package query

import (
	"github.com/miekg/dns"
)

func NewDDRQuery() *ConventionalDNSQuery {
	q := NewConventionalQuery()
	q.QueryMsg = &dns.Msg{}
	q.QueryMsg.SetQuestion("_dns.resolver.arpa.", dns.TypeSVCB)
	// q.QueryMsg.RecursionDesired = false
	// q.QueryMsg.SetEdns0(4096, true)
	return q
}

func NewDDRQueryHandler() *ConventionalDNSQueryHandler {
	return NewConventionalDNSQueryHandler()
}
