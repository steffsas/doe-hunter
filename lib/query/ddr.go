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
	q := NewConventionalDNSQueryHandler()
	q.QueryObj = *NewDDRQuery()
	return q
}

func NewDDRQueryWithServer(host string, port int) *ConventionalDNSQueryHandler {
	q := NewConventionalDNSQueryHandler()
	q.QueryObj = *NewDDRQuery()

	q.QueryObj.Host = host
	q.QueryObj.Port = port
	return q
}
