package query

import (
	"github.com/miekg/dns"
)

func NewDDRQuery(host string, port int) *ConventionalDNSQuery {
	q := NewConventionalDNSQuery()

	q.QueryMsg = &dns.Msg{}
	q.QueryMsg.SetQuestion("_dns.resolver.arpa.", dns.TypeSVCB)
	// q.QueryMsg.RecursionDesired = false
	// q.QueryMsg.SetEdns0(4096, true)
	q.Host = host
	q.Port = port
	return q
}
