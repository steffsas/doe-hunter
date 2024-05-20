package query

import (
	"github.com/miekg/dns"
)

func NewDDRQuery() *ConventionalDNSQuery {
	q := NewConventionalQuery()
	q.QueryMsg = &dns.Msg{}
	q.QueryMsg.SetQuestion("_dns.resolver.arpa.", dns.TypeSVCB)

	// see EDNS0: https://datatracker.ietf.org/doc/html/rfc2671
	// see DNSSEC queries and responses: https://www.ietf.org/rfc/rfc4035
	// A validating security-aware stub resolver MUST set the DO bit,
	// because otherwise it will not receive the DNSSEC RRs it needs to
	// perform signature validation.
	q.QueryMsg.SetEdns0(4096, true)

	return q
}

func NewDDRQueryHandler() *ConventionalDNSQueryHandler {
	return NewConventionalDNSQueryHandler()
}
