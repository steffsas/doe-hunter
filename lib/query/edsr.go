package query

import (
	"fmt"

	"github.com/miekg/dns"
)

func NewEDSRQuery(targetName string) *ConventionalDNSQuery {
	q := NewConventionalQuery()

	q.QueryMsg.SetQuestion(fmt.Sprintf("_dns.%s", targetName), dns.TypeSVCB)
	q.QueryMsg.RecursionDesired = false

	// we are not interested in DNSSEC since EDSR runs in a secure channel anyways
	q.DNSSEC = false

	return q
}

func NewEDSRQueryHandler(config *QueryConfig) *ConventionalDNSQueryHandler {
	return NewConventionalDNSQueryHandler(config)
}
