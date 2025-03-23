package query

import (
	"fmt"

	"github.com/miekg/dns"
)

func NewEDSRQuery(targetName string) *ConventionalDNSQuery {
	q := NewConventionalQuery()

	q.QueryMsg.SetQuestion(fmt.Sprintf("_dns.%s", targetName), dns.TypeSVCB)
	// we explicitly do not set the recursive desired flag to false because this will end up in SERVFAIL responses

	// we are not interested in DNSSEC since EDSR runs in a secure channel anyways
	q.DNSSEC = false

	return q
}

func NewEDSRQueryHandler(config *QueryConfig) *ConventionalDNSQueryHandler {
	return NewConventionalDNSQueryHandler(config)
}
