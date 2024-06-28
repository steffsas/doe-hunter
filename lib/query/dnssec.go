package query

import (
	"fmt"

	"github.com/miekg/dns"
)

func NewDNSSECQuery(targetName string) *ConventionalDNSQuery {
	q := NewConventionalQuery()

	q.QueryMsg.SetQuestion(fmt.Sprintf("_dns.%s", targetName), dns.TypeSVCB)
	// we explicitly do not set the recurive desired flag to false because this will end up in SERVFAIL responses

	// we are not interested in DNSSEC since EDSR runs in a secure channel anyways
	q.DNSSEC = true

	return q
}

func NewDNSSECQueryHandler(config *QueryConfig) *ConventionalDNSQueryHandler {
	return NewConventionalDNSQueryHandler(config)
}
