package query

import (
	"github.com/miekg/dns"
)

func NewResInfoQuery(targetName string) *ConventionalDNSQuery {
	q := NewConventionalQuery()

	q.QueryMsg.SetQuestion(targetName, dns.TypeRESINFO)

	return q
}

func NewResInfoQueryHandler(config *QueryConfig) *ConventionalDNSQueryHandler {
	return NewConventionalDNSQueryHandler(config)
}
