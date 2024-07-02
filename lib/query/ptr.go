package query

import (
	"fmt"

	"github.com/miekg/dns"
	"github.com/steffsas/doe-hunter/lib/custom_errors"
)

type PTRQuery struct {
	ConventionalDNSQuery
}

func (p *PTRQuery) SetQueryMsg(resolveIp string) custom_errors.DoEErrors {
	arpa, err := dns.ReverseAddr(resolveIp)

	if err != nil {
		return custom_errors.NewQueryConfigError(
			custom_errors.ErrFailedToReverseIP, true).
			AddInfoString(fmt.Sprintf("reverse addr: %s, got err %s", resolveIp, err.Error()))
	}

	if p.QueryMsg == nil {
		p.QueryMsg = GetDefaultQueryMsg()
	}

	p.QueryMsg.SetQuestion(arpa, dns.TypePTR)

	return nil
}

func NewPTRQuery() *PTRQuery {
	q := &PTRQuery{}

	q.ConventionalDNSQuery = *NewConventionalQuery()
	q.QueryMsg = GetDefaultQueryMsg()
	q.QueryMsg.SetQuestion("undefined", dns.TypePTR)
	q.Port = DEFAULT_DNS_PORT
	q.Host = DEFAULT_RECURSIVE_RESOLVER
	q.QueryMsg.RecursionDesired = true

	// set DNSSEC flag by default
	q.DNSSEC = true

	return q
}

func NewPTRQueryHandler(config *QueryConfig) (qh *ConventionalDNSQueryHandler) {
	return NewConventionalDNSQueryHandler(config)
}
