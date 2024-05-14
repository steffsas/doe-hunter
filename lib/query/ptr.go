package query

import (
	"github.com/miekg/dns"
)

type PTRQuery struct {
	ConventionalDNSQuery
}

func (p *PTRQuery) SetQueryMsg(resolveIp string) (err error) {
	arpa, err := dns.ReverseAddr(resolveIp)

	if p.QueryMsg == nil {
		p.QueryMsg = &dns.Msg{}
	}

	p.QueryMsg.SetQuestion(arpa, dns.TypePTR)

	return err
}

func NewPTRQuery() *PTRQuery {
	q := &PTRQuery{}

	q.ConventionalDNSQuery = *NewConventionalQuery()
	q.QueryMsg = &dns.Msg{}
	q.QueryMsg.SetQuestion("undefined", dns.TypePTR)
	q.Port = DEFAULT_DNS_PORT
	return q
}

func NewPTRQueryHandler() (qh *ConventionalDNSQueryHandler) {
	return NewConventionalDNSQueryHandler()
}
