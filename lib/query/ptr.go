package query

import (
	"github.com/miekg/dns"
)

func NewPTRQuery(resolveIP string, host string) (*ConventionalDNSQuery, error) {
	arpa, err := dns.ReverseAddr(resolveIP)
	if err != nil {
		return nil, err
	}

	q := NewConventionalQuery()
	q.QueryMsg = &dns.Msg{}
	q.QueryMsg.SetQuestion(arpa, dns.TypePTR)
	q.Host = host
	q.Port = DEFAULT_DNS_PORT
	return q, nil
}

func NewPTRQueryHandler() (qh *ConventionalDNSQueryHandler) {
	return NewConventionalDNSQueryHandler()
}
