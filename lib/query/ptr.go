package query

import (
	"github.com/miekg/dns"
)

func NewPTRQuery(ip string) (*ConventionalDNSQuery, error) {
	arpa, err := dns.ReverseAddr(ip)
	if err != nil {
		return nil, err
	}

	q := NewConventionalQuery()
	q.QueryMsg = &dns.Msg{}
	q.QueryMsg.SetQuestion(arpa, dns.TypePTR)
	return q, nil
}

func NewPTRQueryHandler(ip string) (q *ConventionalDNSQueryHandler, err error) {
	q = NewConventionalDNSQueryHandler()
	query, err := NewPTRQuery(ip)
	if err != nil {
		return nil, err
	}
	q.QueryObj = *query

	// we use default linux local DNS stub
	q.QueryObj.Host = "127.0.0.53"
	q.QueryObj.Port = 53
	return q, nil
}
