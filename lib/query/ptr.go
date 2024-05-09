package query

import (
	"github.com/miekg/dns"
)

func NewPTRQuery(ip string) (q *ConventionalDNSQuery, err error) {
	arpa, err := dns.ReverseAddr(ip)
	if err != nil {
		return nil, err
	}

	q = NewConventionalDNSQuery()

	// we use default linux local DNS stub
	q.Host = "127.0.0.53"

	q.QueryMsg = &dns.Msg{}
	q.QueryMsg.SetQuestion(arpa, dns.TypePTR)
	return q, nil
}
