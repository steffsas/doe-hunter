package query

import (
	"net"
	"time"

	"github.com/miekg/dns"
	"github.com/steffsas/doe-hunter/lib/custom_errors"
)

type QueryResponse struct {
	DNSResponse
}

type QueryHandler interface {
	Query(query *DNSQuery) (res *QueryResponse, err error)
}

type DNSResponse struct {
	// Response is the DNS response
	ResponseMsg *dns.Msg `json:"responsemsg"`
	// RTT is the round-trip time
	RTT time.Duration `json:"rtt"`
}

type QueryConfig struct {
	LocalAddr net.IP
}

type DNSQuery struct {
	// Host is the nameserver to query
	Host string `json:"host"`
	// QueryMsg is the DNS message to send
	QueryMsg *dns.Msg `json:"query_msg"`
	// Port is the port number (default: 443)
	Port int `json:"port"`
	// Timeout is the timeout in ms (default: 5000)
	Timeout time.Duration `json:"timeout"`
	// DNSSEC
	DNSSEC bool `json:"dnssec"`
}

// SetDNSSEC sets the DNSSEC flag in the query message
// Do not use this function before marshaling the query but before sending it as a DNS query
func (q *DNSQuery) SetDNSSEC() {
	if q.DNSSEC {
		if q.QueryMsg == nil {
			q.QueryMsg = new(dns.Msg)
		}
		q.QueryMsg.SetEdns0(2048, true)
	}
}

func (q *DNSQuery) Check(checkForTimeout bool) (err custom_errors.DoEErrors) {
	if q.QueryMsg == nil {
		return custom_errors.NewQueryConfigError(custom_errors.ErrEmptyQueryMessage, true)
	}

	return checkForQueryParams(q.Host, q.Port, q.Timeout, checkForTimeout)
}

type DoEQuery struct {
	DNSQuery

	SkipCertificateVerify bool   `json:"skip_certificate_verify"`
	SNI                   string `json:"sni"`
}

type DoEResponse struct {
	DNSResponse

	CertificateVerified bool `json:"certificate_verified"`
	CertificateValid    bool `json:"certificate_valid"`
}
