package query

import (
	"time"

	"github.com/miekg/dns"
)

type QueryResponse struct {
	DNSResponse
}

type QueryHandler interface {
	Query(query *DNSQuery) (res *QueryResponse, err error)
}

type DNSResponse struct {
	// Response is the DNS response
	ResponseMsg *dns.Msg `json:"response"`
	// RTT is the round-trip time
	RTT time.Duration `json:"rtt"`
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
}
