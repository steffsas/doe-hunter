package query

import (
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

func (q *DNSQuery) Check() (err *custom_errors.DoEError) {
	const ERROR_LOCATION = "DNSQuery.Check"

	if q.QueryMsg == nil {
		return custom_errors.NewQueryConfigError(custom_errors.ErrEmptyQueryMessage, ERROR_LOCATION)
	}

	if q.Host == "" {
		return custom_errors.NewQueryConfigError(custom_errors.ErrHostEmpty, ERROR_LOCATION)
	}

	if q.Port >= 65536 || q.Port <= 0 {
		return custom_errors.NewQueryConfigError(custom_errors.ErrInvalidPort, ERROR_LOCATION)
	}

	return nil
}

type AbstractQueryHandler interface {
	Query(query interface{}) (res interface{}, err error)
}
