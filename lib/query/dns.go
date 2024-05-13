package query

import (
	"fmt"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/steffsas/doe-hunter/lib/helper"
)

const DNS_UDP = "udp"
const DNS_TCP = "tcp"

const DEFAULT_DNS_PORT = 53
const DEFAULT_UDP_TIMEOUT time.Duration = 2500 * time.Millisecond
const DEFAULT_TCP_TIMEOUT time.Duration = 2500 * time.Millisecond
const DEFAULT_UDP_RETRIES = 3
const DEFAULT_TCP_RETRIES = 1
const DEFAULT_BACKOFF_TIME time.Duration = 2500 * time.Millisecond

type ConventionalDNSResponse struct {
	Response    *DNSResponse          `json:"response"`
	Query       *ConventionalDNSQuery `json:"query"`
	UDPAttempts int                   `json:"udp_attempts"`
	TCPAttempts int                   `json:"tcp_attempts"`
}

type ConventionalDNSQuery struct {
	DNSQuery

	// protocol to use (default: udp)
	Protocol string `json:"protocol"`
	// maximum number of UDP retries (default: 3)
	MaxUDPRetries int `json:"max_udp_retries"`
	// fallback to TCP if UDP fails (default: true)
	AutoFallbackTCP bool `json:"auto_fallback_tcp"`
	// maximum number of TCP retries (default: 1)
	MaxTCPRetries int `json:"max_tcp_retries"`
	// timeout in ms for UDP (default: 2500)
	//
	// if Timeout is set, it will overwrite this value
	TimeoutUDP time.Duration `json:"timeout_udp"`
	// timeout in ms for TCP (default: 2500)
	//
	// if Timeout is set, it will overwrite this value
	TimeoutTCP time.Duration `json:"timeout_tcp"`
	// maximum backoff time in ms (default: 2500)
	MaxBackoffTime time.Duration `json:"max_backoff_time"`
}

type ConventionalDNSQueryHandlerI interface {
	Query(query *ConventionalDNSQuery) (res *ConventionalDNSResponse, err error)
}

type ConventionalDNSQueryHandler struct {
	ConventionalDNSQueryHandlerI

	Sleeper      sleeper
	QueryHandler QueryHandlerDNS
}

func (dq *ConventionalDNSQueryHandler) Query(query *ConventionalDNSQuery) (res *ConventionalDNSResponse, err error) {
	res = &ConventionalDNSResponse{}
	res.Response = &DNSResponse{}
	res.UDPAttempts = 0
	res.TCPAttempts = 0
	res.Query = query

	if query == nil {
		return res, ErrQueryMsgNil
	}

	if query.QueryMsg == nil {
		return res, ErrEmptyQueryMessage
	}

	if query.Protocol == "" {
		query.Protocol = DNS_UDP
	}

	if query.Timeout >= 0 {
		query.TimeoutUDP = query.Timeout
		query.TimeoutTCP = query.Timeout
	}

	if query.TimeoutTCP < 0 && query.Timeout < 0 {
		query.TimeoutTCP = DEFAULT_TCP_TIMEOUT
	}

	if query.TimeoutUDP < 0 && query.Timeout < 0 {
		query.TimeoutUDP = DEFAULT_UDP_TIMEOUT
	}

	if query.Host == "" {
		return res, ErrHostEmpty
	}

	if query.QueryMsg == nil {
		return res, ErrEmptyQueryMessage
	}

	if dq.QueryHandler == nil {
		return res, ErrQueryHandlerNil
	}

	if query.Port >= 65536 || query.Port <= 0 {
		return res, fmt.Errorf("invalid port %d", query.Port)
	}

	if query.Protocol != DNS_UDP && query.Protocol != DNS_TCP {
		return res, fmt.Errorf("invalid protocol %s", query.Protocol)
	}

	if query.MaxUDPRetries < 0 {
		query.MaxUDPRetries = DEFAULT_UDP_RETRIES
	}

	if query.MaxTCPRetries < 0 {
		query.MaxTCPRetries = DEFAULT_TCP_RETRIES
	}

	truncated := false
	if query.Protocol == DNS_UDP {
		// create exponential timeout backoff
		b := getBackOffHandler(query.MaxBackoffTime)

		// +1 because we try at least once even if MaxUDPRetries is 0
		for i := 1; i <= query.MaxUDPRetries; i++ {
			res.UDPAttempts = i
			res.Response.ResponseMsg, res.Response.RTT, err = dq.QueryHandler.Query(
				helper.GetFullHostFromHostPort(query.Host, query.Port),
				query.QueryMsg,
				DNS_UDP,
				query.TimeoutUDP,
				nil,
			)

			if err == nil && res.Response.ResponseMsg != nil && !res.Response.ResponseMsg.Truncated {
				// we got some valid response, so we can return
				return
			}

			// if response is truncated, we need to retry with TCP [RFC7766]
			if res.Response.ResponseMsg != nil && res.Response.ResponseMsg.Truncated {
				truncated = true
				break
			}

			if i+1 < query.MaxUDPRetries {
				// sleep for backoff duration since we are going to retry
				dq.Sleeper.Sleep(b.NextBackOff())
			}
		}
	}

	if query.AutoFallbackTCP || query.Protocol == DNS_TCP || (truncated && query.AutoFallbackTCP) {
		// create exponential timeout backoff
		b := getBackOffHandler(query.MaxBackoffTime)

		// +1 because we try at least once even if MaxTCPRetries is 0
		for i := 1; i <= query.MaxTCPRetries; i++ {
			res.TCPAttempts = i
			res.Response.ResponseMsg, res.Response.RTT, err = dq.QueryHandler.Query(
				helper.GetFullHostFromHostPort(query.Host, query.Port),
				query.QueryMsg,
				DNS_TCP,
				query.TimeoutTCP,
				nil,
			)

			if err == nil && res.Response != nil {
				// we got some valid response, so we can return
				return
			}

			if i+1 < query.MaxTCPRetries {
				// sleep for backoff duration since we are going to retry
				dq.Sleeper.Sleep(b.NextBackOff())
			}
		}
	}

	if res.Response.ResponseMsg == nil {
		err = fmt.Errorf("no response received")
	}

	return
}

func NewConventionalQuery() *ConventionalDNSQuery {
	return &ConventionalDNSQuery{
		Protocol:        DNS_UDP,
		MaxUDPRetries:   DEFAULT_UDP_RETRIES,
		AutoFallbackTCP: true,
		MaxTCPRetries:   DEFAULT_TCP_RETRIES,
		TimeoutUDP:      DEFAULT_UDP_TIMEOUT,
		TimeoutTCP:      DEFAULT_TCP_TIMEOUT,
		MaxBackoffTime:  DEFAULT_BACKOFF_TIME,
	}
}

func NewConventionalDNSQueryHandler() *ConventionalDNSQueryHandler {
	query := &ConventionalDNSQueryHandler{
		QueryHandler: NewDefaultQueryHandler(),
		Sleeper:      newDefaultSleeper(),
	}

	return query
}

func getBackOffHandler(maxBackoffTime time.Duration) *backoff.ExponentialBackOff {
	b := backoff.NewExponentialBackOff()
	b.InitialInterval = maxBackoffTime
	b.MaxInterval = maxBackoffTime

	return b
}
