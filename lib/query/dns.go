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
	DNSResponse
	UDPAttempts int  `json:"udp_attempts"`
	TCPAttempts int  `json:"tcp_attempts"`
	Truncated   bool `json:"truncated"`
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

type ConventionalDNSQueryHandler struct {
	Sleeper      sleeper
	QueryHandler QueryHandlerDNS
	QueryObj     ConventionalDNSQuery
}

func (dq *ConventionalDNSQueryHandler) Query() (response *ConventionalDNSResponse, err error) {
	response = &ConventionalDNSResponse{}
	response.Truncated = false
	response.UDPAttempts = 0
	response.TCPAttempts = 0
	response.QueryMsg = dq.QueryObj.QueryMsg

	if dq.QueryObj.Protocol == "" {
		dq.QueryObj.Protocol = DNS_UDP
	}

	if dq.QueryObj.Timeout >= 0 {
		dq.QueryObj.TimeoutUDP = dq.QueryObj.Timeout
		dq.QueryObj.TimeoutTCP = dq.QueryObj.Timeout
	}

	if dq.QueryObj.TimeoutTCP < 0 && dq.QueryObj.Timeout < 0 {
		dq.QueryObj.TimeoutTCP = DEFAULT_TCP_TIMEOUT
	}

	if dq.QueryObj.TimeoutUDP < 0 && dq.QueryObj.Timeout < 0 {
		dq.QueryObj.TimeoutUDP = DEFAULT_UDP_TIMEOUT
	}

	if dq.QueryObj.Host == "" {
		return response, ErrHostEmpty
	}

	if dq.QueryObj.QueryMsg == nil {
		return response, ErrEmptyQueryMessage
	}

	if dq.QueryHandler == nil {
		return response, ErrQueryHandlerNil
	}

	if dq.QueryObj.Port >= 65536 || dq.QueryObj.Port <= 0 {
		return response, fmt.Errorf("invalid port %d", dq.QueryObj.Port)
	}

	if dq.QueryObj.Protocol != DNS_UDP && dq.QueryObj.Protocol != DNS_TCP {
		return response, fmt.Errorf("invalid protocol %s", dq.QueryObj.Protocol)
	}

	if dq.QueryObj.MaxUDPRetries < 0 {
		dq.QueryObj.MaxUDPRetries = DEFAULT_UDP_RETRIES
	}

	if dq.QueryObj.MaxTCPRetries < 0 {
		dq.QueryObj.MaxTCPRetries = DEFAULT_TCP_RETRIES
	}

	if dq.QueryObj.Protocol == DNS_UDP {
		// create exponential timeout backoff
		b := getBackOffHandler(dq.QueryObj.MaxBackoffTime)

		// +1 because we try at least once even if MaxUDPRetries is 0
		for i := 1; i <= dq.QueryObj.MaxUDPRetries; i++ {
			response.UDPAttempts = i
			response.ResponseMsg, response.RTT, err = dq.QueryHandler.Query(helper.GetFullHostFromHostPort(dq.QueryObj.Host, dq.QueryObj.Port), dq.QueryObj.QueryMsg, DNS_UDP, dq.QueryObj.TimeoutUDP, nil)

			if err == nil && response.ResponseMsg != nil && !response.ResponseMsg.Truncated {
				// we got some valid response, so we can return
				return
			}

			// if response is truncated, we need to retry with TCP [RFC7766]
			if response.ResponseMsg != nil && response.ResponseMsg.Truncated {
				response.Truncated = true
				break
			}

			if i+1 < dq.QueryObj.MaxUDPRetries {
				// sleep for backoff duration since we are going to retry
				dq.Sleeper.Sleep(b.NextBackOff())
			}
		}
	}

	if dq.QueryObj.AutoFallbackTCP || dq.QueryObj.Protocol == DNS_TCP || (response.Truncated && dq.QueryObj.AutoFallbackTCP) {
		// create exponential timeout backoff
		b := getBackOffHandler(dq.QueryObj.MaxBackoffTime)

		// +1 because we try at least once even if MaxTCPRetries is 0
		for i := 1; i <= dq.QueryObj.MaxTCPRetries; i++ {
			response.TCPAttempts = i
			response.ResponseMsg, response.RTT, err = dq.QueryHandler.Query(helper.GetFullHostFromHostPort(dq.QueryObj.Host, dq.QueryObj.Port), dq.QueryObj.QueryMsg, DNS_TCP, dq.QueryObj.TimeoutTCP, nil)

			if err == nil && response.ResponseMsg != nil {
				// we got some valid response, so we can return
				return
			}

			if i+1 < dq.QueryObj.MaxTCPRetries {
				// sleep for backoff duration since we are going to retry
				dq.Sleeper.Sleep(b.NextBackOff())
			}
		}
	}

	if response.ResponseMsg == nil {
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
		QueryObj:     *NewConventionalQuery(),
	}

	query.QueryObj.Timeout = -1 * time.Millisecond
	query.QueryObj.Port = DEFAULT_DNS_PORT

	return query
}

func getBackOffHandler(maxBackoffTime time.Duration) *backoff.ExponentialBackOff {
	b := backoff.NewExponentialBackOff()
	b.InitialInterval = maxBackoffTime
	b.MaxInterval = maxBackoffTime

	return b
}
