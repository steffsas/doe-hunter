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

	Sleeper      sleeper
	QueryHandler QueryHandlerDNS

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

func (dq *ConventionalDNSQuery) Query() (response *ConventionalDNSResponse, err error) {
	response = &ConventionalDNSResponse{}
	response.Truncated = false
	response.UDPAttempts = 0
	response.TCPAttempts = 0
	response.QueryMsg = dq.QueryMsg

	if dq.Protocol == "" {
		dq.Protocol = DNS_UDP
	}

	if dq.Timeout >= 0 {
		dq.TimeoutUDP = dq.Timeout
		dq.TimeoutTCP = dq.Timeout
	}

	if dq.TimeoutTCP < 0 && dq.Timeout < 0 {
		dq.TimeoutTCP = DEFAULT_TCP_TIMEOUT
	}

	if dq.TimeoutUDP < 0 && dq.Timeout < 0 {
		dq.TimeoutUDP = DEFAULT_UDP_TIMEOUT
	}

	if dq.Host == "" {
		return response, ErrHostEmpty
	}

	if dq.QueryMsg == nil {
		return response, ErrEmptyQueryMessage
	}

	if dq.QueryHandler == nil {
		return response, ErrQueryHandlerNil
	}

	if dq.Port >= 65536 || dq.Port <= 0 {
		return response, fmt.Errorf("invalid port %d", dq.Port)
	}

	if dq.Protocol != DNS_UDP && dq.Protocol != DNS_TCP {
		return response, fmt.Errorf("invalid protocol %s", dq.Protocol)
	}

	if dq.MaxUDPRetries < 0 {
		dq.MaxUDPRetries = DEFAULT_UDP_RETRIES
	}

	if dq.MaxTCPRetries < 0 {
		dq.MaxTCPRetries = DEFAULT_TCP_RETRIES
	}

	if dq.Protocol == DNS_UDP {
		// create exponential timeout backoff
		b := getBackOffHandler(dq.MaxBackoffTime)

		// +1 because we try at least once even if MaxUDPRetries is 0
		for i := 1; i <= dq.MaxUDPRetries; i++ {
			response.UDPAttempts = i
			response.ResponseMsg, response.RTT, err = dq.QueryHandler.Query(helper.GetFullHostFromHostPort(dq.Host, dq.Port), dq.QueryMsg, DNS_UDP, dq.TimeoutUDP, nil)

			if err == nil && response.ResponseMsg != nil && !response.ResponseMsg.Truncated {
				// we got some valid response, so we can return
				return
			}

			// if response is truncated, we need to retry with TCP [RFC7766]
			if response.ResponseMsg != nil && response.ResponseMsg.Truncated {
				response.Truncated = true
				break
			}

			if i+1 < dq.MaxUDPRetries {
				// sleep for backoff duration since we are going to retry
				dq.Sleeper.Sleep(b.NextBackOff())
			}
		}
	}

	if dq.AutoFallbackTCP || dq.Protocol == DNS_TCP || (response.Truncated && dq.AutoFallbackTCP) {
		// create exponential timeout backoff
		b := getBackOffHandler(dq.MaxBackoffTime)

		// +1 because we try at least once even if MaxTCPRetries is 0
		for i := 1; i <= dq.MaxTCPRetries; i++ {
			response.TCPAttempts = i
			response.ResponseMsg, response.RTT, err = dq.QueryHandler.Query(helper.GetFullHostFromHostPort(dq.Host, dq.Port), dq.QueryMsg, DNS_TCP, dq.TimeoutTCP, nil)

			if err == nil && response.ResponseMsg != nil {
				// we got some valid response, so we can return
				return
			}

			if i+1 < dq.MaxTCPRetries {
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

func NewConventionalDNSQuery() *ConventionalDNSQuery {
	query := &ConventionalDNSQuery{
		QueryHandler:    NewDefaultQueryHandler(),
		Sleeper:         newDefaultSleeper(),
		MaxUDPRetries:   DEFAULT_UDP_RETRIES,
		MaxTCPRetries:   DEFAULT_TCP_RETRIES,
		MaxBackoffTime:  DEFAULT_BACKOFF_TIME,
		TimeoutUDP:      DEFAULT_UDP_TIMEOUT,
		TimeoutTCP:      DEFAULT_TCP_TIMEOUT,
		AutoFallbackTCP: true,
	}

	query.Timeout = -1 * time.Millisecond
	query.Port = DEFAULT_DNS_PORT

	return query
}

func getBackOffHandler(maxBackoffTime time.Duration) *backoff.ExponentialBackOff {
	b := backoff.NewExponentialBackOff()
	b.InitialInterval = maxBackoffTime
	b.MaxInterval = maxBackoffTime

	return b
}
