package query

import (
	"fmt"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/sirupsen/logrus"
	"github.com/steffsas/doe-hunter/lib/custom_errors"
	"github.com/steffsas/doe-hunter/lib/helper"
)

const DNS_UDP = "udp"
const DNS_TCP = "tcp"

const DEFAULT_RECURSIVE_RESOLVER = "8.8.8.8"

const DEFAULT_DNS_PORT = 53
const DEFAULT_UDP_TIMEOUT time.Duration = 2500 * time.Millisecond
const DEFAULT_TCP_TIMEOUT time.Duration = 2500 * time.Millisecond
const DEFAULT_UDP_RETRIES = 3
const DEFAULT_TCP_RETRIES = 1
const DEFAULT_BACKOFF_TIME time.Duration = 2500 * time.Millisecond

type ConventionalDNSResponse struct {
	Response      *DNSResponse `json:"response"`
	WasTruncated  bool         `json:"was_truncated"`
	UDPAttempts   int          `json:"udp_attempts"`
	TCPAttempts   int          `json:"tcp_attempts"`
	AttemptErrors []string     `json:"attempt_errors"`
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
	Query(query *ConventionalDNSQuery) (res *ConventionalDNSResponse, err custom_errors.DoEErrors)
}

type ConventionalDNSQueryHandler struct {
	ConventionalDNSQueryHandlerI

	Sleeper      sleeper
	QueryHandler QueryHandlerDNS
}

func (dq *ConventionalDNSQueryHandler) Query(query *ConventionalDNSQuery) (res *ConventionalDNSResponse, err custom_errors.DoEErrors) {
	res = &ConventionalDNSResponse{}
	res.Response = &DNSResponse{}
	res.UDPAttempts = 0
	res.TCPAttempts = 0

	if query == nil {
		return res, custom_errors.NewQueryConfigError(custom_errors.ErrQueryNil, true)
	}

	if err := query.Check(false); err != nil {
		return res, err
	}

	if query.MaxUDPRetries < 0 {
		return res, custom_errors.NewQueryConfigError(custom_errors.ErrInvalidMaxUDPRetries, true).AddInfoString(fmt.Sprintf("max udp retries: %d", query.MaxUDPRetries))
	}

	if query.MaxTCPRetries < 0 {
		return res, custom_errors.NewQueryConfigError(custom_errors.ErrInvalidMaxTCPRetries, true).AddInfoString(fmt.Sprintf("max tcp retries: %d", query.MaxTCPRetries))
	}

	if dq.QueryHandler == nil {
		return res, custom_errors.NewGenericError(custom_errors.ErrQueryHandlerNil, true)
	}

	if query.Protocol != DNS_UDP && query.Protocol != DNS_TCP {
		return res, custom_errors.NewQueryConfigError(custom_errors.ErrInvalidProtocol, true).AddInfoString(fmt.Sprintf("protocol: %s", query.Protocol))
	}

	// override upd and tcp timeouts if query.Timeout is set
	if query.Timeout >= 0 {
		logrus.Warnf("overwriting udp and tcp timeouts with query timeout: %d", query.Timeout)
		query.TimeoutUDP = query.Timeout
		query.TimeoutTCP = query.Timeout
	} else if query.TimeoutUDP < 0 || query.TimeoutTCP < 0 {
		return res, custom_errors.NewQueryConfigError(custom_errors.ErrInvalidTimeout, true).AddInfoString(fmt.Sprintf("timeout (ms): %d", query.Timeout))
	}

	query.SetDNSSEC()

	res.WasTruncated = false
	if query.Protocol == DNS_UDP {
		// create exponential timeout backoff
		b := getBackOffHandler(query.MaxBackoffTime)

		// +1 because we try at least once even if MaxUDPRetries is 0
		for i := 1; i <= query.MaxUDPRetries; i++ {
			var queryErr error
			res.UDPAttempts = i

			start := time.Now()

			res.Response.ResponseMsg, res.Response.RTT, queryErr = dq.QueryHandler.Query(
				helper.GetFullHostFromHostPort(query.Host, query.Port),
				query.QueryMsg,
				DNS_UDP,
				query.TimeoutUDP,
				nil,
			)

			logrus.Debugf("UDP DNS query took %s", time.Since(start))

			if queryErr != nil {
				res.AttemptErrors = append(res.AttemptErrors, queryErr.Error())
			}

			if queryErr == nil && res.Response.ResponseMsg != nil && !res.Response.ResponseMsg.Truncated {
				// we got some valid response, so we can return
				return
			}

			// if response is truncated, we need to retry with TCP [RFC7766]
			if res.Response.ResponseMsg != nil && res.Response.ResponseMsg.Truncated {
				res.WasTruncated = true
				break
			}

			if i+1 < query.MaxUDPRetries {
				// sleep for backoff duration since we are going to retry
				sleepTime := b.NextBackOff()
				logrus.Debugf("sleeping for %s before next retry", sleepTime)
				dq.Sleeper.Sleep(sleepTime)
			}
		}
	}

	if query.AutoFallbackTCP || query.Protocol == DNS_TCP || (res.WasTruncated && query.AutoFallbackTCP) {
		// create exponential timeout backoff
		b := getBackOffHandler(query.MaxBackoffTime)

		// +1 because we try at least once even if MaxTCPRetries is 0
		for i := 1; i <= query.MaxTCPRetries; i++ {
			var queryErr error
			res.TCPAttempts = i
			start := time.Now()
			res.Response.ResponseMsg, res.Response.RTT, queryErr = dq.QueryHandler.Query(
				helper.GetFullHostFromHostPort(query.Host, query.Port),
				query.QueryMsg,
				DNS_TCP,
				query.TimeoutTCP,
				nil,
			)
			logrus.Debugf("TCP DNS query took %s", time.Since(start))

			if queryErr != nil {
				res.AttemptErrors = append(res.AttemptErrors, queryErr.Error())
			}

			if queryErr == nil && res.Response != nil {
				// we got some valid response, so we can return
				return
			}

			if i+1 < query.MaxTCPRetries {
				// sleep for backoff duration since we are going to retry
				// sleep for backoff duration since we are going to retry
				sleepTime := b.NextBackOff()
				logrus.Debugf("sleeping for %s before next retry", sleepTime)
				dq.Sleeper.Sleep(sleepTime)
			}
		}
	}

	if res.Response.ResponseMsg == nil {
		err = custom_errors.NewQueryError(custom_errors.ErrNoResponse, true)
	}

	return
}

func NewConventionalQuery() *ConventionalDNSQuery {
	q := &ConventionalDNSQuery{
		Protocol:        DNS_UDP,
		MaxUDPRetries:   DEFAULT_UDP_RETRIES,
		AutoFallbackTCP: true,
		MaxTCPRetries:   DEFAULT_TCP_RETRIES,
		TimeoutUDP:      DEFAULT_UDP_TIMEOUT,
		TimeoutTCP:      DEFAULT_TCP_TIMEOUT,
		MaxBackoffTime:  DEFAULT_BACKOFF_TIME,
	}
	// because we'll take the timeoutUDP and timeoutTCP as the default timeout
	q.Timeout = -1

	q.Port = DEFAULT_DNS_PORT

	q.QueryMsg = GetDefaultQueryMsg()

	// set DNSSEC flag by default
	q.DNSSEC = true

	return q
}

func NewConventionalDNSQueryHandler(config *QueryConfig) *ConventionalDNSQueryHandler {
	query := &ConventionalDNSQueryHandler{
		QueryHandler: NewDefaultQueryHandler(config),
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
