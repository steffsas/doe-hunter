package query

import (
	"crypto/tls"
	"time"

	"github.com/steffsas/doe-hunter/lib/custom_errors"
	"github.com/steffsas/doe-hunter/lib/helper"
)

const DNS_DOT_PROTOCOL = "tcp-tls"
const DEFAULT_DOT_PORT = 853
const DEFAULT_DOT_TIMEOUT time.Duration = 5000 * time.Millisecond

type DoTQuery struct {
	DNSQuery

	SkipCertificateVerify bool `json:"skip_certificate_verify"`
}

type DoTResponse struct {
	DoEResponse
}

type DoTQueryHandler struct {
	QueryHandler QueryHandlerDNS
}

func (qh *DoTQueryHandler) Query(query *DoTQuery) (*DoTResponse, custom_errors.DoEErrors) {
	res := &DoTResponse{}

	res.CertificateValid = false
	res.CertificateVerified = false

	if query == nil {
		return res, custom_errors.NewQueryConfigError(custom_errors.ErrQueryNil, true)
	}

	if err := query.Check(); err != nil {
		return res, err
	}

	if qh.QueryHandler == nil {
		return res, custom_errors.NewGenericError(custom_errors.ErrQueryHandlerNil, true)
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: query.SkipCertificateVerify,
	}

	var queryErr error
	res.ResponseMsg, res.RTT, queryErr = qh.QueryHandler.Query(
		helper.GetFullHostFromHostPort(query.Host, query.Port),
		query.QueryMsg, DNS_DOT_PROTOCOL,
		query.Timeout,
		tlsConfig,
	)

	return res, validateCertificateError(
		queryErr,
		custom_errors.NewQueryError(custom_errors.ErrUnknownQueryErr, true).AddInfo(queryErr),
		&res.DoEResponse,
	)
}

func NewDoTQuery() (q *DoTQuery) {
	q = &DoTQuery{}

	q.Port = DEFAULT_DOT_PORT
	q.Timeout = DEFAULT_DOT_TIMEOUT

	return
}

func NewDoTQueryHandler() (h *DoTQueryHandler) {
	h = &DoTQueryHandler{}
	h.QueryHandler = NewDefaultQueryHandler()

	return
}
