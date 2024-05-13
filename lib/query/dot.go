package query

import (
	"crypto/tls"
	"fmt"
	"time"

	"github.com/steffsas/doe-hunter/lib/helper"
)

const DNS_DOT_PROTOCOL = "tcp-tls"
const DEFAULT_DOT_PORT = 853
const DEFAULT_DOT_TIMEOUT time.Duration = 5000 * time.Millisecond

type DoTQuery struct {
	DNSQuery

	TLSConfig *tls.Config `json:"tls_config"`
}

type DoTQueryResponse struct {
	Response *DNSResponse `json:"response"`
	Query    *DoTQuery    `json:"query"`
}

type DoTQueryHandler struct {
	QueryHandler QueryHandlerDNS
}

func (qh *DoTQueryHandler) Query(query *DoTQuery) (res *DoTQueryResponse, err error) {
	res = &DoTQueryResponse{}
	res.Query = query
	res.Response = &DNSResponse{}

	if query == nil {
		return res, ErrQueryNil
	}

	if query.QueryMsg == nil {
		return res, ErrQueryMsgNil
	}

	if qh.QueryHandler == nil {
		return res, ErrQueryHandlerNil
	}

	if query.Host == "" {
		return res, ErrHostEmpty
	}

	if query.Port >= 65536 || query.Port < 0 {
		return res, fmt.Errorf("invalid port %d", query.Port)
	}

	res.Response.ResponseMsg, res.Response.RTT, err = qh.QueryHandler.Query(
		helper.GetFullHostFromHostPort(query.Host, query.Port),
		query.QueryMsg, DNS_DOT_PROTOCOL,
		query.Timeout,
		query.TLSConfig,
	)

	return
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
