package query

import (
	"crypto/tls"
	"fmt"
	"time"

	"github.com/miekg/dns"
	"github.com/steffsas/doe-hunter/lib/helper"
)

const DNS_DOT_PROTOCOL = "tcp-tls"
const DEFAULT_DOT_PORT = 853
const DEFAULT_DOT_TIMEOUT time.Duration = 5000 * time.Millisecond

type DoTQuery struct {
	DNSQuery

	TLSConfig    *tls.Config `json:"tls_config"`
	QueryHandler QueryHandlerDNS
}

type DoTQueryResponse struct {
	DNSResponse
}

func (q *DoTQuery) Query() (response *DoTQueryResponse, err error) {
	response = &DoTQueryResponse{}
	response.QueryMsg = q.QueryMsg

	if q.Host == "" {
		return response, ErrHostEmpty
	}

	if q.Port >= 65536 || q.Port < 0 {
		return response, fmt.Errorf("invalid port %d", q.Port)
	}

	if q.QueryMsg == nil {
		return response, ErrQueryMsgNil
	}

	if q.QueryHandler == nil {
		return response, ErrQueryHandlerNil
	}

	var res *dns.Msg
	res, response.RTT, err = q.QueryHandler.Query(helper.GetFullHostFromHostPort(q.Host, q.Port), q.QueryMsg, DNS_DOT_PROTOCOL, q.Timeout, q.TLSConfig)
	if err != nil {
		// TODO retry on certificate error
		// certErr := CheckOnCertificateError(err)
		// if certErr {
		// 	// fmt.Println("TODO retry with certificate verification skip")
		// }
		return response, err
	}

	response.ResponseMsg = res

	return response, nil
}

func NewDoTQuery() (q *DoTQuery) {
	q = &DoTQuery{
		QueryHandler: &DefaultQueryHandlerDNS{},
	}

	q.Port = DEFAULT_DOT_PORT
	q.Timeout = DEFAULT_DOT_TIMEOUT

	return
}
