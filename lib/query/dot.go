package query

import (
	"crypto/tls"
	"net"
	"time"

	"github.com/miekg/dns"
	"github.com/steffsas/doe-hunter/lib/custom_errors"
	"github.com/steffsas/doe-hunter/lib/helper"
)

const DNS_DOT_PROTOCOL = "tcp-tls"
const DEFAULT_DOT_PORT = 853
const DEFAULT_DOT_TIMEOUT time.Duration = 10000 * time.Millisecond

type DoTQuery struct {
	DoEQuery
}

type DoTResponse struct {
	DoEResponse
}

type DefaultDoTQueryHandler struct {
	QueryHandler DoTQueryHandler
}

func (qh *DefaultDoTQueryHandler) Query(query *DoTQuery) (*DoTResponse, custom_errors.DoEErrors) {
	res := &DoTResponse{}

	res.CertificateValid = false
	res.CertificateVerified = false

	if query == nil {
		return res, custom_errors.NewQueryConfigError(custom_errors.ErrQueryNil, true)
	}

	if err := query.Check(true); err != nil {
		return res, err
	}

	if qh.QueryHandler == nil {
		return res, custom_errors.NewGenericError(custom_errors.ErrQueryHandlerNil, true)
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: query.SkipCertificateVerify,
	}

	if query.SNI != "" {
		tlsConfig.ServerName = query.SNI
	}

	query.SetDNSSEC()

	var queryErr error

	var tlsConnState *tls.ConnectionState

	res.ResponseMsg, res.RTT, tlsConnState, queryErr = qh.QueryHandler.Query(
		helper.GetFullHostFromHostPort(query.Host, query.Port),
		query.QueryMsg,
		query.Timeout,
		tlsConfig,
	)

	// check whether connection was ok
	if tlsConnState != nil {
		res.CertificateValid = true
		res.CertificateVerified = tlsConnState.VerifiedChains != nil
		res.TLSVersion = tls.VersionName(tlsConnState.Version)
		res.TLSCipherSuite = tls.CipherSuiteName(tlsConnState.CipherSuite)
	}

	return res, validateCertificateError(
		queryErr,
		custom_errors.NewQueryError(custom_errors.ErrUnknownQuery, true),
		&res.DoEResponse,
		query.SkipCertificateVerify,
	)
}

func NewDoTQuery() (q *DoTQuery) {
	q = &DoTQuery{}

	q.Port = DEFAULT_DOT_PORT
	q.Timeout = DEFAULT_DOT_TIMEOUT

	q.QueryMsg = GetDefaultQueryMsg()

	// set DNSSEC flag by default
	q.DNSSEC = true

	return
}

type DoTQueryHandler interface {
	Query(host string, query *dns.Msg, timeout time.Duration, tlsConfig *tls.Config) (answer *dns.Msg, rtt time.Duration, tlsConnState *tls.ConnectionState, err error)
}

type defaultQueryHandlerDoT struct {
	DialerTCP *net.Dialer
}

func (df *defaultQueryHandlerDoT) Query(host string, query *dns.Msg, timeout time.Duration, tlsConfig *tls.Config) (*dns.Msg, time.Duration, *tls.ConnectionState, error) {
	c := &dns.Client{
		Timeout: timeout,
	}

	tlsDialer := &tls.Dialer{
		NetDialer: df.DialerTCP,
		Config:    tlsConfig,
	}

	// create connection
	conn, err := tlsDialer.Dial("tcp", host)
	if err != nil {
		return nil, 0, nil, err
	}

	// retrieve the tls version and cipher suite
	// parse connection state to tls connection

	tlsConn := conn.(*tls.Conn)

	// handshake
	if err := tlsConn.Handshake(); err != nil {
		return nil, 0, nil, err
	}

	// get the negotiated tls version and cipher suite
	tlsConnState := tlsConn.ConnectionState()

	msg, rtt, err := c.ExchangeWithConn(query, &dns.Conn{Conn: conn})

	return msg, rtt, &tlsConnState, err
}

func NewDefaultDoTHandler(config *QueryConfig) *DefaultDoTQueryHandler {
	qh := &defaultQueryHandlerDoT{
		DialerTCP: &net.Dialer{},
	}

	if config != nil {
		qh.DialerTCP.LocalAddr = &net.TCPAddr{
			IP:   config.LocalAddr,
			Port: 0,
		}
	}

	dqh := &DefaultDoTQueryHandler{
		QueryHandler: qh,
	}

	return dqh
}
