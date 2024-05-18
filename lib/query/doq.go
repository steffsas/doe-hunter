package query

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/steffsas/doe-hunter/lib/custom_errors"
	"github.com/steffsas/doe-hunter/lib/helper"
)

const DEFAULT_DOQ_TIMEOUT time.Duration = 5000 * time.Millisecond

// see https://www.rfc-editor.org/rfc/rfc9250.html#section-4.1.1
const DEFAULT_DOQ_PORT = 853

// nolint: gochecknoglobals
var DOQ_TLS_PROTOCOLS = []string{"doq", "dq"}

type QuicConn interface {
	CloseWithError(quic.ApplicationErrorCode, string) error
	OpenStream() (quic.Stream, error)
}

type QuicDialHandler interface {
	DialAddr(ctx context.Context, addr string, tlsConf *tls.Config, conf *quic.Config) (QuicConn, error)
}

type DefaultQuicDialHandler struct{}

func (d *DefaultQuicDialHandler) DialAddr(ctx context.Context, addr string, tlsConf *tls.Config, conf *quic.Config) (QuicConn, error) {
	return quic.DialAddr(ctx, addr, tlsConf, conf)
}

type DoQResponse struct {
	DoEResponse
}

type DoQQuery struct {
	DoEQuery
}

type DoQQueryHandler struct {
	// QueryHandler is the QUIC dial handler (defaults to quic.DialAddr)
	QueryHandler QuicDialHandler
}

// This DoQ implementation is inspired by the q library, see https://github.com/natesales/q/blob/main/transport/quic.go
func (qh *DoQQueryHandler) Query(query *DoQQuery) (*DoQResponse, custom_errors.DoEErrors) {
	// see RFC https://datatracker.ietf.org/doc/rfc9250/
	// see example implementation https://github.com/natesales/doqd/blob/main/pkg/client/main.go
	res := &DoQResponse{}

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
		NextProtos:         DOQ_TLS_PROTOCOLS,
		InsecureSkipVerify: query.SkipCertificateVerify,
	}

	quicConfig := &quic.Config{
		HandshakeIdleTimeout: query.Timeout,
	}

	// measure some RTT
	start := time.Now()

	session, err := qh.QueryHandler.DialAddr(
		context.Background(),
		helper.GetFullHostFromHostPort(query.Host, query.Port),
		tlsConfig,
		quicConfig,
	)
	if err != nil {
		return res, validateCertificateError(
			err,
			custom_errors.NewQueryError(custom_errors.ErrSessionEstablishmentFailed, true),
			&res.DoEResponse,
		)
	}
	// for linting wrapped in a anon function
	defer func() {
		_ = session.CloseWithError(0, "")
	}()

	// open a stream
	stream, err := session.OpenStream()
	if err != nil {
		return res, validateCertificateError(
			err,
			custom_errors.NewQueryError(custom_errors.ErrOpenStreamFailed, true),
			&res.DoEResponse,
		)
	}

	// prepare message according to RFC9250
	// https://datatracker.ietf.org/doc/html/rfc9250#section-4.2.1
	query.QueryMsg.Id = 0

	// pack DNS query message
	packedMessage, err := query.QueryMsg.Pack()
	if err != nil {
		return res, custom_errors.NewQueryError(custom_errors.ErrDNSPackFailed, true).AddInfo(err)
	}

	// All DNS messages (queries and responses) sent over DoQ connections
	// MUST be encoded as a 2-octet length field followed by the message
	// content as specified in [RFC1035].
	// https://datatracker.ietf.org/doc/html/rfc9250#section-4.2-4
	prefixedMsg := AddQuicPrefix(packedMessage)

	// send DNS query message
	_, err = stream.Write(prefixedMsg)
	if err != nil {
		stream.Close()
		return res, custom_errors.NewQueryError(custom_errors.ErrWriteToStreamFailed, true).AddInfo(err)
	}

	// The client MUST send the DNS query over the selected stream, and MUST
	// indicate through the STREAM FIN mechanism that no further data will
	// be sent on that stream.
	// https://datatracker.ietf.org/doc/html/rfc9250#section-4.2
	_ = stream.Close()

	// read DNS response message
	response, err := io.ReadAll(stream)
	if err != nil {
		return res, custom_errors.NewQueryError(custom_errors.ErrStreamReadFailed, true).AddInfo(err)
	}
	if len(response) == 0 {
		return res, custom_errors.NewQueryError(custom_errors.ErrEmptyStreamResponse, true)
	}

	// measure RTT
	res.RTT = time.Since(start)

	// unpack DNS response message
	responseMsg := &dns.Msg{}
	// remove 2-byte prefix
	err = responseMsg.Unpack(response[2:])
	if err != nil {
		return res, custom_errors.NewQueryError(custom_errors.ErrUnpackFailed, true).AddInfo(err)
	}

	res.ResponseMsg = responseMsg

	return res, nil
}

// AddQuicPrefix adds a 2-byte prefix with the DNS message length.
// see https://datatracker.ietf.org/doc/html/rfc9250#section-4.2-4
func AddQuicPrefix(b []byte) (m []byte) {
	m = make([]byte, 2+len(b))
	binary.BigEndian.PutUint16(m, uint16(len(b)))
	copy(m[2:], b)

	return m
}

func NewDoQQuery() (q *DoQQuery) {
	q = &DoQQuery{}

	q.Port = DEFAULT_DOQ_PORT
	q.Timeout = DEFAULT_DOQ_TIMEOUT

	return
}

func NewDoQQueryHandler() (qh *DoQQueryHandler) {
	qh = &DoQQueryHandler{}
	qh.QueryHandler = &DefaultQuicDialHandler{}

	return
}
