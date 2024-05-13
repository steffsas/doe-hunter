package query

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
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
	Response *DNSResponse `json:"response"`
	Query    *DoQQuery    `json:"query"`
}

type DoQQuery struct {
	DNSQuery

	// TLSConfig is the TLS configuration (defaults to nil which means basic TLS configuration)
	TLSConfig *tls.Config `json:"tls_config"`
	// QuicConfig is the QUIC configuration (defaults to nil which means basic QUIC configuration)
	// The timeout will not be considered since it is given in this struct already and replaced.
	QuicConfig *quic.Config `json:"quic_config"`
}

type DoQQueryHandler struct {
	QueryHandler

	// DialHandler is the QUIC dial handler (defaults to quic.DialAddr)
	DialHandler QuicDialHandler
}

// This DoQ implementation is inspired by the q library, see https://github.com/natesales/q/blob/main/transport/quic.go
func (qh *DoQQueryHandler) Query(query *DoQQuery) (res *DoQResponse, err error) {
	// see RFC https://datatracker.ietf.org/doc/rfc9250/
	// see example implementation https://github.com/natesales/doqd/blob/main/pkg/client/main.go
	res = &DoQResponse{}
	res.Query = query
	res.Response = &DNSResponse{}

	if query == nil {
		return res, ErrQueryMsgNil
	}

	if query.QueryMsg == nil {
		return res, ErrEmptyQueryMessage
	}

	if query.Host == "" {
		return res, ErrHostEmpty
	}

	if query.Port >= 65536 || query.Port < 0 {
		return res, fmt.Errorf("invalid port %d", query.Port)
	}

	// set TLS config with default supported protocols
	if query.TLSConfig == nil {
		query.TLSConfig = &tls.Config{
			NextProtos: DOQ_TLS_PROTOCOLS,
		}
	} else if query.TLSConfig.NextProtos == nil {
		query.TLSConfig.NextProtos = DOQ_TLS_PROTOCOLS
	}

	// set quic config with timeout
	if query.QuicConfig == nil {
		query.QuicConfig = &quic.Config{
			HandshakeIdleTimeout: query.Timeout,
		}
	} else {
		query.QuicConfig.HandshakeIdleTimeout = query.Timeout
	}

	// measure some RTT
	start := time.Now()

	session, err := qh.DialHandler.DialAddr(
		context.Background(),
		helper.GetFullHostFromHostPort(query.Host, query.Port),
		query.TLSConfig,
		query.QuicConfig,
	)
	if err != nil {
		return res, err
	}
	// for linting wrapped in a anon function
	defer func() {
		_ = session.CloseWithError(0, "")
	}()

	// open a stream
	stream, err := session.OpenStream()
	if err != nil {
		return
	}

	// prepare message according to RFC9250
	// https://datatracker.ietf.org/doc/html/rfc9250#section-4.2.1
	query.QueryMsg.Id = 0

	// pack DNS query message
	packedMessage, err := query.QueryMsg.Pack()
	if err != nil {
		return
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
		return
	}

	// The client MUST send the DNS query over the selected stream, and MUST
	// indicate through the STREAM FIN mechanism that no further data will
	// be sent on that stream.
	// https://datatracker.ietf.org/doc/html/rfc9250#section-4.2
	_ = stream.Close()

	// read DNS response message
	response, err := io.ReadAll(stream)
	if err != nil {
		return
	}
	if len(response) == 0 {
		return res, fmt.Errorf("empty response")
	}

	// measure RTT
	res.Response.RTT = time.Since(start)

	// unpack DNS response message
	responseMsg := &dns.Msg{}
	// remove 2-byte prefix
	err = responseMsg.Unpack(response[2:])
	if err != nil {
		return
	}

	res.Response.ResponseMsg = responseMsg

	return
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
	qh.DialHandler = &DefaultQuicDialHandler{}

	return
}
