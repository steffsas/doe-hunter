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

const DEFAULT_DOQ_TIMEOUT = 5000

// see https://www.rfc-editor.org/rfc/rfc9250.html#section-4.1.1
const DEFAULT_DOQ_PORT = 853

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
	DNSResponse
}

type DoQQuery struct {
	DNSQuery

	// DialHandler is the QUIC dial handler (defaults to quic.DialAddr)
	DialHandler QuicDialHandler
	// TLSConfig is the TLS configuration (defaults to nil which means basic TLS configuration)
	TLSConfig *tls.Config `json:"tls_config"`
	// QuicConfig is the QUIC configuration (defaults to nil which means basic QUIC configuration)
	// The timeout will not be considered since it is given in this struct already and replaced.
	QuicConfig *quic.Config `json:"quic_config"`
}

// This DoQ implementation is inspired by the q library, see https://github.com/natesales/q/blob/main/transport/quic.go
func (q *DoQQuery) Query() (res *DoQResponse, err error) {
	// see RFC https://datatracker.ietf.org/doc/rfc9250/
	// see example implementation https://github.com/natesales/doqd/blob/main/pkg/client/main.go

	res = &DoQResponse{}
	res.QueryMsg = q.QueryMsg

	// set TLS config with default supported protocols
	if q.TLSConfig == nil {
		q.TLSConfig = &tls.Config{
			NextProtos: DOQ_TLS_PROTOCOLS,
		}
	} else if q.TLSConfig.NextProtos == nil {
		q.TLSConfig.NextProtos = DOQ_TLS_PROTOCOLS
	}

	// set quic config with timeout
	if q.QuicConfig == nil {
		q.QuicConfig = &quic.Config{
			HandshakeIdleTimeout: time.Duration(q.Timeout) * time.Millisecond,
		}
	} else {
		q.QuicConfig.HandshakeIdleTimeout = time.Duration(q.Timeout) * time.Millisecond
	}

	session, err := q.DialHandler.DialAddr(
		context.Background(),
		helper.GetFullHostFromHostPort(q.Host, q.Port),
		q.TLSConfig,
		q.QuicConfig,
	)
	if err != nil {
		return res, err
	}
	defer func() {
		session.CloseWithError(0, "")
	}()

	// open a stream
	stream, err := session.OpenStream()
	if err != nil {
		return res, fmt.Errorf("open new stream to %s: %v", q.Host, err)
	}

	// prepare message according to RFC9250
	// https://datatracker.ietf.org/doc/html/rfc9250#section-4.2.1
	q.QueryMsg.Id = 0

	// pack DNS query message
	packedMessage, err := q.QueryMsg.Pack()
	if err != nil {
		return res, fmt.Errorf("packing DNS message for %s: %v", q.Host, err)
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
		return res, fmt.Errorf("could not write DNS query on stream to %s: %v", q.Host, err)
	}

	// The client MUST send the DNS query over the selected stream, and MUST
	// indicate through the STREAM FIN mechanism that no further data will
	// be sent on that stream.
	// https://datatracker.ietf.org/doc/html/rfc9250#section-4.2
	_ = stream.Close()

	// read DNS response message
	response, err := io.ReadAll(stream)
	if err != nil {
		return res, fmt.Errorf("could not read DNS response from stream of %s: %v", q.Host, err)
	}
	if len(response) == 0 {
		return res, fmt.Errorf("empty response from %s", q.Host)
	}

	// unpack DNS response message
	responseMsg := &dns.Msg{}
	// remove 2-byte prefix
	err = responseMsg.Unpack(response[2:])
	if err != nil {
		return res, fmt.Errorf("could not unpack DNS response from %s: %v", q.Host, err)
	}

	res.ResponseMsg = responseMsg

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
	q = &DoQQuery{
		DialHandler: &DefaultQuicDialHandler{},
	}

	q.Port = DEFAULT_DOQ_PORT
	q.Timeout = DEFAULT_DOQ_TIMEOUT

	return
}
