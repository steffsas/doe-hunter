package query

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/steffsas/doe-hunter/lib/custom_errors"
	"github.com/steffsas/doe-hunter/lib/helper"
)

const DEFAULT_DOQ_TIMEOUT time.Duration = 5000 * time.Millisecond

// see https://www.rfc-editor.org/rfc/rfc9250.html#section-4.1.1
const DEFAULT_DOQ_PORT = 853

// see https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml
// nolint: gochecknoglobals
var DOQ_TLS_PROTOCOLS = []string{"doq", "dq"}

type QuicConn interface {
	CloseWithError(quic.ApplicationErrorCode, string) error
	OpenStream() (quic.Stream, error)
}

type QuicQueryHandler interface {
	Query(ctx context.Context, addr net.Addr, tlsConf *tls.Config, conf *quic.Config) (QuicConn, error)
}

type DefaultQuicQueryHandler struct {
	Conn net.PacketConn
}

func (d *DefaultQuicQueryHandler) Query(ctx context.Context, addr net.Addr, tlsConf *tls.Config, conf *quic.Config) (QuicConn, error) {
	return quic.Dial(ctx, d.Conn, addr, tlsConf, conf)
}

type DoQResponse struct {
	DoEResponse
}

type DoQQuery struct {
	DoEQuery
}

type DoQQueryHandler struct {
	// QueryHandler is the QUIC dial handler (defaults to quic.DialAddr)
	QueryHandler QuicQueryHandler
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

	if err := query.Check(true); err != nil {
		return res, err
	}

	if qh.QueryHandler == nil {
		return res, custom_errors.NewGenericError(custom_errors.ErrQueryHandlerNil, true)
	}

	tlsConfig := &tls.Config{
		ServerName:         query.Host,
		NextProtos:         DOQ_TLS_PROTOCOLS,
		InsecureSkipVerify: query.SkipCertificateVerify,
	}

	if query.SNI != "" {
		tlsConfig.ServerName = query.SNI
	}

	quicConfig := &quic.Config{
		HandshakeIdleTimeout: query.Timeout,
	}

	query.SetDNSSEC()

	// measure some RTT
	start := time.Now()

	// resolve the target address if necessary
	var udpAddr *net.UDPAddr
	ipAddr := net.ParseIP(query.Host)
	if ipAddr == nil {
		resolvedAddress, err := net.ResolveUDPAddr("udp", helper.GetFullHostFromHostPort(query.Host, query.Port))
		if err != nil {
			return res, custom_errors.NewQueryError(custom_errors.ErrResolveHostFailed, true).AddInfo(err)
		}

		udpAddr = resolvedAddress
	} else {
		udpAddr = &net.UDPAddr{
			IP:   ipAddr,
			Port: query.Port,
		}
	}

	session, err := qh.QueryHandler.Query(
		context.Background(),
		udpAddr,
		tlsConfig,
		quicConfig,
	)
	if err != nil {
		cErr := validateCertificateError(
			err,
			custom_errors.NewQueryError(custom_errors.ErrSessionEstablishmentFailed, true),
			&res.DoEResponse,
			query.SkipCertificateVerify,
		)

		return res, cErr
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
			query.SkipCertificateVerify,
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

	if query.SkipCertificateVerify {
		// we cannot say anything about the certificate validity
		res.CertificateValid = false
		res.CertificateVerified = false
	} else {
		// the certificate must be valid
		res.CertificateValid = true
		res.CertificateVerified = true
	}

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

	q.QueryMsg = GetDefaultQueryMsg()

	// set DNSSEC flag by default
	q.DNSSEC = true

	return
}

func NewDoQQueryHandler(config *QueryConfig) (*DoQQueryHandler, error) {
	qh := &DoQQueryHandler{}

	addr := &net.UDPAddr{}
	if config != nil {
		addr = &net.UDPAddr{
			IP:   config.LocalAddr,
			Port: 0,
		}
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, err
	}

	qh.QueryHandler = &DefaultQuicQueryHandler{
		Conn: conn,
	}

	return qh, nil
}
