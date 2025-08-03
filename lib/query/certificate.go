package query

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/steffsas/doe-hunter/lib/custom_errors"
	"github.com/steffsas/doe-hunter/lib/helper"
)

const TLS_PROTOCOL_TCP = "tcp"
const TLS_PROTOCOL_UDP = "udp"

const DEFAULT_TLS_PORT = 443
const DEFAULT_TLS_TIMEOUT time.Duration = 5000 * time.Millisecond

type Conn interface {
	Close() error
	ConnectionState() tls.ConnectionState
}

type CertQueryHandler interface {
	Query(host string, port int, protocol string, timeout time.Duration, tlsConf *tls.Config) (*tls.ConnectionState, error)
}

type DefaultCertQueryHandler struct {
	dialerTCP *net.Dialer
	udpConn   *net.UDPConn
}

func (d *DefaultCertQueryHandler) Query(host string, port int, protocol string, timeout time.Duration, tlsConf *tls.Config) (*tls.ConnectionState, error) {
	if protocol != TLS_PROTOCOL_TCP && protocol != TLS_PROTOCOL_UDP {
		return nil, custom_errors.NewGenericError(custom_errors.ErrUnknownProtocolForTLS, true)
	}

	if protocol == TLS_PROTOCOL_UDP {
		// we cannot use the crypto/tls library as it is specific for TCP
		// dial a QUIC session instead

		quicConfig := &quic.Config{
			HandshakeIdleTimeout: timeout,
		}

		// resolve the target address if necessary
		var udpAddr *net.UDPAddr
		ipAddr := net.ParseIP(host)
		if ipAddr == nil {
			resolvedAddress, err := net.ResolveUDPAddr("udp", helper.GetFullHostFromHostPort(host, port))
			if err != nil {
				return nil, custom_errors.NewQueryError(custom_errors.ErrResolveHostFailed, true).AddInfo(err)
			}

			udpAddr = resolvedAddress
		} else {
			udpAddr = &net.UDPAddr{
				IP:   ipAddr,
				Port: port,
			}
		}

		// establish session
		session, err := quic.Dial(context.Background(), d.udpConn, udpAddr, tlsConf, quicConfig)
		if err != nil {
			return nil, custom_errors.NewQueryError(custom_errors.ErrSessionEstablishmentFailed, true).AddInfo(err)
		}

		// retrieve quic connection state including TLS connection state
		connState := session.ConnectionState()

		// close the session, do not check for errors
		_ = session.CloseWithError(0, "")

		return &connState.TLS, err
	} else {
		d.dialerTCP.Timeout = timeout

		//nolint:all // intentionally using tls.DialWithDialer
		conn, err := tls.DialWithDialer(d.dialerTCP, "tcp", helper.GetFullHostFromHostPort(host, port), tlsConf)
		if err != nil {
			return nil, err
		}

		// retrieve connection information
		connState := conn.ConnectionState()

		// close the connection, do not check for errors
		_ = conn.Close()

		return &connState, err
	}
}

type CertificateQuery struct {
	// Host is the host for the dialer (required)
	Host string `json:"host"`
	// Port is the port for the dialer (default: 443)
	Port int `json:"port"`
	// Protocol is the protocol for the dialer (default: "tcp")
	Protocol string `json:"protocol"`
	// Timeout is the timeout in ms (default: 2500)
	Timeout time.Duration `json:"timeout"`
	// SNI
	SNI string `json:"sni"`
	// ALPN protocol
	ALPN []string `json:"alpn"`
}

func (cq *CertificateQuery) Check() (err custom_errors.DoEErrors) {
	return checkForQueryParams(cq.Host, cq.Port, cq.Timeout, true)
}

type CertificateQueryHandler struct {
	QueryHandler CertQueryHandler
}

type CertificateResponse struct {
	// Certificate is the certificate
	Certificates []*x509.Certificate `json:"certificates"`

	RetryWithoutCertificateVerification bool `json:"retry_without_certificate_verification"`
}

func (qh *CertificateQueryHandler) Query(q *CertificateQuery) (*CertificateResponse, custom_errors.DoEErrors) {
	res := &CertificateResponse{}
	res.RetryWithoutCertificateVerification = false

	if err := q.Check(); err != nil {
		return res, err
	}

	if qh.QueryHandler == nil {
		return res, custom_errors.NewGenericError(custom_errors.ErrQueryHandlerNil, true)
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: false,
	}

	// see https://dl.acm.org/doi/pdf/10.1145/3589334.3645539
	if q.SNI != "" {
		tlsConfig.ServerName = q.SNI
	}

	if len(q.ALPN) > 0 {
		tlsConfig.NextProtos = q.ALPN
	}

	conn, err := qh.QueryHandler.Query(q.Host, q.Port, q.Protocol, q.Timeout, tlsConfig)

	if err != nil {
		if helper.IsCertificateError(err) {
			// we will try to get the certificate without verification
			// codeql [go/disabled-certificate-check]: This is intentional
			res.RetryWithoutCertificateVerification, tlsConfig.InsecureSkipVerify = true, true
			conn, err = qh.QueryHandler.Query(q.Host, q.Port, q.Protocol, q.Timeout, tlsConfig)

			if err != nil {
				return res, custom_errors.NewQueryError(custom_errors.ErrUnknownQuery, true).AddInfo(err)
			}
		} else {
			return res, custom_errors.NewQueryError(custom_errors.ErrUnknownQuery, true).AddInfo(err)
		}
	}
	res.Certificates = conn.PeerCertificates

	return res, nil
}

func NewCertificateQuery() (q *CertificateQuery) {
	return &CertificateQuery{
		Port:     DEFAULT_TLS_PORT,
		Protocol: TLS_PROTOCOL_TCP,
		Timeout:  DEFAULT_TLS_TIMEOUT,
	}
}

func NewCertificateQueryHandler(config *QueryConfig) (*CertificateQueryHandler, error) {
	qh := &CertificateQueryHandler{}

	cqh := &DefaultCertQueryHandler{
		dialerTCP: &net.Dialer{},
	}

	// udp addr for quic
	udpAddr := &net.UDPAddr{}

	if config != nil && config.LocalAddr != nil {
		cqh.dialerTCP.LocalAddr = &net.TCPAddr{
			IP:   config.LocalAddr,
			Port: 0,
		}

		udpAddr = &net.UDPAddr{
			IP:   config.LocalAddr,
			Port: 0,
		}
	}

	var err error
	cqh.udpConn, err = net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, err
	}

	qh.QueryHandler = cqh

	return qh, nil
}
