package query

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"time"

	"github.com/steffsas/doe-hunter/lib/custom_errors"
	"github.com/steffsas/doe-hunter/lib/helper"
)

const TLS_PROTOCOL_TCP = "tcp"
const TLS_PROTOCOL_UDP = "udp"
const DEFAULT_TLS_PORT = 443
const DEFAULT_TLS_TIMEOUT time.Duration = 2500 * time.Millisecond

type Conn interface {
	Close() error
	ConnectionState() tls.ConnectionState
}

type CertQueryHandler interface {
	Query(port string, timeout time.Duration, tlsConf *tls.Config) (Conn, error)
}

type DefaultCertQueryHandler struct {
	dialer *net.Dialer
}

func (d *DefaultCertQueryHandler) Query(host string, timeout time.Duration, tlsConf *tls.Config) (Conn, error) {
	d.dialer.Timeout = timeout
	return tls.DialWithDialer(d.dialer, "tcp", host, tlsConf)
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

	conn, err := qh.QueryHandler.Query(helper.GetFullHostFromHostPort(q.Host, q.Port), q.Timeout, tlsConfig)

	if err != nil {
		if helper.IsCertificateError(err) {
			// we will try to get the certificate without verification
			res.RetryWithoutCertificateVerification, tlsConfig.InsecureSkipVerify = true, true
			conn, err = qh.QueryHandler.Query(helper.GetFullHostFromHostPort(q.Host, q.Port), q.Timeout, tlsConfig)

			if err != nil {
				return res, custom_errors.NewQueryError(custom_errors.ErrUnknownQuery, true).AddInfo(err)
			}
		} else {
			return res, custom_errors.NewQueryError(custom_errors.ErrUnknownQuery, true).AddInfo(err)
		}
	}
	defer conn.Close()

	res.Certificates = conn.ConnectionState().PeerCertificates

	return res, nil
}

func NewCertificateQuery() (q *CertificateQuery) {
	return &CertificateQuery{
		Port:     DEFAULT_TLS_PORT,
		Protocol: TLS_PROTOCOL_TCP,
		Timeout:  DEFAULT_TLS_TIMEOUT,
	}
}

func NewCertificateQueryHandler(config *QueryConfig) *CertificateQueryHandler {
	qh := &CertificateQueryHandler{}

	cqh := &DefaultCertQueryHandler{
		dialer: &net.Dialer{},
	}

	if config != nil {
		cqh.dialer.LocalAddr = &net.TCPAddr{
			IP:   config.LocalAddr,
			Port: 0,
		}
	}

	qh.QueryHandler = cqh

	return qh
}
