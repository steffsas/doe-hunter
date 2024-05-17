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
const TLS_PORT = 443
const TLS_DEFAULT_TIMEOUT time.Duration = 2500 * time.Millisecond

type Conn interface {
	Close() error
	ConnectionState() tls.ConnectionState
}

type DialHandler interface {
	DialWithDialer(dialer *net.Dialer, network string, port string, tlsConf *tls.Config) (Conn, error)
}

type defaultDialHandler struct{}

func (d *defaultDialHandler) DialWithDialer(dialer *net.Dialer, network string, host string, tlsConf *tls.Config) (Conn, error) {
	return tls.DialWithDialer(dialer, network, host, tlsConf)
}

type CertificateQuery struct {
	SkipCertificateVerify bool `json:"skip_certificate_verify"`
	// Host is the host for the dialer (required)
	Host string `json:"host"`
	// Port is the port for the dialer (default: 443)
	Port int `json:"port"`
	// Protocol is the protocol for the dialer (default: "tcp")
	Protocol string `json:"protocol"`
	// Timeout is the timeout in ms (default: 2500)
	Timeout time.Duration `json:"timeout"`
}

func (cq *CertificateQuery) Check() (err custom_errors.DoEErrors) {
	return checkForQueryParams(cq.Host, cq.Port, cq.Timeout)
}

type CertificateQueryHandler struct {
	QueryHandler DialHandler
}

type CertificateResponse struct {
	DoEResponse
	// Certificate is the certificate
	Certificates []*x509.Certificate `json:"certificates"`
}

func (qh *CertificateQueryHandler) Query(q *CertificateQuery) (*CertificateResponse, custom_errors.DoEErrors) {
	res := &CertificateResponse{}

	res.CertificateValid = false
	res.CertificateVerified = false

	if err := q.Check(); err != nil {
		return res, err
	}

	if qh.QueryHandler == nil {
		return res, custom_errors.NewGenericError(custom_errors.ErrQueryHandlerNil, true)
	}

	dialer := &net.Dialer{
		Timeout: q.Timeout,
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: q.SkipCertificateVerify,
	}

	conn, err := qh.QueryHandler.DialWithDialer(dialer, "tcp", helper.GetFullHostFromHostPort(q.Host, q.Port), tlsConfig)
	if err != nil {
		if q.SkipCertificateVerify {
			return res, custom_errors.NewQueryError(custom_errors.ErrUnknownQueryErr, true).AddInfo(err)
		} else {
			return res, validateCertificateError(
				err,
				custom_errors.NewQueryError(custom_errors.ErrUnknownQueryErr, true).AddInfo(err),
				&res.DoEResponse,
			)
		}

	}
	defer conn.Close()

	res.Certificates = conn.ConnectionState().PeerCertificates

	return res, nil
}

func NewCertificateQuery() (q *CertificateQuery) {
	return &CertificateQuery{
		Port:     TLS_PORT,
		Protocol: TLS_PROTOCOL_TCP,
		Timeout:  TLS_DEFAULT_TIMEOUT,
	}
}

func NewCertificateQueryHandler() (qh *CertificateQueryHandler) {
	qh = &CertificateQueryHandler{
		QueryHandler: &defaultDialHandler{},
	}

	return
}
