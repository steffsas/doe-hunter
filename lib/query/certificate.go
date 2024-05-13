package query

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"time"

	"github.com/steffsas/doe-hunter/lib/helper"
)

const TLS_PROTOCOL_TCP = "tcp"
const TLS_PROTOCOL_UDP = "udp"
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
	DialHandler DialHandler

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

type CertificateQueryHandler struct {
	QueryHandler DialHandler
}

type CertificateResponse struct {
	// Certificate is the certificate
	Certificates []*x509.Certificate `json:"certificates"`
}

func (qh *CertificateQueryHandler) Query(q *CertificateQuery) (response *CertificateResponse, err error) {
	response = &CertificateResponse{}

	if q.Host == "" {
		err = fmt.Errorf("host is empty")
		return
	}

	if q.Port >= 65536 || q.Port <= 0 {
		err = fmt.Errorf("invalid port %d", q.Port)
		return
	}

	if q.Protocol != TLS_PROTOCOL_TCP && q.Protocol != TLS_PROTOCOL_UDP {
		err = fmt.Errorf("invalid protocol %s", q.Protocol)
		return
	}

	if q.DialHandler == nil {
		err = fmt.Errorf("dial handler is nil")
		return
	}

	if q.Timeout < 0 {
		q.Timeout = TLS_DEFAULT_TIMEOUT
	}

	dialer := &net.Dialer{
		Timeout: q.Timeout,
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: q.SkipCertificateVerify,
	}

	conn, err := q.DialHandler.DialWithDialer(dialer, "tcp", helper.GetFullHostFromHostPort(q.Host, q.Port), tlsConfig)
	if err != nil {
		err = fmt.Errorf("failed to dial: %w", err)
		return
	}
	defer conn.Close()

	response.Certificates = conn.ConnectionState().PeerCertificates

	return response, nil
}

func NewCertificateQuery() (q *CertificateQuery) {
	q = &CertificateQuery{
		DialHandler: &defaultDialHandler{},
	}

	q.Protocol = TLS_PROTOCOL_TCP
	q.Timeout = TLS_DEFAULT_TIMEOUT

	return
}

func NewCertificateQueryHandler() (qh *CertificateQueryHandler) {
	qh = &CertificateQueryHandler{
		QueryHandler: &defaultDialHandler{},
	}

	return
}
