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
	// Dialer for the TLS handshake. Timeout is replaced by the query timeout given in this struct.
	Dialer *net.Dialer
	// Host is the host for the dialer (required)
	Host string `json:"host"`
	// Port is the port for the dialer (default: 443)
	Port int `json:"port"`
	// Protocol is the protocol for the dialer (default: "tcp")
	Protocol string `json:"protocol"`
	// TLS Config is the TLS configuration (defaults to nil which means basic TLS configuration and verification)
	TLSConfig *tls.Config `json:"tls_config"`
	// Timeout is the timeout in ms (default: 2500)
	Timeout time.Duration `json:"timeout"`
}

type CertificateQueryResponse struct {
	// Certificate is the certificate
	Certificates []*x509.Certificate `json:"certificates"`
}

func (q *CertificateQuery) Query() (response *CertificateQueryResponse, err error) {
	response = &CertificateQueryResponse{}

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

	if q.TLSConfig == nil {
		q.TLSConfig = &tls.Config{}
	}

	if q.Dialer == nil {
		q.Dialer = &net.Dialer{
			Timeout: q.Timeout,
		}
	} else {
		q.Dialer.Timeout = q.Timeout
	}

	conn, err := q.DialHandler.DialWithDialer(q.Dialer, "tcp", helper.GetFullHostFromHostPort(q.Host, q.Port), q.TLSConfig)
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
	q.Dialer = &net.Dialer{}

	return
}
