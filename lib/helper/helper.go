package helper

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
)

func GetFullHostFromHostPort(host string, port int) string {
	return net.JoinHostPort(host, fmt.Sprintf("%d", port))
}

func IsCertificateError(err error) bool {
	if err == nil {
		return false
	}

	// nolint: errorlint
	switch err.(type) {
	case *tls.CertificateVerificationError:
		return true
	case x509.UnknownAuthorityError:
		return true
	case *x509.UnknownAuthorityError:
		return true
	case x509.CertificateInvalidError:
		return true
	case *x509.CertificateInvalidError:
		return true
	}

	return false
}
