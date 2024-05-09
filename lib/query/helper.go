package query

import (
	"crypto/tls"
	"crypto/x509"
	"time"

	"github.com/cenkalti/backoff/v4"
)

func CheckOnCertificateError(err error) bool {
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

func getBackOffHandler(maxBackoffTime time.Duration) *backoff.ExponentialBackOff {
	b := backoff.NewExponentialBackOff()
	b.InitialInterval = 100 * time.Millisecond
	b.MaxInterval = maxBackoffTime

	return b
}
