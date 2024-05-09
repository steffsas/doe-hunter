package query_test

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"testing"

	"github.com/steffsas/doe-hunter/lib/query"

	"github.com/stretchr/testify/assert"
)

func TestCheckOnCertificateError_CertificateError(t *testing.T) {
	tlsCertErr := &tls.CertificateVerificationError{}

	ok := query.CheckOnCertificateError(tlsCertErr)
	assert.True(t, ok, "should be a certificate error")
}

func TestCheckOnCertificateError_UnkownAuthorityError(t *testing.T) {
	tlsCertErr := &x509.UnknownAuthorityError{}

	ok := query.CheckOnCertificateError(tlsCertErr)
	assert.True(t, ok, "should be a certificate error")
}

func TestCheckOnCertificateError_CertificateInvalidError(t *testing.T) {
	tlsCertErr := &x509.CertificateInvalidError{}

	ok := query.CheckOnCertificateError(tlsCertErr)
	assert.True(t, ok, "should be a certificate error")
}

func TestCheckOnCertificateError_NoCertError(t *testing.T) {
	err := fmt.Errorf("some error")

	ok := query.CheckOnCertificateError(err)
	assert.False(t, ok, "should not be a certificate error")
}
