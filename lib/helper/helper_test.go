package helper_test

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"testing"

	"github.com/steffsas/doe-hunter/lib/helper"
	"github.com/stretchr/testify/assert"
)

func TestGetFullHostFromHostPort_Hostname(t *testing.T) {
	host := "localhost"
	port := 8080
	expected := "localhost:8080"
	actual := helper.GetFullHostFromHostPort(host, port)

	assert.Equal(t, expected, actual)
}

func TestGetFullHostFromPort_IPv4(t *testing.T) {
	host := "8.8.8.8"
	port := 53

	expected := "8.8.8.8:53"
	actual := helper.GetFullHostFromHostPort(host, port)

	assert.Equal(t, expected, actual)
}

func TestGetFullHostFromPort_IPv6(t *testing.T) {
	host := "2001:4860:4860::8888"
	port := 53

	expected := "[2001:4860:4860::8888]:53"
	actual := helper.GetFullHostFromHostPort(host, port)

	assert.Equal(t, expected, actual)
}

func TestGetFullHostFromPort_EmptyHost(t *testing.T) {
	host := ""
	port := 53

	expected := ":53"
	actual := helper.GetFullHostFromHostPort(host, port)

	assert.Equal(t, expected, actual)
}

func TestCheckOnCertificateError_CertificateError(t *testing.T) {
	tlsCertErrP := &tls.CertificateVerificationError{}

	ok := helper.IsCertificateError(tlsCertErrP)
	assert.True(t, ok, "should be a certificate error")
}

func TestCheckOnCertificateError_UnkownAuthorityError(t *testing.T) {
	tlsCertErrP := &x509.UnknownAuthorityError{}

	ok := helper.IsCertificateError(tlsCertErrP)
	assert.True(t, ok, "should be a certificate error")

	tlsCertErr := x509.UnknownAuthorityError{}

	ok = helper.IsCertificateError(tlsCertErr)
	assert.True(t, ok, "should be a certificate error")
}

func TestCheckOnCertificateError_CertificateInvalidError(t *testing.T) {
	tlsCertErrP := &x509.CertificateInvalidError{}

	ok := helper.IsCertificateError(tlsCertErrP)
	assert.True(t, ok, "should be a certificate error")

	tlsCertErr := x509.CertificateInvalidError{}

	ok = helper.IsCertificateError(tlsCertErr)
	assert.True(t, ok, "should be a certificate error")
}

func TestCheckOnCertificateError_NoCertError(t *testing.T) {
	err := fmt.Errorf("some error")

	ok := helper.IsCertificateError(err)
	assert.False(t, ok, "should not be a certificate error")
}

func TestCheckOnCertificateError_NilError(t *testing.T) {
	ok := helper.IsCertificateError(nil)
	assert.False(t, ok, "should not be a certificate error")
}
