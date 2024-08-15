package helper_test

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"testing"

	"github.com/steffsas/doe-hunter/lib/helper"
	"github.com/stretchr/testify/assert"
)

func TestGetFullHostFromHostPort(t *testing.T) {
	t.Parallel()

	t.Run("hostname", func(t *testing.T) {
		t.Parallel()

		host := "localhost"
		port := 8080
		expected := "localhost:8080"
		actual := helper.GetFullHostFromHostPort(host, port)

		assert.Equal(t, expected, actual)
	})

	t.Run("ipv4", func(t *testing.T) {
		t.Parallel()

		host := "8.8.8.8"
		port := 53

		expected := "8.8.8.8:53"
		actual := helper.GetFullHostFromHostPort(host, port)

		assert.Equal(t, expected, actual)
	})

	t.Run("ipv6", func(t *testing.T) {
		t.Parallel()

		host := "2001:4860:4860::8888"
		port := 53

		expected := "[2001:4860:4860::8888]:53"
		actual := helper.GetFullHostFromHostPort(host, port)

		assert.Equal(t, expected, actual)
	})

	t.Run("empty host", func(t *testing.T) {
		t.Parallel()

		host := ""
		port := 53

		expected := ":53"
		actual := helper.GetFullHostFromHostPort(host, port)

		assert.Equal(t, expected, actual)
	})
}

func TestCheckOnCertificateError(t *testing.T) {
	t.Parallel()

	t.Run("certificate error", func(t *testing.T) {
		t.Parallel()

		tlsCertErrP := &tls.CertificateVerificationError{}

		ok := helper.IsCertificateError(tlsCertErrP)
		assert.True(t, ok, "should be a certificate error")
	})

	t.Run("unknonw authority error", func(t *testing.T) {
		t.Parallel()

		tlsCertErrP := &x509.UnknownAuthorityError{}

		ok := helper.IsCertificateError(tlsCertErrP)
		assert.True(t, ok, "should be a certificate error")

		tlsCertErr := x509.UnknownAuthorityError{}

		ok = helper.IsCertificateError(tlsCertErr)
		assert.True(t, ok, "should be a certificate error")
	})

	t.Run("certificate invalid error", func(t *testing.T) {
		t.Parallel()

		tlsCertErrP := &x509.CertificateInvalidError{}

		ok := helper.IsCertificateError(tlsCertErrP)
		assert.True(t, ok, "should be a certificate error")

		tlsCertErr := x509.CertificateInvalidError{}

		ok = helper.IsCertificateError(tlsCertErr)
		assert.True(t, ok, "should be a certificate error")
	})

	t.Run("no error", func(t *testing.T) {
		t.Parallel()

		err := fmt.Errorf("some error")

		ok := helper.IsCertificateError(err)
		assert.False(t, ok, "should not be a certificate error")
	})

	t.Run("nil error", func(t *testing.T) {
		t.Parallel()

		ok := helper.IsCertificateError(nil)
		assert.False(t, ok, "should not be a certificate error")
	})
}

func TestGetTopicFromNameAndVP(t *testing.T) {
	t.Parallel()

	topic := "topic"
	vp := "vp"
	expected := "topic-vp"
	actual := helper.GetTopicFromNameAndVP(topic, vp)

	assert.Equal(t, expected, actual)
}
