package query_test

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"testing"

	"github.com/steffsas/doe-hunter/lib/query"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type mockedTLSConn struct {
	mock.Mock
}

func (m *mockedTLSConn) Close() error {
	args := m.Called()
	return args.Error(0)
}

func (m *mockedTLSConn) ConnectionState() tls.ConnectionState {
	args := m.Called()
	return args.Get(0).(tls.ConnectionState)
}

type mockedTLSDialer struct {
	mock.Mock
}

func (m *mockedTLSDialer) DialWithDialer(dialer *net.Dialer, network string, addr string, config *tls.Config) (query.Conn, error) {
	args := m.Called(dialer, network, addr, config)

	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(query.Conn), args.Error(1)
}

const localhost = "localhost"

func TestCertificateQuery_RealWorld(t *testing.T) {
	t.Parallel()

	t.Run("hostname", func(t *testing.T) {
		t.Parallel()

		q := query.NewCertificateQuery()
		q.Host = "www.google.de"
		q.Port = 443

		qh := query.NewCertificateQueryHandler()

		res, err := qh.Query(q)

		assert.Nil(t, err, "should not have returned an error")
		assert.NotNil(t, res, "should have returned a response")
		assert.GreaterOrEqual(t, len(res.Certificates), 1, "should have returned at least one certificate")
	})

	t.Run("IPv4", func(t *testing.T) {
		t.Parallel()

		q := query.NewCertificateQuery()
		q.Host = "142.250.185.227" // www.google.de
		q.Port = 443

		qh := query.NewCertificateQueryHandler()

		res, err := qh.Query(q)

		assert.Nil(t, err, "should not have returned an error")
		assert.NotNil(t, res, "should have returned a response")
		assert.GreaterOrEqual(t, len(res.Certificates), 1, "should have returned at least one certificate")
	})

	// exclude IPv6 test since it does not work on GitHub Actions
	// t.Run("IPv6", func(t *testing.T) {
	// 	q := query.NewCertificateQuery()
	// 	q.Port = 443
	// 	q.Host = "2a00:1450:4001:813::2003" // www.google.de
	// 	q.TLSConfig = &tls.Config{
	// 		ServerName: "www.google.de", // required for IP addresses SNI
	// 	}
	//
	// qh := query.NewCertificateQueryHandler()
	// res, err := qh.Query(q)
	//
	// 	assert.Nil(t, err, "should not have returned an error")
	// 	assert.NotNil(t, res, "should have returned a response")
	// 	assert.GreaterOrEqual(t, len(res.Certificates), 1, "should have returned at least one certificate")
	// })
}

func TestCertificateQuery_ShouldNotFailOnNoCertificates(t *testing.T) {
	t.Parallel()

	tlsConn := tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{},
	}
	mockedDial := getMockedDialHandlerValidRespnse(&tlsConn)

	q := query.NewCertificateQuery()
	q.Host = localhost
	q.Port = 8080

	qh := query.NewCertificateQueryHandler()
	qh.QueryHandler = mockedDial

	res, err := qh.Query(q)

	assert.Nil(t, err, "should not have returned an error")
	assert.NotNil(t, res, "should not have returned a response")
}

func TestCertificateQuery_Host(t *testing.T) {
	t.Parallel()

	tlsConn := tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{},
	}
	mockedDial := getMockedDialHandlerValidRespnse(&tlsConn)

	t.Run("valid host", func(t *testing.T) {
		t.Parallel()

		q := query.NewCertificateQuery()
		q.Port = 443
		q.Host = localhost

		qh := query.NewCertificateQueryHandler()
		qh.QueryHandler = mockedDial

		res, err := qh.Query(q)

		assert.Nil(t, err, "should not have returned an error")
		assert.NotNil(t, res, "should have returned a response")
	})

	t.Run("empty host", func(t *testing.T) {
		t.Parallel()

		tlsConn := tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{},
		}
		mockedDial := getMockedDialHandlerValidRespnse(&tlsConn)

		q := query.NewCertificateQuery()
		q.Host = ""

		qh := query.NewCertificateQueryHandler()
		qh.QueryHandler = mockedDial

		res, err := qh.Query(q)

		assert.NotNil(t, err, "should fail if host is empty")
		assert.NotNil(t, res, "should have returned a response")
		assert.Nil(t, res.Certificates, "should not have returned any certificates")
	})
}

func TestCertificateQuery_Port(t *testing.T) {
	t.Parallel()

	tlsConn := tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{},
	}
	mockedDial := getMockedDialHandlerValidRespnse(&tlsConn)

	t.Run("valid port", func(t *testing.T) {
		t.Parallel()

		q := query.NewCertificateQuery()
		q.Host = localhost
		q.Port = 443

		qh := query.NewCertificateQueryHandler()
		qh.QueryHandler = mockedDial

		res, err := qh.Query(q)

		assert.Nil(t, err, "should fail if port is negative")
		assert.NotNil(t, res, "should have returned a response")
		assert.NotNil(t, res.Certificates, "should not have returned any certificates")
	})

	t.Run("negative port", func(t *testing.T) {
		t.Parallel()

		q := query.NewCertificateQuery()
		q.Host = localhost
		q.Port = -1

		qh := query.NewCertificateQueryHandler()
		qh.QueryHandler = mockedDial

		res, err := qh.Query(q)

		assert.NotNil(t, err, "should fail if port is negative")
		assert.NotNil(t, res, "should have returned a response")
		assert.Nil(t, res.Certificates, "should not have returned any certificates")
	})

	t.Run("zero port", func(t *testing.T) {
		t.Parallel()

		q := query.NewCertificateQuery()
		q.Host = localhost
		q.Port = 0

		qh := query.NewCertificateQueryHandler()
		qh.QueryHandler = mockedDial

		res, err := qh.Query(q)

		assert.NotNil(t, err, "should fail if port is zero")
		assert.NotNil(t, res, "should have returned a response")
		assert.Nil(t, res.Certificates, "should not have returned any certificates")
	})

	t.Run("default TLS port", func(t *testing.T) {
		t.Parallel()

		q := query.NewCertificateQuery()
		q.Host = localhost

		qh := query.NewCertificateQueryHandler()
		qh.QueryHandler = mockedDial

		res, err := qh.Query(q)

		assert.Nil(t, err, "should fail if port is not provided")
		assert.NotNil(t, res, "should have returned a response")
		assert.NotNil(t, res.Certificates, "should not have returned any certificates")
		assert.Equal(t, query.DEFAULT_TLS_PORT, q.Port, "port should be set to default")
	})

	t.Run("too large port", func(t *testing.T) {
		t.Parallel()

		q := query.NewCertificateQuery()
		q.Host = localhost
		q.Port = 70000

		qh := query.NewCertificateQueryHandler()
		qh.QueryHandler = mockedDial

		res, err := qh.Query(q)

		assert.NotNil(t, err, "should fail if port is too large")
		assert.NotNil(t, res, "should have returned a response")
		assert.Nil(t, res.Certificates, "should not have returned any certificates")
	})
}

func TestCertificateQuery_Timeout(t *testing.T) {
	t.Parallel()

	tlsConn := tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{},
	}
	mockedDial := getMockedDialHandlerValidRespnse(&tlsConn)

	t.Run("negative timeout", func(t *testing.T) {
		t.Parallel()

		q := query.NewCertificateQuery()
		q.Host = localhost
		q.Port = 8080
		q.Timeout = -1

		qh := query.NewCertificateQueryHandler()
		qh.QueryHandler = mockedDial

		res, err := qh.Query(q)

		assert.NotNil(t, err, "should not have returned an error because it should be set to default")
		assert.NotNil(t, res, "should have returned a response")
		assert.Nil(t, res.Certificates, "should not have returned any certificates")
	})

	t.Run("zero timeout", func(t *testing.T) {
		t.Parallel()

		q := query.NewCertificateQuery()
		q.Host = localhost
		q.Port = 8080
		q.Timeout = 0

		qh := query.NewCertificateQueryHandler()
		qh.QueryHandler = mockedDial

		res, err := qh.Query(q)

		assert.Nil(t, err, "should not have returned an error because zero means no timeout")
		assert.NotNil(t, res, "should have returned a response")
	})

	t.Run("default timeout", func(t *testing.T) {
		t.Parallel()

		q := query.NewCertificateQuery()
		q.Host = localhost
		q.Port = 8080

		qh := query.NewCertificateQueryHandler()
		qh.QueryHandler = mockedDial

		res, err := qh.Query(q)

		assert.Nil(t, err, "should not have returned an error because default timeout should be used")
		assert.NotNil(t, res, "should have returned a response")
		assert.Equal(t, query.DEFAULT_TLS_TIMEOUT, q.Timeout, "timeout should be set to default")
	})
}

func TestCertificateQuery_DialHandler(t *testing.T) {
	t.Parallel()

	t.Run("no query handler", func(t *testing.T) {
		t.Parallel()

		q := query.NewCertificateQuery()
		q.Host = localhost
		q.Port = 8080

		qh := query.NewCertificateQueryHandler()
		qh.QueryHandler = nil

		res, err := qh.Query(q)

		assert.NotNil(t, err, "should not have returned an error because default handler should be used")
		assert.NotNil(t, res, "should have returned a response")
		assert.Nil(t, res.Certificates, "should have returned certificates")
	})

	t.Run("dial failed", func(t *testing.T) {
		t.Parallel()

		mockedDial := new(mockedTLSDialer)
		mockedDial.On("DialWithDialer", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil, fmt.Errorf("dial failed"))

		q := query.NewCertificateQuery()
		q.Host = localhost
		q.Port = 8080

		qh := query.NewCertificateQueryHandler()
		qh.QueryHandler = mockedDial

		res, err := qh.Query(q)

		assert.NotNil(t, err, "should have returned an error")
		assert.NotNil(t, res, "should have returned a response")
	})
}

func TestCertificateQuery_SNI(t *testing.T) {
	t.Parallel()

	t.Run("valid SNI", func(t *testing.T) {
		t.Parallel()

		tlsConn := tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{},
		}
		mockedDial := getMockedDialHandlerValidRespnse(&tlsConn)

		q := query.NewCertificateQuery()
		q.Host = localhost
		q.Port = 8080
		q.SNI = "www.google.de"

		qh := query.NewCertificateQueryHandler()
		qh.QueryHandler = mockedDial

		res, err := qh.Query(q)

		assert.Nil(t, err, "should not have returned an error")
		assert.NotNil(t, res, "should have returned a response")
		assert.Equal(t, q.SNI, mockedDial.Calls[0].Arguments[3].(*tls.Config).ServerName, "SNI should be set in TLS config")
	})
}

func TestCertificateQuery_ALPN(t *testing.T) {
	t.Parallel()

	t.Run("valid ALPN", func(t *testing.T) {
		t.Parallel()

		tlsConn := tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{},
		}
		mockedDial := getMockedDialHandlerValidRespnse(&tlsConn)

		q := query.NewCertificateQuery()
		q.Host = localhost
		q.Port = 8080
		q.ALPN = []string{"h2"}

		qh := query.NewCertificateQueryHandler()
		qh.QueryHandler = mockedDial

		res, err := qh.Query(q)

		assert.Nil(t, err, "should not have returned an error")
		assert.NotNil(t, res, "should have returned a response")
		assert.Equal(t, q.ALPN, mockedDial.Calls[0].Arguments[3].(*tls.Config).NextProtos, "ALPN should be set in TLS config")
	})
}

func TestCertificateQuery_RetryWithSkipCertificateVerification(t *testing.T) {
	t.Parallel()

	t.Run("retry without certificate verification", func(t *testing.T) {
		t.Parallel()

		mockedDial := new(mockedTLSDialer)

		certError := x509.CertificateInvalidError{
			Cert:   &x509.Certificate{},
			Reason: x509.NameMismatch,
		}

		mockedDial.On("DialWithDialer", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil, certError)

		q := query.NewCertificateQuery()
		q.Host = localhost
		q.Port = 8080

		qh := query.NewCertificateQueryHandler()
		qh.QueryHandler = mockedDial

		res, err := qh.Query(q)

		assert.NotNil(t, err, "should have returned an error")
		assert.NotNil(t, res, "should have returned a response")
		assert.True(t, res.RetryWithoutCertificateVerification, "should have set retry without certificate verification")
		assert.True(t, mockedDial.Calls[1].Arguments[3].(*tls.Config).InsecureSkipVerify, "should have set InsecureSkipVerify")
	})

	t.Run("do not retry on other error", func(t *testing.T) {
		t.Parallel()

		mockedDial := new(mockedTLSDialer)

		otherError := fmt.Errorf("some other error")

		mockedDial.On("DialWithDialer", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil, otherError)

		q := query.NewCertificateQuery()
		q.Host = localhost
		q.Port = 8080

		qh := query.NewCertificateQueryHandler()
		qh.QueryHandler = mockedDial

		res, err := qh.Query(q)

		assert.NotNil(t, err, "should have returned an error")
		assert.NotNil(t, res, "should have returned a response")
		assert.False(t, res.RetryWithoutCertificateVerification, "should not have set retry without certificate verification")
	})
}

func getMockedDialHandlerValidRespnse(connState *tls.ConnectionState) *mockedTLSDialer {
	mockedDial := new(mockedTLSDialer)

	mockedConn := new(mockedTLSConn)
	mockedConn.On("Close").Return(nil)
	mockedConn.On("ConnectionState").Return(*connState)

	mockedDial.On("DialWithDialer", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(mockedConn, nil)

	return mockedDial
}
