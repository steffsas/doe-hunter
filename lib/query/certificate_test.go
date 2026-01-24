package query_test

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/steffsas/doe-hunter/lib/query"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type mockedCertQueryHandler struct {
	mock.Mock
}

func (m *mockedCertQueryHandler) Query(host string, port int, protocol string, timeout time.Duration, config *tls.Config) (*tls.ConnectionState, error) {
	args := m.Called(host, port, timeout, config)

	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(*tls.ConnectionState), args.Error(1)
}

func TestCertificateQuery_RealWorld(t *testing.T) {
	t.Parallel()

	t.Run("hostname", func(t *testing.T) {
		t.Parallel()

		q := query.NewCertificateQuery()
		q.Host = "www.google.de"
		q.Port = 443

		qh, err := query.NewCertificateQueryHandler(nil)

		require.NoError(t, err, "should not have returned an error")

		res, err := qh.Query(q)

		assert.Nil(t, err, "should not have returned an error")
		assert.NotNil(t, res, "should have returned a response")
		assert.GreaterOrEqual(t, len(res.Certificates), 1, "should have returned at least one certificate")
	})

	t.Run("IPv4", func(t *testing.T) {
		t.Parallel()

		q := query.NewCertificateQuery()
		q.Host = "172.217.20.131" // www.google.de
		q.Port = 443

		qh, err := query.NewCertificateQueryHandler(nil)

		require.NoError(t, err, "should not have returned an error")

		res, err := qh.Query(q)

		assert.Nil(t, err, "should not have returned an error")
		assert.NotNil(t, res, "should have returned a response")
		assert.GreaterOrEqual(t, len(res.Certificates), 1, "should have returned at least one certificate")
	})

	t.Run("multiple queries on same handler", func(t *testing.T) {
		t.Parallel()

		q := query.NewCertificateQuery()
		q.Host = "172.217.20.131" // www.google.de
		q.Port = 443

		qh, err := query.NewCertificateQueryHandler(nil)

		require.NoError(t, err, "should not have returned an error")

		res, err := qh.Query(q)

		assert.Nil(t, err, "should not have returned an error")
		assert.NotNil(t, res, "should have returned a response")
		assert.GreaterOrEqual(t, len(res.Certificates), 1, "should have returned at least one certificate")

		q = query.NewCertificateQuery()
		q.Host = "8.8.8.8" // www.google.de
		q.Port = 443

		res, err = qh.Query(q)

		assert.Nil(t, err, "should not have returned an error")
		assert.NotNil(t, res, "should have returned a response")
		assert.GreaterOrEqual(t, len(res.Certificates), 1, "should have returned at least one certificate")

		// check for timeout
		q = query.NewCertificateQuery()
		q.Host = "8.8.8.8" // www.google.de
		q.Timeout = 1 * time.Millisecond
		q.Port = 443

		res, err = qh.Query(q)

		assert.Error(t, err, "should have returned an error because timeout is too tight")
		assert.NotNil(t, res, "should have returned a response")
		assert.Empty(t, res.Certificates, "should have returned at least one certificate")
	})

	t.Run("specify local addr", func(t *testing.T) {
		t.Parallel()

		config := &query.QueryConfig{
			LocalAddr: net.IP{0, 0, 0, 0},
		}

		qh, err := query.NewCertificateQueryHandler(config)

		require.NoError(t, err, "should not have returned an error")

		q := query.NewCertificateQuery()
		q.Host = "8.8.8.8" // www.google.de
		q.Port = 443

		res, err := qh.Query(q)

		assert.NoError(t, err, "should not have returned an error")
		assert.NotNil(t, res, "should have returned a response")
		assert.NotEmpty(t, res.Certificates, "should have returned at least one certificate")
	})

	t.Run("fail on wrong local addr", func(t *testing.T) {
		t.Parallel()

		config := &query.QueryConfig{
			LocalAddr: net.IP{1, 1, 1, 1},
		}

		_, err := query.NewCertificateQueryHandler(config)

		require.Error(t, err, "should have returned an error")
	})

	t.Run("fail on missing ALPN for AdGuard", func(t *testing.T) {
		t.Parallel()

		q := query.NewCertificateQuery()
		// https://adguard-dns.io/kb/de/general/dns-providers/
		q.Host = "dns.adguard-dns.com"
		q.Port = 853
		q.Protocol = query.TLS_PROTOCOL_UDP

		qh, err := query.NewCertificateQueryHandler(nil)

		require.NoError(t, err, "should not have returned an error")

		_, err = qh.Query(q)

		require.Error(t, err, "should have returned an error")
	})

	t.Run("test UDP (QUIC) connection and certificate retrieval on hostname", func(t *testing.T) {
		t.Parallel()

		q := query.NewCertificateQuery()
		// https://adguard-dns.io/kb/de/general/dns-providers/
		q.Host = "dns.adguard-dns.com"
		q.Port = 853
		q.Protocol = query.TLS_PROTOCOL_UDP
		q.ALPN = []string{"doq"}

		qh, err := query.NewCertificateQueryHandler(nil)

		require.NoError(t, err, "should not have returned an error")

		res, err := qh.Query(q)

		assert.Nil(t, err, "should not have returned an error")
		assert.NotNil(t, res, "should have returned a response")
		assert.GreaterOrEqual(t, len(res.Certificates), 1, "should have returned at least one certificate")
	})

	t.Run("test UDP (QUIC) connection and certificate retrieval on IPv4", func(t *testing.T) {
		t.Parallel()

		q := query.NewCertificateQuery()
		// https://adguard-dns.io/kb/de/general/dns-providers/
		q.Host = "94.140.14.14"
		q.Port = 853
		q.Protocol = query.TLS_PROTOCOL_UDP
		q.ALPN = []string{"doq"}

		qh, err := query.NewCertificateQueryHandler(nil)

		require.NoError(t, err, "should not have returned an error")

		res, err := qh.Query(q)

		assert.Nil(t, err, "should not have returned an error")
		assert.NotNil(t, res, "should have returned a response")
		assert.GreaterOrEqual(t, len(res.Certificates), 1, "should have returned at least one certificate")
	})

	t.Run("test UDP (HTTP/3 via QUIC) connection and certificate retrieval", func(t *testing.T) {
		t.Parallel()

		q := query.NewCertificateQuery()
		// https://adguard-dns.io/kb/de/general/dns-providers/
		q.Host = "dns.adguard-dns.com"
		q.Port = 443
		q.Protocol = query.TLS_PROTOCOL_UDP
		q.ALPN = []string{"h3"}

		qh, err := query.NewCertificateQueryHandler(nil)

		require.NoError(t, err, "should not have returned an error")

		res, err := qh.Query(q)

		assert.Nil(t, err, "should not have returned an error")
		assert.NotNil(t, res, "should have returned a response")
		assert.GreaterOrEqual(t, len(res.Certificates), 1, "should have returned at least one certificate")
	})

	// // exclude IPv6 test since it does not work on GitHub Actions
	// t.Run("IPv6 google https/3", func(t *testing.T) {
	// 	q := query.NewCertificateQuery()
	// 	q.Port = 443
	// 	q.Host = "2a00:1450:4001:813::2003" // www.google.de
	// 	q.ALPN = []string{"h3"}

	// 	qh, err := query.NewCertificateQueryHandler(nil)

	// 	require.NoError(t, err, "should not have returned an error")

	// 	res, err := qh.Query(q)

	// 	assert.Nil(t, err, "should not have returned an error")
	// 	assert.NotNil(t, res, "should have returned a response")
	// 	assert.GreaterOrEqual(t, len(res.Certificates), 1, "should have returned at least one certificate")
	// })

	// t.Run("IPv6 quic", func(t *testing.T) {
	// 	q := query.NewCertificateQuery()
	// 	q.Port = 853
	// 	q.Host = "2a10:50c0::ad1:ff" // adguard
	// 	q.ALPN = []string{"doq"}

	// 	qh, err := query.NewCertificateQueryHandler(nil)

	// 	require.NoError(t, err, "should not have returned an error")

	// 	res, err := qh.Query(q)

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
	mockedDial := getMockedDialHandlerValidResponse(&tlsConn)

	q := query.NewCertificateQuery()
	q.Host = "localhost"
	q.Port = 8080

	qh, err := query.NewCertificateQueryHandler(nil)

	require.NoError(t, err, "should not have returned an error")

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
	mockedDial := getMockedDialHandlerValidResponse(&tlsConn)

	t.Run("valid host", func(t *testing.T) {
		t.Parallel()

		q := query.NewCertificateQuery()
		q.Port = 443
		q.Host = "localhost"

		qh, err := query.NewCertificateQueryHandler(nil)

		require.NoError(t, err, "should not have returned an error")

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
		mockedDial := getMockedDialHandlerValidResponse(&tlsConn)

		q := query.NewCertificateQuery()
		q.Host = ""

		qh, err := query.NewCertificateQueryHandler(nil)

		require.NoError(t, err, "should not have returned an error")

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
	mockedDial := getMockedDialHandlerValidResponse(&tlsConn)

	t.Run("valid port", func(t *testing.T) {
		t.Parallel()

		q := query.NewCertificateQuery()
		q.Host = "localhost"
		q.Port = 443

		qh, err := query.NewCertificateQueryHandler(nil)

		require.NoError(t, err, "should not have returned an error")

		qh.QueryHandler = mockedDial

		res, err := qh.Query(q)

		assert.Nil(t, err, "should fail if port is negative")
		assert.NotNil(t, res, "should have returned a response")
		assert.NotNil(t, res.Certificates, "should not have returned any certificates")
	})

	t.Run("negative port", func(t *testing.T) {
		t.Parallel()

		q := query.NewCertificateQuery()
		q.Host = "localhost"
		q.Port = -1

		qh, err := query.NewCertificateQueryHandler(nil)

		require.NoError(t, err, "should not have returned an error")

		qh.QueryHandler = mockedDial

		res, err := qh.Query(q)

		assert.NotNil(t, err, "should fail if port is negative")
		assert.NotNil(t, res, "should have returned a response")
		assert.Nil(t, res.Certificates, "should not have returned any certificates")
	})

	t.Run("zero port", func(t *testing.T) {
		t.Parallel()

		q := query.NewCertificateQuery()
		q.Host = "localhost"
		q.Port = 0

		qh, err := query.NewCertificateQueryHandler(nil)

		require.NoError(t, err, "should not have returned an error")

		qh.QueryHandler = mockedDial

		res, err := qh.Query(q)

		assert.NotNil(t, err, "should fail if port is zero")
		assert.NotNil(t, res, "should have returned a response")
		assert.Nil(t, res.Certificates, "should not have returned any certificates")
	})

	t.Run("default TLS port", func(t *testing.T) {
		t.Parallel()

		q := query.NewCertificateQuery()
		q.Host = "localhost"

		qh, err := query.NewCertificateQueryHandler(nil)

		require.NoError(t, err, "should not have returned an error")

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
		q.Host = "localhost"
		q.Port = 70000

		qh, err := query.NewCertificateQueryHandler(nil)

		require.NoError(t, err, "should not have returned an error")

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
	mockedDial := getMockedDialHandlerValidResponse(&tlsConn)

	t.Run("negative timeout", func(t *testing.T) {
		t.Parallel()

		q := query.NewCertificateQuery()
		q.Host = "localhost"
		q.Port = 8080
		q.Timeout = -1

		qh, err := query.NewCertificateQueryHandler(nil)

		require.NoError(t, err, "should not have returned an error")

		qh.QueryHandler = mockedDial

		res, err := qh.Query(q)

		assert.NotNil(t, err, "should not have returned an error because it should be set to default")
		assert.NotNil(t, res, "should have returned a response")
		assert.Nil(t, res.Certificates, "should not have returned any certificates")
	})

	t.Run("zero timeout", func(t *testing.T) {
		t.Parallel()

		q := query.NewCertificateQuery()
		q.Host = "localhost"
		q.Port = 8080
		q.Timeout = 0

		qh, err := query.NewCertificateQueryHandler(nil)

		require.NoError(t, err, "should not have returned an error")

		qh.QueryHandler = mockedDial

		res, err := qh.Query(q)

		assert.Nil(t, err, "should not have returned an error because zero means no timeout")
		assert.NotNil(t, res, "should have returned a response")
	})

	t.Run("default timeout", func(t *testing.T) {
		t.Parallel()

		q := query.NewCertificateQuery()
		q.Host = "localhost"
		q.Port = 8080

		qh, err := query.NewCertificateQueryHandler(nil)

		require.NoError(t, err, "should not have returned an error")

		qh.QueryHandler = mockedDial

		res, err := qh.Query(q)

		assert.Nil(t, err, "should not have returned an error because default timeout should be used")
		assert.NotNil(t, res, "should have returned a response")
		assert.Equal(t, query.DEFAULT_TLS_TIMEOUT, q.Timeout, "timeout should be set to default")
	})
}

func TestCertificateQuery_Query(t *testing.T) {
	t.Parallel()

	t.Run("no query handler", func(t *testing.T) {
		t.Parallel()

		q := query.NewCertificateQuery()
		q.Host = "localhost"
		q.Port = 8080

		qh, err := query.NewCertificateQueryHandler(nil)

		require.NoError(t, err, "should not have returned an error")

		qh.QueryHandler = nil

		res, err := qh.Query(q)

		assert.NotNil(t, err, "should not have returned an error because default handler should be used")
		assert.NotNil(t, res, "should have returned a response")
		assert.Nil(t, res.Certificates, "should have returned certificates")
	})

	t.Run("query failed", func(t *testing.T) {
		t.Parallel()

		mockedDial := new(mockedCertQueryHandler)
		mockedDial.On("Query", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil, fmt.Errorf("dial failed"))

		q := query.NewCertificateQuery()
		q.Host = "localhost"
		q.Port = 8080

		qh, err := query.NewCertificateQueryHandler(nil)

		require.NoError(t, err, "should not have returned an error")

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
		mockedDial := getMockedDialHandlerValidResponse(&tlsConn)

		q := query.NewCertificateQuery()
		q.Host = "localhost"
		q.Port = 8080
		q.SNI = "www.google.de"

		qh, err := query.NewCertificateQueryHandler(nil)

		require.NoError(t, err, "should not have returned an error")

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
		mockedDial := getMockedDialHandlerValidResponse(&tlsConn)

		q := query.NewCertificateQuery()
		q.Host = "localhost"
		q.Port = 8080
		q.ALPN = []string{"h2"}

		qh, err := query.NewCertificateQueryHandler(nil)

		require.NoError(t, err, "should not have returned an error")

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

		mockedDial := new(mockedCertQueryHandler)

		certError := x509.CertificateInvalidError{
			Cert:   &x509.Certificate{},
			Reason: x509.NameMismatch,
		}

		mockedDial.On("Query", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil, certError)

		q := query.NewCertificateQuery()
		q.Host = "localhost"
		q.Port = 8080

		qh, err := query.NewCertificateQueryHandler(nil)

		require.NoError(t, err, "should not have returned an error")

		qh.QueryHandler = mockedDial

		res, err := qh.Query(q)

		assert.NotNil(t, err, "should have returned an error")
		assert.NotNil(t, res, "should have returned a response")
		assert.True(t, res.RetryWithoutCertificateVerification, "should have set retry without certificate verification")
		assert.True(t, mockedDial.Calls[1].Arguments[3].(*tls.Config).InsecureSkipVerify, "should have set InsecureSkipVerify")
	})

	t.Run("do not retry on other error", func(t *testing.T) {
		t.Parallel()

		mockedDial := new(mockedCertQueryHandler)

		otherError := fmt.Errorf("some other error")

		mockedDial.On("Query", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil, otherError)

		q := query.NewCertificateQuery()
		q.Host = "localhost"
		q.Port = 8080

		qh, err := query.NewCertificateQueryHandler(nil)

		require.NoError(t, err, "should not have returned an error")

		qh.QueryHandler = mockedDial

		res, err := qh.Query(q)

		assert.NotNil(t, err, "should have returned an error")
		assert.NotNil(t, res, "should have returned a response")
		assert.False(t, res.RetryWithoutCertificateVerification, "should not have set retry without certificate verification")
	})
}

func getMockedDialHandlerValidResponse(connState *tls.ConnectionState) *mockedCertQueryHandler {
	mockedCertQueryHandler := &mockedCertQueryHandler{}
	mockedCertQueryHandler.On("Query", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(connState, nil)

	return mockedCertQueryHandler
}
