package query_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/steffsas/doe-hunter/lib/query"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const doqNameQuery = "dns.google."
const ipv4Host = "94.140.14.140"

func TestStreamMock(t *testing.T) {
	t.Parallel()

	stream := new(mockedQuicStream)
	stream.reader = strings.NewReader("test")

	n, err := io.ReadAll(stream)

	assert.Equal(t, 4, len(n), "number of bytes read should be 4")
	assert.Nil(t, err, "error should be nil")
}

func TestDoQQuery_RealWorld(t *testing.T) {
	t.Parallel()

	t.Run("IPv4", func(t *testing.T) {
		t.Parallel()

		qm := new(dns.Msg)
		qm.SetQuestion(doqNameQuery, dns.TypeA)

		qh := query.NewDoQQueryHandler()

		q := query.NewDoQQuery()
		q.Host = ipv4Host
		q.QueryMsg = qm
		q.Port = 853

		res, err := qh.Query(q)

		require.NotNil(t, res, "response should not be nil")
		assert.GreaterOrEqual(t, res.RTT, 0*time.Millisecond, "response's RTT should not be nil")
		assert.NotNil(t, res.ResponseMsg, "response should not be nil")
		assert.Nil(t, err, "error should be nil")
	})

	// exclude IPv6 test since it does not work on GitHub Actions
	// t.Run("IPv6", func(t *testing.T) {
	//  t.Parallel()
	// 	qm := new(dns.Msg)
	// 	qm.SetQuestion(doqNameQuery, dns.TypeA)

	// 	qh := query.NewDoQQueryHandler()

	// 	// TODO check for valid IPv6 endpoint with valid cert
	// 	tlsConfig := &tls.Config{
	// 		InsecureSkipVerify: true,
	// 	}

	// 	q := query.NewDoQQuery()
	// 	q.Host = "2a10:50c0::1:ff"
	// 	q.QueryMsg = qm
	// 	q.TLSConfig = tlsConfig
	// 	q.Port = 853

	// 	res, err := qh.Query(q)

	// 	require.NotNil(t, res, "response should not be nil")
	// 	require.NotNil(t, res.Response, "response should not be nil")
	// 	assert.GreaterOrEqual(t, res.Response.RTT, 0*time.Millisecond, "response's RTT should not be nil")
	// 	assert.NotNil(t, res.Response.ResponseMsg, "response should not be nil")
	// 	assert.Nil(t, err, "error should be nil")
	// })
}

func TestDoQQuery_TriggerCheck(t *testing.T) {
	t.Parallel()

	qm := new(dns.Msg)
	qm.SetQuestion(doqNameQuery, dns.TypeA)

	qh := query.NewDoQQueryHandler()

	q := query.NewDoQQuery()
	q.Host = ""

	res, err := qh.Query(q)

	assert.NotNil(t, err, "error should not be nil")
	require.NotNil(t, res, "result should not be nil")
	require.Nil(t, res.ResponseMsg, "response should be nil")
}

func TestDoQQuery_EmptyQueryHandler(t *testing.T) {
	t.Parallel()

	qm := new(dns.Msg)
	qm.SetQuestion(doqNameQuery, dns.TypeA)

	q := query.NewDoQQuery()
	q.Host = ipv4Host
	q.QueryMsg = qm

	qh := query.NewDoQQueryHandler()
	qh.QueryHandler = nil

	res, err := qh.Query(q)

	assert.NotNil(t, err, "error should not be nil")
	require.NotNil(t, res, "result should not be nil")
	require.Nil(t, res.ResponseMsg, "response should be nil")
}

func TestDoQQuery_EmptyQuery(t *testing.T) {
	t.Parallel()

	qh := query.NewDoQQueryHandler()

	res, err := qh.Query(nil)

	assert.NotNil(t, err, "error should not be nil")
	require.NotNil(t, res, "result should not be nil")
	require.Nil(t, res.ResponseMsg, "response should be nil")
}

func TestDoQQuery_Response(t *testing.T) {
	t.Parallel()

	response := new(dns.Msg)
	quicConnection := getMockedQuicConnection(response, nil)
	dialHandler := getMockedDialHandlerWithConnection(quicConnection)

	qm := new(dns.Msg)
	qm.SetQuestion(doqNameQuery, dns.TypeA)

	qh := query.NewDoQQueryHandler()
	qh.QueryHandler = dialHandler

	q := query.NewDoQQuery()
	q.Host = ipv4Host
	q.QueryMsg = qm
	q.Port = 853

	res, err := qh.Query(q)

	require.NotNil(t, res, "response should not be nil")
	assert.NotNil(t, res.ResponseMsg, "response should not be nil")
	assert.GreaterOrEqual(t, res.RTT, 0*time.Millisecond, "response's RTT should not be nil")
	assert.Nil(t, err, "error should be nil")
}

func TestDoQQuery_FailSafelyOnDialError(t *testing.T) {
	t.Parallel()

	dialErr := errors.New("dial error")
	quicConnection := getMockedQuicConnection(nil, dialErr)
	dialHandler := getMockedDialHandlerWithConnection(quicConnection)

	qh := query.NewDoQQueryHandler()
	qh.QueryHandler = dialHandler

	qm := new(dns.Msg)
	qm.SetQuestion(doqNameQuery, dns.TypeA)

	q := query.NewDoQQuery()
	q.Host = ipv4Host
	q.QueryMsg = qm
	q.Port = 853

	res, err := qh.Query(q)

	assert.NotNil(t, err, "should dial error error")
	require.NotNil(t, res, "response should not be nil")
	assert.Nil(t, res.ResponseMsg, "DNS response should be nil")
}

func TestDoQQuery_EmptyResponseError(t *testing.T) {
	t.Parallel()

	quicConnection := getMockedQuicConnection(nil, nil)
	dialHandler := getMockedDialHandlerWithConnection(quicConnection)

	qh := query.NewDoQQueryHandler()
	qh.QueryHandler = dialHandler

	qm := new(dns.Msg)
	qm.SetQuestion(doqNameQuery, dns.TypeA)

	q := query.NewDoQQuery()
	q.Host = ipv4Host
	q.QueryMsg = qm
	q.Port = 853

	res, err := qh.Query(q)

	assert.NotNil(t, err, "should dial error error")
	require.NotNil(t, res, "response should not be nil")
	assert.Nil(t, res.ResponseMsg, "DNS response should be nil")
}

func TestDoQQuery_SNI(t *testing.T) {
	t.Parallel()

	response := new(dns.Msg)
	quicConnection := getMockedQuicConnection(response, nil)
	dialHandler := getMockedDialHandlerWithConnection(quicConnection)

	qm := new(dns.Msg)
	qm.SetQuestion(doqNameQuery, dns.TypeA)

	qh := query.NewDoQQueryHandler()
	qh.QueryHandler = dialHandler

	q := query.NewDoQQuery()
	q.Host = doqNameQuery
	q.QueryMsg = qm
	q.Port = 853
	q.SNI = doqNameQuery

	res, err := qh.Query(q)

	require.NotNil(t, res, "response should not be nil")
	assert.NotNil(t, res.ResponseMsg, "response should not be nil")
	assert.GreaterOrEqual(t, res.RTT, 0*time.Millisecond, "response's RTT should not be nil")
	assert.Nil(t, err, "error should be nil")
}

func TestDoQQuery_SkipCertificateVerify(t *testing.T) {
	t.Parallel()

	t.Run("do not skip certificate verify", func(t *testing.T) {
		t.Parallel()

		certError := x509.CertificateInvalidError{
			Cert:   nil,
			Reason: x509.Expired,
		}

		dialHandler := new(mockedDialHandler)
		dialHandler.On("DialAddr", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil, certError)

		qm := new(dns.Msg)
		qm.SetQuestion(doqNameQuery, dns.TypeA)

		qh := query.NewDoQQueryHandler()
		qh.QueryHandler = dialHandler

		q := query.NewDoQQuery()
		q.Host = doqNameQuery
		q.QueryMsg = qm
		q.Port = 853
		q.SNI = doqNameQuery
		q.SkipCertificateVerify = false

		res, err := qh.Query(q)

		assert.NotNil(t, err, "error should not be nil")
		require.NotNil(t, res, "response should not be nil")
		assert.Nil(t, res.ResponseMsg, "response should be nil")
		assert.False(t, res.CertificateValid, "certificate should not be valid")
		assert.True(t, res.CertificateVerified, "certificate should not be verified")
	})

	t.Run("no cert skip but cert error", func(t *testing.T) {
		t.Parallel()

		response := new(dns.Msg)
		quicConnection := getMockedQuicConnection(response, nil)
		dialHandler := getMockedDialHandlerWithConnection(quicConnection)

		qm := new(dns.Msg)
		qm.SetQuestion(doqNameQuery, dns.TypeA)

		qh := query.NewDoQQueryHandler()
		qh.QueryHandler = dialHandler

		q := query.NewDoQQuery()
		q.Host = doqNameQuery
		q.QueryMsg = qm
		q.Port = 853
		q.SNI = doqNameQuery
		q.SkipCertificateVerify = false

		res, err := qh.Query(q)

		require.NotNil(t, res, "response should not be nil")
		assert.NotNil(t, res.ResponseMsg, "response should not be nil")
		assert.GreaterOrEqual(t, res.RTT, 0*time.Millisecond, "response's RTT should not be nil")
		assert.Nil(t, err, "error should be nil")
		assert.True(t, res.CertificateValid, "certificate should be valid")
		assert.True(t, res.CertificateVerified, "certificate should be verified")
	})

	t.Run("skip certificate verify", func(t *testing.T) {
		t.Parallel()

		response := new(dns.Msg)
		quicConnection := getMockedQuicConnection(response, nil)
		dialHandler := getMockedDialHandlerWithConnection(quicConnection)

		qm := new(dns.Msg)
		qm.SetQuestion(doqNameQuery, dns.TypeA)

		qh := query.NewDoQQueryHandler()
		qh.QueryHandler = dialHandler

		q := query.NewDoQQuery()
		q.Host = doqNameQuery
		q.QueryMsg = qm
		q.Port = 853
		q.SNI = doqNameQuery
		q.SkipCertificateVerify = true

		res, err := qh.Query(q)

		require.NotNil(t, res, "response should not be nil")
		assert.NotNil(t, res.ResponseMsg, "response should not be nil")
		assert.GreaterOrEqual(t, res.RTT, 0*time.Millisecond, "response's RTT should not be nil")
		assert.Nil(t, err, "error should be nil")
		assert.False(t, res.CertificateValid, "certificate should be valid")
		assert.False(t, res.CertificateVerified, "certificate should be verified")
	})

}

func getMockedQuicConnection(response *dns.Msg, err error) (conn query.QuicConn) {
	stream := new(mockedQuicStream)
	if response == nil {
		stream.reader = bytes.NewReader(nil)
	} else {
		res, e := response.Pack()
		if e != nil {
			panic(e)
		}
		stream.reader = bytes.NewReader(query.AddQuicPrefix(res))
	}

	qConn := new(mockedQuicConn)
	qConn.On("OpenStream").Return(stream, err)
	qConn.On("CloseWithError", mock.Anything, mock.Anything).Return(nil)

	return qConn
}

func getMockedDialHandlerWithConnection(conn query.QuicConn) *mockedDialHandler {
	handler := new(mockedDialHandler)
	handler.On("DialAddr", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(conn, nil)
	return handler
}

type mockedDialHandler struct {
	mock.Mock
}

func (m *mockedDialHandler) DialAddr(ctx context.Context, addr string, tlsConf *tls.Config, conf *quic.Config) (query.QuicConn, error) {
	args := m.Called(ctx, addr, tlsConf, conf)

	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(query.QuicConn), args.Error(1)
}

type mockedQuicStream struct {
	quic.Stream
	reader io.Reader
}

func (m *mockedQuicStream) Read(p []byte) (n int, err error) {
	return m.reader.Read(p)
}

func (m *mockedQuicStream) Write(p []byte) (n int, err error) {
	return len(p), nil
}

func (m *mockedQuicStream) Close() error {
	return nil
}

type mockedQuicConn struct {
	mock.Mock
}

func (m *mockedQuicConn) CloseWithError(quic.ApplicationErrorCode, string) error {
	return nil
}

func (m *mockedQuicConn) OpenStream() (quic.Stream, error) {
	args := m.Called()
	return args.Get(0).(quic.Stream), args.Error(1)
}
