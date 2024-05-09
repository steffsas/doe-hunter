package query_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/steffsas/doe-hunter/lib/query"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestStreamMock(t *testing.T) {
	stream := new(mockedQuicStream)
	stream.reader = strings.NewReader("test")

	n, err := io.ReadAll(stream)

	assert.Equal(t, 4, len(n), "number of bytes read should be 4")
	assert.Nil(t, err, "error should be nil")
}

func TestDoQQuery_RealWorld(t *testing.T) {
	t.Run("IPv4", func(t *testing.T) {
		qm := new(dns.Msg)
		qm.SetQuestion("dns.google.", dns.TypeA)

		q := query.NewDoQQuery()
		q.Host = "94.140.14.140"
		q.QueryMsg = qm
		q.Port = 853

		res, err := q.Query()

		assert.NotNil(t, res, "response should not be nil")
		assert.Nil(t, err, "error should be nil")
	})

	t.Run("IPv6", func(t *testing.T) {
		qm := new(dns.Msg)
		qm.SetQuestion("dns.google.", dns.TypeA)

		// TODO check for valid IPv6 endpoint with valid cert
		tlsConfig := &tls.Config{
			InsecureSkipVerify: true,
		}

		q := query.NewDoQQuery()
		q.Host = "2a10:50c0::1:ff"
		q.QueryMsg = qm
		q.TLSConfig = tlsConfig
		q.Port = 853

		res, err := q.Query()

		fmt.Println(err)

		assert.NotNil(t, res, "response should not be nil")
		assert.Nil(t, err, "error should be nil")
	})
}

func TestDoQQuery_CustomTLSConfig(t *testing.T) {
	response := new(dns.Msg)
	quicConnection := getMockedQuicConnection(response, nil)
	dialHandler := getMockedDialHandlerWithConnection(quicConnection)

	qm := new(dns.Msg)
	qm.SetQuestion("dns.google.", dns.TypeA)

	tlsConfig := &tls.Config{
		ServerName: "dns.google",
	}

	q := query.NewDoQQuery()
	q.Host = "94.140.14.140"
	q.QueryMsg = qm
	q.Port = 853
	q.DialHandler = dialHandler
	q.TLSConfig = tlsConfig

	res, err := q.Query()

	assert.NotNil(t, res, "response should not be nil")
	assert.Nil(t, err, "error should be nil")
}

func TestDoQQuery_CustomQicConfigOverrideTimeout(t *testing.T) {
	response := new(dns.Msg)
	quicConnection := getMockedQuicConnection(response, nil)
	dialHandler := getMockedDialHandlerWithConnection(quicConnection)

	qm := new(dns.Msg)
	qm.SetQuestion("dns.google.", dns.TypeA)

	quicConfig := &quic.Config{
		HandshakeIdleTimeout: 5 * time.Second,
	}

	q := query.NewDoQQuery()
	q.Host = "94.140.14.140"
	q.QueryMsg = qm
	q.Port = 853
	q.DialHandler = dialHandler
	q.QuicConfig = quicConfig

	res, err := q.Query()

	assert.Equal(t, time.Duration(q.Timeout)*time.Millisecond, q.QuicConfig.HandshakeIdleTimeout, "quic timeout should be reset on custom config")
	assert.NotNil(t, res, "response should not be nil")
	assert.Nil(t, err, "error should be nil")
}

func TestDoQQuery_FailSafelyOnDialError(t *testing.T) {
	dialErr := errors.New("dial error")
	quicConnection := getMockedQuicConnection(nil, dialErr)
	dialHandler := getMockedDialHandlerWithConnection(quicConnection)

	qm := new(dns.Msg)
	qm.SetQuestion("dns.google.", dns.TypeA)

	q := query.NewDoQQuery()
	q.Host = "94.140.14.140"
	q.QueryMsg = qm
	q.Port = 853
	q.DialHandler = dialHandler

	res, err := q.Query()

	assert.NotNil(t, err, "should dial error error")
	assert.Contains(t, err.Error(), dialErr.Error(), "error message should contain opening quic session to")
	assert.Nil(t, res.ResponseMsg, "response should be nil")
}

func TestDoQQuery_EmptyResponseError(t *testing.T) {
	quicConnection := getMockedQuicConnection(nil, nil)
	dialHandler := getMockedDialHandlerWithConnection(quicConnection)

	qm := new(dns.Msg)
	qm.SetQuestion("dns.google.", dns.TypeA)

	q := query.NewDoQQuery()
	q.Host = "94.140.14.140"
	q.QueryMsg = qm
	q.Port = 853
	q.DialHandler = dialHandler

	res, err := q.Query()

	assert.NotNil(t, err, "should dial error error")
	assert.Contains(t, err.Error(), "empty response", "error message should contain opening quic session to")
	assert.Nil(t, res.ResponseMsg, "response should be nil")
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
