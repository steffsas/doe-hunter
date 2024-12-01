package query_test

import (
	"crypto/tls"
	"testing"
	"time"

	"github.com/steffsas/doe-hunter/lib/query"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const dotQueryName = "dns.google."

func TestDoTQuery_RealWorld(t *testing.T) {
	t.Parallel()

	t.Run("IPv4", func(t *testing.T) {
		t.Parallel()

		qm := new(dns.Msg)
		qm.SetQuestion(dotQueryName, dns.TypeA)

		qh := query.NewDefaultDoTHandler(nil)

		q := query.NewDoTQuery()
		q.Host = "94.140.14.140"
		q.QueryMsg = qm

		res, err := qh.Query(q)

		assert.Nil(t, err, "error should be nil")
		require.NotNil(t, res, "response should not be nil")
		assert.NotNil(t, res.ResponseMsg, "response DNS msg should not be nil")
	})

	t.Run("TLS ciphersuite detected", func(t *testing.T) {
		t.Parallel()

		qm := new(dns.Msg)
		qm.SetQuestion(dotQueryName, dns.TypeA)

		qh := query.NewDefaultDoTHandler(nil)

		q := query.NewDoTQuery()
		q.Host = "94.140.14.140"
		q.QueryMsg = qm

		res, err := qh.Query(q)

		assert.Nil(t, err, "error should be nil")
		require.NotNil(t, res, "response should not be nil")

		assert.NotEmpty(t, res.DoEResponse.TLSCipherSuite, "ciphersuite should be detected")
		assert.Contains(t, res.DoEResponse.TLSCipherSuite, "AES", "ciphersuite should be detected")
	})

	t.Run("TLS configuration advertising all ciphersuites and TLS versions", func(t *testing.T) {
		t.Parallel()

		qm := new(dns.Msg)
		qm.SetQuestion(dotQueryName, dns.TypeA)

		qh := query.NewDefaultDoTHandler(nil)

		q := query.NewDoTQuery()
		q.Host = "8.8.8.8"
		q.QueryMsg = qm

		res, err := qh.Query(q)

		assert.Nil(t, err, "error should be nil")
		require.NotNil(t, res, "response should not be nil")
		assert.NotNil(t, res.ResponseMsg, "response DNS msg should not be nil")
	})

	t.Run("TLS version detected", func(t *testing.T) {
		t.Parallel()

		qm := new(dns.Msg)
		qm.SetQuestion(dotQueryName, dns.TypeA)

		qh := query.NewDefaultDoTHandler(nil)

		q := query.NewDoTQuery()
		q.Host = "94.140.14.140"
		q.QueryMsg = qm

		res, err := qh.Query(q)

		assert.Nil(t, err, "error should be nil")
		require.NotNil(t, res, "response should not be nil")

		assert.NotEmpty(t, res.DoEResponse.TLSVersion, "tls version should be detected")
		assert.Contains(t, res.DoEResponse.TLSVersion, "1.", "tls version should be detected")
	})

	// exclude IPv6 test since it does not work on GitHub Actions
	// t.Run("IPv6", func(t *testing.T) {
	// 	qm := new(dns.Msg)
	// 	qm.SetQuestion(dotQueryName, dns.TypeA)

	// 	qh := query.NewDefaultDoTHandler(nil)

	// 	q := query.NewDoTQuery()
	// 	q.Host = "2a10:50c0::1:ff"
	// 	q.QueryMsg = qm

	// 	// TODO use endpoint with valid certificate
	// 	q.TLSConfig = &tls.Config{
	// 		InsecureSkipVerify: true,
	// 	}

	// 	res, err := qh.Query(q)

	// 	assert.Nil(t, err, "error should be nil")
	// 	require.NotNil(t, res, "response should not be nil")
	// 	require.NotNil(t, res.Response, "response should not be nil")
	// 	assert.NotNil(t, res.Response.ResponseMsg, "response DNS msg should not be nil")
	// })
}

func TestDoTQuery_EmptyHost(t *testing.T) {
	t.Parallel()

	qm := new(dns.Msg)
	qm.SetQuestion(dotQueryName, dns.TypeA)

	qh := query.NewDefaultDoTHandler(nil)

	q := query.NewDoTQuery()
	q.Host = ""
	q.QueryMsg = qm

	res, err := qh.Query(q)

	assert.NotNil(t, err, "error should not be nil")
	require.NotNil(t, res, "result should not be nil")
	assert.Nil(t, res.ResponseMsg, "response should be nil")
}

func TestDoTQuery_QueryMsg(t *testing.T) {
	t.Parallel()

	response := new(dns.Msg)

	qm := new(dns.Msg)
	qm.SetQuestion(dotQueryName, dns.TypeA)

	handler := &mockedDoTQueryHandler{}
	handler.On("Query", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(response, time.Duration(0), nil, nil)

	qh := query.NewDefaultDoTHandler(nil)
	qh.QueryHandler = handler

	t.Run("valid query msg", func(t *testing.T) {
		t.Parallel()

		q := query.NewDoTQuery()
		q.Host = dotQueryName
		q.QueryMsg = qm

		res, err := qh.Query(q)

		require.NotNil(t, res, "response should not be nil")
		require.NotNil(t, res.ResponseMsg, "response DNS msg should not be nil")
		assert.Nil(t, err, "error should be nil")
	})

	t.Run("nil query msg", func(t *testing.T) {
		t.Parallel()

		q := query.NewDoTQuery()
		q.Host = dotQueryName
		q.QueryMsg = nil

		res, err := qh.Query(q)

		assert.NotNil(t, err, "error should not be nil")
		require.NotNil(t, res, "result should not be nil")
		assert.Nil(t, res.ResponseMsg, "response should not be nil")
	})
}

func TestDoTQuery_Response(t *testing.T) {
	t.Parallel()

	response := new(dns.Msg)

	handler := &mockedDoTQueryHandler{}
	handler.On("Query", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(response, time.Duration(0), nil, nil)

	qh := query.NewDefaultDoTHandler(nil)
	qh.QueryHandler = handler

	qm := new(dns.Msg)
	qm.SetQuestion(dotQueryName, dns.TypeA)

	q := query.NewDoTQuery()
	q.Host = dotQueryName
	q.QueryMsg = qm

	res, err := qh.Query(q)

	assert.Nil(t, err, "error should be nil")
	require.NotNil(t, res, "result should not be nil")
	assert.Equal(t, res.ResponseMsg, response, "response should be equal to the response msg")
	assert.GreaterOrEqual(t, res.RTT, time.Duration(0), "RTT should be greater or equal to 0")
}

func TestDoTQuery_NilQueryMsg(t *testing.T) {
	t.Parallel()

	q := query.NewDoTQuery()
	q.Host = dotQueryName
	q.QueryMsg = nil

	qh := query.NewDefaultDoTHandler(nil)

	res, err := qh.Query(q)

	assert.NotNil(t, err, "error should not be nil")
	require.NotNil(t, res, "result should not be nil")
	assert.Nil(t, res.ResponseMsg, "response should be nil")
}

func TestDoTQuery_Handler(t *testing.T) {
	t.Parallel()

	response := new(dns.Msg)

	handler := &mockedDoTQueryHandler{}
	handler.On("Query", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(response, time.Duration(0), nil, nil)

	t.Run("valid query handler", func(t *testing.T) {
		t.Parallel()

		qm := new(dns.Msg)
		qm.SetQuestion(dotQueryName, dns.TypeA)

		qh := query.NewDefaultDoTHandler(nil)
		qh.QueryHandler = handler

		q := query.NewDoTQuery()
		q.Host = dotQueryName
		q.QueryMsg = qm

		res, err := qh.Query(q)

		require.NotNil(t, res, "response should not be nil")
		assert.Nil(t, err, "error should be nil")
		assert.NotNil(t, res.ResponseMsg, "response DNS msg should not be nil")
	})

	t.Run("nil query handler", func(t *testing.T) {
		t.Parallel()

		qm := new(dns.Msg)
		qm.SetQuestion(dotQueryName, dns.TypeA)

		qh := query.NewDefaultDoTHandler(nil)
		qh.QueryHandler = nil

		q := query.NewDoTQuery()
		q.Host = dotQueryName
		q.QueryMsg = qm

		res, err := qh.Query(q)

		assert.NotNil(t, err, "error should not be nil")
		require.NotNil(t, res, "result should not be nil")
		assert.Nil(t, res.ResponseMsg, "response DNS msg should be nil")
	})
}

func TestDoTQuery_Port(t *testing.T) {
	t.Parallel()

	response := new(dns.Msg)

	handler := &mockedDoTQueryHandler{}
	handler.On("Query", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(response, time.Duration(0), nil, nil)

	qh := query.NewDefaultDoTHandler(nil)
	qh.QueryHandler = handler

	t.Run("valid port", func(t *testing.T) {
		t.Parallel()

		qm := new(dns.Msg)
		qm.SetQuestion(dotQueryName, dns.TypeA)

		q := query.NewDoTQuery()
		q.Host = dotQueryName
		q.QueryMsg = qm
		q.Port = 853

		res, err := qh.Query(q)

		require.NotNil(t, res, "response should not be nil")
		assert.Nil(t, err, "error should be nil")
		assert.NotNil(t, res.ResponseMsg, "response DNS msg should not be nil")
	})

	t.Run("too large port", func(t *testing.T) {
		t.Parallel()

		qm := new(dns.Msg)
		qm.SetQuestion(dotQueryName, dns.TypeA)

		q := query.NewDoTQuery()
		q.Host = dotQueryName
		q.QueryMsg = qm
		q.Port = 65536

		res, err := qh.Query(q)

		assert.NotNil(t, err, "error should not be nil")
		require.NotNil(t, res, "result should not be nil")
	})

	t.Run("negative port", func(t *testing.T) {
		t.Parallel()

		qm := new(dns.Msg)
		qm.SetQuestion(dotQueryName, dns.TypeA)

		q := query.NewDoTQuery()
		q.Host = dotQueryName
		q.QueryMsg = qm
		q.Port = -1

		res, err := qh.Query(q)

		assert.NotNil(t, err, "error should not be nil")
		require.NotNil(t, res, "result should not be nil")
	})
}

func TestDoTQuery_Host(t *testing.T) {
	t.Parallel()

	response := new(dns.Msg)

	handler := &mockedDoTQueryHandler{}
	handler.On("Query", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(response, time.Duration(0), nil, nil)

	qh := query.NewDefaultDoTHandler(nil)
	qh.QueryHandler = handler

	t.Run("valid host", func(t *testing.T) {
		t.Parallel()

		qm := new(dns.Msg)
		qm.SetQuestion(dotQueryName, dns.TypeA)

		q := query.NewDoTQuery()
		q.Host = dotQueryName
		q.QueryMsg = qm

		res, err := qh.Query(q)

		require.NotNil(t, res, "response should not be nil")
		assert.Nil(t, err, "error should be nil")
		assert.NotNil(t, res.ResponseMsg, "response DNS msg should not be nil")
	})

	t.Run("invalid host", func(t *testing.T) {
		t.Parallel()

		qm := new(dns.Msg)
		qm.SetQuestion(dotQueryName, dns.TypeA)

		q := query.NewDoTQuery()
		q.Host = ""
		q.QueryMsg = qm

		res, err := qh.Query(q)

		assert.NotNil(t, err, "error should not be nil")
		require.NotNil(t, res, "result should not be nil")
		assert.Nil(t, res.ResponseMsg, "response should be nil")
	})
}

func TestDoTQuery_NilQuery(t *testing.T) {
	t.Parallel()

	qh := query.NewDefaultDoTHandler(nil)

	res, err := qh.Query(nil)

	assert.NotNil(t, err, "error should not be nil")
	require.NotNil(t, res, "result should not be nil")
}

func TestDoTQuery_SNI(t *testing.T) {
	t.Parallel()

	response := new(dns.Msg)

	handler := &mockedDoTQueryHandler{}
	handler.On("Query", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(response, time.Duration(0), nil, nil)

	qh := query.NewDefaultDoTHandler(nil)
	qh.QueryHandler = handler

	t.Run("valid SNI", func(t *testing.T) {
		t.Parallel()

		qm := new(dns.Msg)
		qm.SetQuestion(dotQueryName, dns.TypeA)

		q := query.NewDoTQuery()
		q.Host = dotQueryName
		q.QueryMsg = qm
		q.SNI = dotQueryName

		res, err := qh.Query(q)

		require.NotNil(t, res, "response should not be nil")
		assert.Nil(t, err, "error should be nil")
		assert.NotNil(t, res.ResponseMsg, "response DNS msg should not be nil")
	})

	t.Run("empty SNI", func(t *testing.T) {
		t.Parallel()

		qm := new(dns.Msg)
		qm.SetQuestion(dotQueryName, dns.TypeA)

		q := query.NewDoTQuery()
		q.Host = dotQueryName
		q.QueryMsg = qm
		q.SNI = ""

		res, err := qh.Query(q)

		require.NotNil(t, res, "response should not be nil")
		assert.Nil(t, err, "error should be nil")
		assert.NotNil(t, res.ResponseMsg, "response DNS msg should not be nil")
	})
}

type mockedDoTQueryHandler struct {
	mock.Mock
}

func (df *mockedDoTQueryHandler) Query(host string, query *dns.Msg, timeout time.Duration, tlsConfig *tls.Config) (*dns.Msg, time.Duration, *tls.ConnectionState, error) {
	args := df.Called(host, query, timeout, tlsConfig)

	if args.Get(0) == nil {
		return nil, args.Get(1).(time.Duration), args.Get(2).(*tls.ConnectionState), args.Error(3)
	}

	if args.Get(2) == nil {
		return args.Get(0).(*dns.Msg), args.Get(1).(time.Duration), nil, args.Error(3)
	}

	return args.Get(0).(*dns.Msg), args.Get(1).(time.Duration), args.Get(2).(*tls.ConnectionState), args.Error(3)
}
