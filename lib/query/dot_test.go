package query_test

import (
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

		qh := query.NewDoTQueryHandler(nil)

		q := query.NewDoTQuery()
		q.Host = "94.140.14.140"
		q.QueryMsg = qm

		res, err := qh.Query(q)

		assert.Nil(t, err, "error should be nil")
		require.NotNil(t, res, "response should not be nil")
		assert.NotNil(t, res.ResponseMsg, "response DNS msg should not be nil")
	})

	// exclude IPv6 test since it does not work on GitHub Actions
	// t.Run("IPv6", func(t *testing.T) {
	// 	qm := new(dns.Msg)
	// 	qm.SetQuestion(dotQueryName, dns.TypeA)

	// 	qh := query.NewDoTQueryHandler(nil)

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

	qh := query.NewDoTQueryHandler(nil)

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

	handler := &mockedQueryHandler{}
	handler.On("Query", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(response, time.Duration(0), nil)

	qh := query.NewDoTQueryHandler(nil)
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

	handler := &mockedQueryHandler{}
	handler.On("Query", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(response, time.Duration(0), nil)

	qh := query.NewDoTQueryHandler(nil)
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

	qh := query.NewDoTQueryHandler(nil)

	res, err := qh.Query(q)

	assert.NotNil(t, err, "error should not be nil")
	require.NotNil(t, res, "result should not be nil")
	assert.Nil(t, res.ResponseMsg, "response should be nil")
}

func TestDoTQuery_Handler(t *testing.T) {
	t.Parallel()

	response := new(dns.Msg)

	handler := &mockedQueryHandler{}
	handler.On("Query", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(response, time.Duration(0), nil)

	t.Run("valid query handler", func(t *testing.T) {
		t.Parallel()

		qm := new(dns.Msg)
		qm.SetQuestion(dotQueryName, dns.TypeA)

		qh := query.NewDoTQueryHandler(nil)
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

		qh := query.NewDoTQueryHandler(nil)
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

	handler := &mockedQueryHandler{}
	handler.On("Query", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(response, time.Duration(0), nil)

	qh := query.NewDoTQueryHandler(nil)
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

	handler := &mockedQueryHandler{}
	handler.On("Query", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(response, time.Duration(0), nil)

	qh := query.NewDoTQueryHandler(nil)
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

	qh := query.NewDoTQueryHandler(nil)

	res, err := qh.Query(nil)

	assert.NotNil(t, err, "error should not be nil")
	require.NotNil(t, res, "result should not be nil")
}

func TestDoTQuery_SNI(t *testing.T) {
	t.Parallel()

	response := new(dns.Msg)

	handler := &mockedQueryHandler{}
	handler.On("Query", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(response, time.Duration(0), nil)

	qh := query.NewDoTQueryHandler(nil)
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
