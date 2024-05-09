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

func TestDoTQuery_RealWorld(t *testing.T) {
	t.Run("IPv4", func(t *testing.T) {
		qm := new(dns.Msg)
		qm.SetQuestion(dnsGoogle, dns.TypeA)

		q := query.NewDoTQuery()
		q.Host = "94.140.14.140"
		q.QueryMsg = qm

		res, err := q.Query()

		assert.NotNil(t, res, "response should not be nil")
		assert.Nil(t, err, "error should be nil")
	})

	// t.Run("IPv6", func(t *testing.T) {
	// 	qm := new(dns.Msg)
	// 	qm.SetQuestion(dnsGoogle, dns.TypeA)

	// 	q := query.NewDoTQuery()
	// 	q.Host = "2a10:50c0::1:ff"
	// 	q.QueryMsg = qm

	// 	// TODO use endpoint with valid certificate
	// 	q.TLSConfig = &tls.Config{
	// 		InsecureSkipVerify: true,
	// 	}

	// 	res, err := q.Query()

	// 	assert.NotNil(t, res, "response should not be nil")
	// 	assert.Nil(t, err, "error should be nil")
	// })
}

func TestDoTQuery_EmptyHost(t *testing.T) {
	qm := new(dns.Msg)
	qm.SetQuestion(dnsGoogle, dns.TypeA)

	q := query.NewDoTQuery()
	q.Host = ""
	q.QueryMsg = qm

	res, err := q.Query()

	assert.NotNil(t, err, "error should not be nil")
	require.NotNil(t, res, "result should not be nil")
	assert.Nil(t, res.ResponseMsg, "response should be nil")
}

func TestDoTQuery_QueryMsg(t *testing.T) {
	response := new(dns.Msg)

	qm := new(dns.Msg)
	qm.SetQuestion(dnsGoogle, dns.TypeA)

	handler := &mockedQueryHandler{}
	handler.On("Query", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(response, time.Duration(0), nil)

	t.Run("valid query msg", func(t *testing.T) {
		q := query.NewDoTQuery()
		q.Host = dnsGoogle
		q.QueryMsg = qm
		q.QueryHandler = handler

		res, err := q.Query()

		assert.NotNil(t, res, "response should not be nil")
		assert.NotNil(t, res.ResponseMsg, "response DNS msg should not be nil")
		assert.Nil(t, err, "error should be nil")
	})

	t.Run("nil query msg", func(t *testing.T) {
		q := query.NewDoTQuery()
		q.Host = dnsGoogle
		q.QueryMsg = nil
		q.QueryHandler = handler

		res, err := q.Query()

		assert.NotNil(t, err, "error should not be nil")
		require.NotNil(t, res, "result should not be nil")
		assert.Nil(t, res.ResponseMsg, "response should be nil")
	})
}

func TestDoTQuery_NilQueryMsg(t *testing.T) {
	q := query.NewDoTQuery()
	q.Host = dnsGoogle
	q.QueryMsg = nil

	res, err := q.Query()

	assert.NotNil(t, err, "error should not be nil")
	require.NotNil(t, res, "result should not be nil")
	assert.Nil(t, res.ResponseMsg, "response should be nil")
}

func TestDoTQuery_Handler(t *testing.T) {
	response := new(dns.Msg)

	handler := &mockedQueryHandler{}
	handler.On("Query", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(response, time.Duration(0), nil)

	t.Run("valid query handler", func(t *testing.T) {
		qm := new(dns.Msg)
		qm.SetQuestion(dnsGoogle, dns.TypeA)

		q := query.NewDoTQuery()
		q.Host = dnsGoogle
		q.QueryMsg = qm
		q.QueryHandler = handler

		res, err := q.Query()

		assert.NotNil(t, res, "response should not be nil")
		assert.NotNil(t, res.ResponseMsg, "response DNS msg should not be nil")
		assert.Nil(t, err, "error should be nil")
	})

	t.Run("nil query handler", func(t *testing.T) {
		qm := new(dns.Msg)
		qm.SetQuestion(dnsGoogle, dns.TypeA)

		q := query.NewDoTQuery()
		q.Host = dnsGoogle
		q.QueryMsg = qm
		q.QueryHandler = nil

		res, err := q.Query()

		assert.NotNil(t, err, "error should not be nil")
		require.NotNil(t, res, "result should not be nil")
		assert.Nil(t, res.ResponseMsg, "response should be nil")
	})
}

func TestDoTQuery_Port(t *testing.T) {
	response := new(dns.Msg)

	handler := &mockedQueryHandler{}
	handler.On("Query", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(response, time.Duration(0), nil)

	t.Run("valid port", func(t *testing.T) {
		qm := new(dns.Msg)
		qm.SetQuestion(dnsGoogle, dns.TypeA)

		q := query.NewDoTQuery()
		q.Host = dnsGoogle
		q.QueryMsg = qm
		q.Port = 853
		q.QueryHandler = handler

		res, err := q.Query()

		assert.NotNil(t, res, "response should not be nil")
		assert.NotNil(t, res.ResponseMsg, "response DNS msg should not be nil")
		assert.Nil(t, err, "error should be nil")
	})

	t.Run("too large port", func(t *testing.T) {
		qm := new(dns.Msg)
		qm.SetQuestion(dnsGoogle, dns.TypeA)

		q := query.NewDoTQuery()
		q.Host = dnsGoogle
		q.QueryMsg = qm
		q.Port = 65536
		q.QueryHandler = handler

		res, err := q.Query()

		assert.NotNil(t, err, "error should not be nil")
		require.NotNil(t, res, "result should not be nil")
		assert.Nil(t, res.ResponseMsg, "response should be nil")
	})

	t.Run("negative port", func(t *testing.T) {
		qm := new(dns.Msg)
		qm.SetQuestion(dnsGoogle, dns.TypeA)

		q := query.NewDoTQuery()
		q.Host = dnsGoogle
		q.QueryMsg = qm
		q.Port = -1
		q.QueryHandler = handler

		res, err := q.Query()

		assert.NotNil(t, err, "error should not be nil")
		require.NotNil(t, res, "result should not be nil")
		assert.Nil(t, res.ResponseMsg, "response should be nil")
	})
}

func TestDoTQuery_Host(t *testing.T) {
	response := new(dns.Msg)

	handler := &mockedQueryHandler{}
	handler.On("Query", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(response, time.Duration(0), nil)

	t.Run("valid host", func(t *testing.T) {
		qm := new(dns.Msg)
		qm.SetQuestion(dnsGoogle, dns.TypeA)

		q := query.NewDoTQuery()
		q.Host = dnsGoogle
		q.QueryMsg = qm
		q.QueryHandler = handler

		res, err := q.Query()

		assert.NotNil(t, res, "response should not be nil")
		assert.NotNil(t, res.ResponseMsg, "response DNS msg should not be nil")
		assert.Nil(t, err, "error should be nil")
	})

	t.Run("invalid host", func(t *testing.T) {
		qm := new(dns.Msg)
		qm.SetQuestion(dnsGoogle, dns.TypeA)

		q := query.NewDoTQuery()
		q.Host = ""
		q.QueryMsg = qm
		q.QueryHandler = handler

		res, err := q.Query()

		assert.NotNil(t, err, "error should not be nil")
		require.NotNil(t, res, "result should not be nil")
		assert.Nil(t, res.ResponseMsg, "response should be nil")
	})
}

func TestDoTQuery_CertificateError(t *testing.T) {
	t.Run("certificate validation error", func(t *testing.T) {
		response := new(dns.Msg)

		certError := &tls.CertificateVerificationError{}

		handler := &mockedQueryHandler{}
		handler.On("Query", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(response, time.Duration(0), certError)

		qm := new(dns.Msg)
		qm.SetQuestion(dnsGoogle, dns.TypeA)

		q := query.NewDoTQuery()
		q.Host = dnsGoogle
		q.QueryMsg = qm
		q.QueryHandler = handler

		res, err := q.Query()

		assert.NotNil(t, err, "error should not be nil")
		require.NotNil(t, res, "result should not be nil")
		assert.Nil(t, res.ResponseMsg, "response should be nil")
	})
}
