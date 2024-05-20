package query_test

import (
	"crypto/tls"
	"fmt"
	"testing"
	"time"

	"github.com/steffsas/doe-hunter/lib/query"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const COMMON_IP = "8.8.8.8"
const COMMON_PORT = 53

type mockedQueryHandler struct {
	mock.Mock
}

func (df *mockedQueryHandler) Query(host string, query *dns.Msg, protocol string, timeout time.Duration, tlsConfig *tls.Config) (answer *dns.Msg, rtt time.Duration, err error) {
	args := df.Called(host, query, protocol, timeout, tlsConfig)

	if args.Get(0) == nil {
		return nil, args.Get(1).(time.Duration), args.Error(2)
	}

	return args.Get(0).(*dns.Msg), args.Get(1).(time.Duration), args.Error(2)
}

type mockedSleeper struct {
	mock.Mock
}

func (ts *mockedSleeper) Sleep(d time.Duration) {
	ts.Called(d)
}

func getDefaultQueryHandler() *query.ConventionalDNSQueryHandler {
	sleeper := &mockedSleeper{}
	sleeper.On("Sleep", mock.Anything).Return()

	dnsQuery := query.NewConventionalDNSQueryHandler()
	dnsQuery.Sleeper = sleeper

	return dnsQuery
}

func getDefaultQuery() *query.ConventionalDNSQuery {
	q := &dns.Msg{}
	q.SetQuestion("google.com.", dns.TypeA)

	qo := query.NewConventionalQuery()
	qo.QueryMsg = q
	qo.Host = COMMON_IP
	qo.Port = COMMON_PORT

	return qo
}

func TestDNSQuery_RealWorld(t *testing.T) {
	t.Parallel()

	t.Run("hostname", func(t *testing.T) {
		t.Parallel()

		dq := getDefaultQueryHandler()

		res, err := dq.Query(getDefaultQuery())

		require.NotNil(t, res, "response should not be nil")
		assert.Nil(t, err, "error should be nil")
		require.NotNil(t, res.Response, "response should not be nil")
		require.NotNil(t, res.Response.ResponseMsg, "response message should not be nil")
		assert.NotNil(t, res.Response.ResponseMsg.Answer, "response should have an answer")
	})

	t.Run("IPv4", func(t *testing.T) {
		t.Parallel()

		dq := getDefaultQueryHandler()

		res, err := dq.Query(getDefaultQuery())

		require.NotNil(t, res, "response should not be nil")
		assert.Nil(t, err, "error should be nil")
		require.NotNil(t, res.Response, "response should not be nil")
		require.NotNil(t, res.Response.ResponseMsg, "response message should not be nil")
		assert.NotNil(t, res.Response.ResponseMsg.Answer, "response should have an answer")
	})

	// exclude IPv6 test since it does not work on GitHub Actions
	// t.Run("IPv6", func(t *testing.T) {
	// 	dq := getDefaultQueryHandler()
	// 	q := getDefaultQuery()
	// 	q.Host = "2001:4860:4860::8888" // google-public-dns-a.google.com

	// 	res, err := dq.Query(q)

	// 	require.NotNil(t, res, "response should not be nil")
	// 	assert.Nil(t, err, "error should be nil")
	// 	require.NotNil(t, res.Response, "response should not be nil")
	// 	require.NotNil(t, res.Response.ResponseMsg, "response message should not be nil")
	// 	assert.NotNil(t, res.Response.ResponseMsg.Answer, "response should have an answer")
	// })
}

// TestDNSQuery_InvalidProtocol tests the DNS query with an invalid protocol
func TestDNSQuery_InvalidProtocol(t *testing.T) {
	t.Parallel()

	dq := getDefaultQueryHandler()
	q := getDefaultQuery()
	q.Protocol = "invalid"

	_, err := dq.Query(q)
	assert.NotNil(t, err, "should have returned an error")
}

func TestDNSQuery_QueryCheck(t *testing.T) {
	t.Parallel()

	t.Run("should return error on nil query", func(t *testing.T) {
		t.Parallel()

		dq := getDefaultQueryHandler()

		res, err := dq.Query(nil)

		assert.NotNil(t, err, "should have returned an error")
		require.NotNil(t, res, "response should not be nil")
		require.NotNil(t, res.Response, "response should not be nil")
		assert.Nil(t, res.Response.ResponseMsg, "response should not be nil")
	})

	t.Run("should return error on empty query message", func(t *testing.T) {
		t.Parallel()

		dq := getDefaultQueryHandler()
		q := getDefaultQuery()
		q.QueryMsg = nil

		res, err := dq.Query(q)

		assert.NotNil(t, err, "should have returned an error")
		require.NotNil(t, res, "response should not be nil")
		require.NotNil(t, res.Response, "response should not be nil")
		assert.Nil(t, res.Response.ResponseMsg, "response should not be nil")
	})

	t.Run("should return error on empty host", func(t *testing.T) {
		t.Parallel()

		dq := getDefaultQueryHandler()
		q := getDefaultQuery()
		q.Host = ""

		res, err := dq.Query(q)

		assert.NotNil(t, err, "should have returned an error")
		require.NotNil(t, res, "response should not be nil")
		require.NotNil(t, res.Response, "response should not be nil")
		assert.Nil(t, res.Response.ResponseMsg, "response should not be nil")
	})

	t.Run("should return error on negative port", func(t *testing.T) {
		t.Parallel()

		dq := getDefaultQueryHandler()
		q := getDefaultQuery()
		q.Port = -1

		res, err := dq.Query(q)

		assert.NotNil(t, err, "should have returned an error")
		require.NotNil(t, res, "response should not be nil")
		require.NotNil(t, res.Response, "response should not be nil")
		assert.Nil(t, res.Response.ResponseMsg, "response should not be nil")
	})

	t.Run("should return error on too large port", func(t *testing.T) {
		t.Parallel()

		dq := getDefaultQueryHandler()
		q := getDefaultQuery()
		q.Port = 65536

		res, err := dq.Query(q)

		assert.NotNil(t, err, "should have returned an error")
		require.NotNil(t, res, "response should not be nil")
		require.NotNil(t, res.Response, "response should not be nil")
		assert.Nil(t, res.Response.ResponseMsg, "response should not be nil")
	})

	t.Run("should return error on negative timeout", func(t *testing.T) {
		t.Parallel()

		dq := getDefaultQueryHandler()
		q := getDefaultQuery()
		q.Timeout = -1
		q.TimeoutUDP = -1
		q.TimeoutTCP = -1

		res, err := dq.Query(q)

		assert.NotNil(t, err, "should have returned an error")
		require.NotNil(t, res, "response should not be nil")
		require.NotNil(t, res.Response, "response should not be nil")
		assert.Nil(t, res.Response.ResponseMsg, "response should not be nil")
	})
}

func TestDNSQuery_Response(t *testing.T) {
	t.Parallel()

	t.Run("should return response and query", func(t *testing.T) {
		t.Parallel()

		response := &dns.Msg{}

		handler := &mockedQueryHandler{}
		handler.On("Query", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(response, time.Duration(0), nil)

		dq := getDefaultQueryHandler()
		dq.QueryHandler = handler

		q := getDefaultQuery()

		res, err := dq.Query(q)

		assert.Nil(t, err, "should not have returned an error")
		require.NotNil(t, res, "response should not be nil")
		require.NotNil(t, res.Response, "response should not be nil")
		require.NotNil(t, res.Response.ResponseMsg, "response message should not be nil")
		assert.Equal(t, response, res.Response.ResponseMsg, "should have returned the response")
	})
}

func TestDNSQuery_UDPAttempts(t *testing.T) {
	t.Parallel()

	t.Run("one attempt on success", func(t *testing.T) {
		t.Parallel()

		response := &dns.Msg{}

		handler := &mockedQueryHandler{}
		handler.On("Query", mock.Anything, mock.Anything, query.DNS_UDP, mock.Anything, mock.Anything).Return(response, time.Duration(0), nil)

		dq := getDefaultQueryHandler()
		dq.QueryHandler = handler

		res, err := dq.Query(getDefaultQuery())

		assert.Nil(t, err, "should not have returned an error")
		assert.Equal(t, 1, res.UDPAttempts, "should have exactly one UDP attempt")
		require.NotNil(t, res.Response, "should have returned a response")
		require.NotNil(t, res.Response.ResponseMsg, "should have returned a DNS response")
		assert.Equal(t, response, res.Response.ResponseMsg, "should have returned the response")
	})

	t.Run("max attempts on failure", func(t *testing.T) {
		t.Parallel()

		handler := &mockedQueryHandler{}
		handler.On("Query", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil, time.Duration(0), fmt.Errorf("no response"))

		dq := getDefaultQueryHandler()
		dq.QueryHandler = handler

		q := getDefaultQuery()
		q.MaxUDPRetries = 3
		q.MaxTCPRetries = 3

		res, err := dq.Query(q)

		assert.NotNil(t, err, "should have returned an error")
		assert.Equal(t, q.MaxUDPRetries, res.UDPAttempts, "should have exactly max UDP attempts")
		assert.Equal(t, q.MaxTCPRetries, res.TCPAttempts, "should have exactly max UDP attempts")
		require.NotNil(t, res.Response, "should have returned a response")
		assert.Nil(t, res.Response.ResponseMsg, "should not have returned a DNS response")
	})
}

func TestDNSQuery_UDPRetries(t *testing.T) {
	t.Parallel()

	t.Run("error on negative retries", func(t *testing.T) {
		t.Parallel()

		response := &dns.Msg{}

		handler := &mockedQueryHandler{}
		handler.On("Query", mock.Anything, mock.Anything, query.DNS_UDP, mock.Anything, mock.Anything).Return(response, time.Duration(0), nil)

		dq := getDefaultQueryHandler()
		dq.QueryHandler = handler

		q := getDefaultQuery()
		q.MaxUDPRetries = -1

		res, err := dq.Query(q)

		assert.NotNil(t, err, "should have returned an error")
		assert.NotNil(t, res, "response should not be nil")
		assert.NotNil(t, res.Response, "response should not be nil")
		assert.Nil(t, res.Response.ResponseMsg, "response should not be nil")
	})
}

func TestDNSQuery_TCPAttempts(t *testing.T) {
	t.Parallel()

	t.Run("one attempt on success", func(t *testing.T) {
		t.Parallel()

		response := &dns.Msg{}

		handler := &mockedQueryHandler{}
		handler.On("Query", mock.Anything, mock.Anything, query.DNS_TCP, mock.Anything, mock.Anything).Return(response, time.Duration(0), nil)

		dq := getDefaultQueryHandler()
		dq.QueryHandler = handler

		q := getDefaultQuery()
		q.Protocol = query.DNS_TCP

		res, err := dq.Query(q)

		assert.Nil(t, err, "should not have returned an error")
		assert.Equal(t, 0, res.UDPAttempts, "should have no UDP attempt")
		assert.Equal(t, 1, res.TCPAttempts, "should have exactly one TCP attempt")
		require.NotNil(t, res.Response, "should have returned a response")
		require.NotNil(t, res.Response.ResponseMsg, "should have returned a DNS response")
		assert.Equal(t, response, res.Response.ResponseMsg, "should have returned the response")
	})

	t.Run("max attempts on failure", func(t *testing.T) {
		t.Parallel()

		handler := &mockedQueryHandler{}
		handler.On("Query", mock.Anything, mock.Anything, query.DNS_TCP, mock.Anything, mock.Anything).Return(nil, time.Duration(0), fmt.Errorf("no response"))

		dq := getDefaultQueryHandler()
		dq.QueryHandler = handler

		q := getDefaultQuery()
		q.Protocol = query.DNS_TCP
		q.MaxTCPRetries = 3

		res, err := dq.Query(q)

		assert.NotNil(t, err, "should have returned an error")
		assert.Equal(t, q.MaxTCPRetries, res.TCPAttempts, "should have exactly max TCP attempts")
		assert.Equal(t, 0, res.UDPAttempts, "should have no UDP attempt")
		assert.NotNil(t, res.Response, "should have returned a response")
		assert.NotNil(t, err, "should have returned an error")
		assert.Nil(t, res.Response.ResponseMsg, "should not have returned a DNS response")
	})
}

func TestDNSQuery_TCPRetries(t *testing.T) {
	t.Parallel()

	t.Run("error on negative retries", func(t *testing.T) {
		t.Parallel()

		response := &dns.Msg{}

		handler := &mockedQueryHandler{}
		handler.On("Query", mock.Anything, mock.Anything, query.DNS_TCP, mock.Anything, mock.Anything).Return(response, time.Duration(0), nil)

		dq := getDefaultQueryHandler()
		dq.QueryHandler = handler

		q := getDefaultQuery()
		q.MaxTCPRetries = -1

		res, err := dq.Query(q)

		assert.NotNil(t, err, "should have returned an error")
		assert.NotNil(t, res, "response should not be nil")
		assert.NotNil(t, res.Response, "response should not be nil")
		assert.Nil(t, res.Response.ResponseMsg, "response should not be nil")
	})
}

func TestDNSQuery_TCPFallback(t *testing.T) {
	t.Parallel()

	t.Run("fallback on udp error", func(t *testing.T) {
		t.Parallel()

		response := &dns.Msg{}

		handler := &mockedQueryHandler{}
		handler.On("Query", mock.Anything, mock.Anything, query.DNS_UDP, mock.Anything, mock.Anything).Return(nil, time.Duration(0), fmt.Errorf("no response"))
		handler.On("Query", mock.Anything, mock.Anything, query.DNS_TCP, mock.Anything, mock.Anything).Return(response, time.Duration(0), nil)

		dq := getDefaultQueryHandler()
		dq.QueryHandler = handler

		q := getDefaultQuery()
		q.Protocol = query.DNS_TCP
		q.AutoFallbackTCP = true
		q.Protocol = query.DNS_UDP

		res, err := dq.Query(q)

		assert.Nil(t, err, "should not have returned an error")
		assert.Equal(t, q.MaxUDPRetries, res.UDPAttempts, "should have tried UDP max times")
		assert.Equal(t, 1, res.TCPAttempts, "should have exactly one TCP attempt")
		require.NotNil(t, res.Response, "should have returned a response")
		require.NotNil(t, res.Response.ResponseMsg, "should have returned a DNS response")
	})

	t.Run("no fallback if not set", func(t *testing.T) {
		t.Parallel()

		response := &dns.Msg{}

		handler := &mockedQueryHandler{}
		handler.On("Query", mock.Anything, mock.Anything, query.DNS_UDP, mock.Anything, mock.Anything).Return(nil, time.Duration(0), fmt.Errorf("no response"))
		handler.On("Query", mock.Anything, mock.Anything, query.DNS_TCP, mock.Anything, mock.Anything).Return(response, time.Duration(0), nil)

		dq := getDefaultQueryHandler()
		dq.QueryHandler = handler

		q := getDefaultQuery()
		q.Protocol = query.DNS_TCP
		q.AutoFallbackTCP = false
		q.Protocol = query.DNS_UDP

		res, err := dq.Query(q)

		assert.NotNil(t, err, "should have returned an error (no response)")
		assert.Equal(t, q.MaxUDPRetries, res.UDPAttempts, "should have tried UDP max times")
		assert.Equal(t, 0, res.TCPAttempts, "should have no TCP attempt")
		assert.NotNil(t, res.Response, "should have returned a response")
		assert.Nil(t, res.Response.ResponseMsg, "should not have returned a DNS response")
	})

	t.Run("fallback on truncation bit", func(t *testing.T) {
		t.Parallel()

		responseUDP := &dns.Msg{}
		responseUDP.Truncated = true

		responseTCP := &dns.Msg{}

		handler := &mockedQueryHandler{}
		handler.On("Query", mock.Anything, mock.Anything, query.DNS_UDP, mock.Anything, mock.Anything).Return(responseUDP, time.Duration(0), nil)
		handler.On("Query", mock.Anything, mock.Anything, query.DNS_TCP, mock.Anything, mock.Anything).Return(responseTCP, time.Duration(0), nil)

		dq := getDefaultQueryHandler()
		dq.QueryHandler = handler

		q := getDefaultQuery()
		q.AutoFallbackTCP = true

		res, err := dq.Query(q)

		assert.Nil(t, err, "should not have returned an error")
		assert.Equal(t, 1, res.UDPAttempts, "should have tried UDP once")
		assert.Equal(t, 1, res.TCPAttempts, "should have tried TCP")
		require.NotNil(t, res.Response, "should have returned the TCP response")
		require.NotNil(t, res.Response.ResponseMsg, "should have returned a DNS response")
		require.Equal(t, res.Response.ResponseMsg, responseTCP, "should have returned the TCP response")
	})

	t.Run("no fallback on truncation bit if TCP fallback is not wanted", func(t *testing.T) {
		t.Parallel()

		responseUDP := &dns.Msg{}
		responseUDP.Truncated = true

		responseTCP := &dns.Msg{}

		handler := &mockedQueryHandler{}
		handler.On("Query", mock.Anything, mock.Anything, query.DNS_UDP, mock.Anything, mock.Anything).Return(responseUDP, time.Duration(0), nil)
		handler.On("Query", mock.Anything, mock.Anything, query.DNS_TCP, mock.Anything, mock.Anything).Return(responseTCP, time.Duration(0), nil)

		dq := getDefaultQueryHandler()
		dq.QueryHandler = handler

		q := getDefaultQuery()
		q.AutoFallbackTCP = false

		res, err := dq.Query(q)

		assert.Nil(t, err, "should not have returned an error")
		assert.Equal(t, 1, res.UDPAttempts, "should have tried UDP once")
		assert.Equal(t, 0, res.TCPAttempts, "should not have tried TCP")
		require.NotNil(t, res.Response, "should have returned the TCP response")
		require.NotNil(t, res.Response.ResponseMsg, "should have returned a DNS response")
		require.Equal(t, res.Response.ResponseMsg, responseUDP, "should have returned the UDP response")
	})
}

func TestDNSQuery_Protocol(t *testing.T) {
	t.Parallel()

	t.Run("udp", func(t *testing.T) {
		t.Parallel()

		response := &dns.Msg{}

		handler := &mockedQueryHandler{}
		handler.On("Query", mock.Anything, mock.Anything, query.DNS_UDP, mock.Anything, mock.Anything).Return(response, time.Duration(0), nil)

		dq := getDefaultQueryHandler()
		dq.QueryHandler = handler

		q := getDefaultQuery()
		q.Protocol = query.DNS_UDP

		res, err := dq.Query(q)

		assert.Nil(t, err, "should not have returned an error")
		assert.Equal(t, 1, res.UDPAttempts, "should have exactly one UDP attempt")
		assert.Equal(t, 0, res.TCPAttempts, "should have no TCP attempt")
		require.NotNil(t, res.Response, "should have returned the TCP response")
		require.NotNil(t, res.Response.ResponseMsg, "should have returned a DNS response")
		assert.Equal(t, response, res.Response.ResponseMsg, "should have returned the response")
	})

	t.Run("tcp", func(t *testing.T) {
		t.Parallel()

		response := &dns.Msg{}

		handler := &mockedQueryHandler{}
		handler.On("Query", mock.Anything, mock.Anything, query.DNS_TCP, mock.Anything, mock.Anything).Return(response, time.Duration(0), nil)

		dq := getDefaultQueryHandler()
		dq.QueryHandler = handler

		q := getDefaultQuery()
		q.Protocol = query.DNS_TCP

		res, err := dq.Query(q)

		assert.Nil(t, err, "should not have returned an error")
		assert.Equal(t, 0, res.UDPAttempts, "should have no UDP attempt")
		assert.Equal(t, 1, res.TCPAttempts, "should have exactly one TCP attempt")
		require.NotNil(t, res.Response, "should have returned the TCP response")
		require.NotNil(t, res.Response.ResponseMsg, "should have returned a DNS response")
		assert.Equal(t, response, res.Response.ResponseMsg, "should have returned the response")
	})
}

func TestDNSQuery_NilQueryHandler(t *testing.T) {
	t.Parallel()

	dq := getDefaultQueryHandler()
	dq.QueryHandler = nil

	q := getDefaultQuery()

	res, err := dq.Query(q)

	assert.NotNil(t, err, "should have returned an error")
	require.NotNil(t, res, "response should not be nil")
	assert.Equal(t, 0, res.UDPAttempts, "should not have tried UDP")
	assert.Equal(t, 0, res.TCPAttempts, "should not have tried TCP")
	require.NotNil(t, res.Response, "should have returned a response")
	assert.Nil(t, res.Response.ResponseMsg, "should not have returned any response")
}

func TestDNSQuery_UDPTimeout(t *testing.T) {
	t.Parallel()

	t.Run("negative timeout", func(t *testing.T) {
		t.Parallel()

		response := &dns.Msg{}

		handler := &mockedQueryHandler{}
		handler.On("Query", mock.Anything, mock.Anything, query.DNS_UDP, mock.Anything, mock.Anything).Return(response, time.Duration(0), nil)

		dq := getDefaultQueryHandler()
		dq.QueryHandler = handler

		q := getDefaultQuery()
		q.Timeout = -1
		q.TimeoutUDP = -1

		res, err := dq.Query(q)

		assert.NotNil(t, err, "should have returned an error")
		require.NotNil(t, res, "response should not be nil")
		require.NotNil(t, res.Response, "should have returned a response")
		assert.Nil(t, res.Response.ResponseMsg, "should not have returned a DNS response")
	})

	t.Run("accept zero timeout", func(t *testing.T) {
		t.Parallel()

		response := &dns.Msg{}

		handler := &mockedQueryHandler{}
		handler.On("Query", mock.Anything, mock.Anything, query.DNS_UDP, mock.Anything, mock.Anything).Return(response, time.Duration(0), nil)

		dq := getDefaultQueryHandler()
		dq.QueryHandler = handler

		q := getDefaultQuery()
		q.TimeoutUDP = 0

		res, err := dq.Query(q)

		assert.Nil(t, err, "should not have returned an error")
		require.NotNil(t, res, "response should not be nil")
		require.NotNil(t, res.Response, "should have returned a response")
		assert.NotNil(t, res.Response.ResponseMsg, "should have returned a DNS response")
	})

	t.Run("use timeout over UDPTimeout", func(t *testing.T) {
		t.Parallel()

		response := &dns.Msg{}

		handler := &mockedQueryHandler{}
		handler.On("Query", mock.Anything, mock.Anything, query.DNS_UDP, mock.Anything, mock.Anything).Return(response, time.Duration(0), nil)

		dq := getDefaultQueryHandler()
		dq.QueryHandler = handler

		q := getDefaultQuery()
		q.Timeout = 1000 * time.Millisecond
		q.TimeoutUDP = -1

		res, err := dq.Query(q)

		assert.Nil(t, err, "should not have returned an error")
		require.NotNil(t, res, "response should not be nil")
		require.NotNil(t, res.Response, "should have returned a response")
		assert.NotNil(t, res.Response.ResponseMsg, "should have returned a DNS response")
	})
}

func TestDNSQuery_TCPTimeout(t *testing.T) {
	t.Parallel()

	t.Run("negative timeout", func(t *testing.T) {
		t.Parallel()

		response := &dns.Msg{}

		handler := &mockedQueryHandler{}
		handler.On("Query", mock.Anything, mock.Anything, query.DNS_TCP, mock.Anything, mock.Anything).Return(response, time.Duration(0), nil)

		dq := getDefaultQueryHandler()
		dq.QueryHandler = handler

		q := getDefaultQuery()
		q.Protocol = query.DNS_TCP
		q.Timeout = -1
		q.TimeoutTCP = -1

		res, err := dq.Query(q)

		assert.NotNil(t, err, "should have returned an error")
		require.NotNil(t, res, "response should not be nil")
		require.NotNil(t, res.Response, "should have returned a response")
		assert.Nil(t, res.Response.ResponseMsg, "should not have returned a DNS response")
	})

	t.Run("negative tcp timeout", func(t *testing.T) {
		t.Parallel()

		response := &dns.Msg{}

		handler := &mockedQueryHandler{}
		handler.On("Query", mock.Anything, mock.Anything, query.DNS_TCP, mock.Anything, mock.Anything).Return(response, time.Duration(0), nil)

		dq := getDefaultQueryHandler()
		dq.QueryHandler = handler

		q := getDefaultQuery()
		q.Protocol = query.DNS_TCP
		q.Timeout = -1
		q.TimeoutTCP = -1

		res, err := dq.Query(q)

		assert.NotNil(t, err, "should have returned an error")
		require.NotNil(t, res, "response should not be nil")
		require.NotNil(t, res.Response, "should have returned a response")
		assert.Nil(t, res.Response.ResponseMsg, "should not have returned a DNS response")
	})

	t.Run("accept zero timeout", func(t *testing.T) {
		t.Parallel()

		response := &dns.Msg{}

		handler := &mockedQueryHandler{}
		handler.On("Query", mock.Anything, mock.Anything, query.DNS_TCP, mock.Anything, mock.Anything).Return(response, time.Duration(0), nil)

		dq := getDefaultQueryHandler()
		dq.QueryHandler = handler

		q := getDefaultQuery()
		q.Protocol = query.DNS_TCP
		q.TimeoutTCP = 0

		res, err := dq.Query(q)

		assert.Nil(t, err, "should not have returned an error")
		require.NotNil(t, res, "response should not be nil")
		require.NotNil(t, res.Response, "should have returned a response")
		assert.NotNil(t, res.Response.ResponseMsg, "should have returned a DNS response")
	})

	t.Run("use timeout over TCPTimeout", func(t *testing.T) {
		t.Parallel()

		response := &dns.Msg{}

		handler := &mockedQueryHandler{}
		handler.On("Query", mock.Anything, mock.Anything, query.DNS_TCP, mock.Anything, mock.Anything).Return(response, time.Duration(0), nil)

		dq := getDefaultQueryHandler()
		dq.QueryHandler = handler

		q := getDefaultQuery()
		q.Protocol = query.DNS_TCP
		q.Timeout = 1000 * time.Millisecond
		q.TimeoutTCP = -1
		q.Protocol = query.DNS_TCP

		res, err := dq.Query(q)

		assert.Nil(t, err, "should not have returned an error")
		require.NotNil(t, res.Response, "should have returned a response")
		assert.NotNil(t, res.Response.ResponseMsg, "should have returned a DNS response")
	})
}
