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

func getDefaultQuery() *query.ConventionalDNSQuery {
	sleeper := &mockedSleeper{}
	sleeper.On("Sleep", mock.Anything).Return()

	q := &dns.Msg{}
	q.SetQuestion("google.com.", dns.TypeA)

	dnsQuery := query.NewConventionalDNSQuery()
	dnsQuery.QueryHandler = query.NewDefaultQueryHandler()
	dnsQuery.QueryMsg = q
	dnsQuery.Sleeper = sleeper
	dnsQuery.Host = "8.8.8.8"

	return dnsQuery
}

func TestDNSQuery_RealWorld(t *testing.T) {
	t.Run("hostname", func(t *testing.T) {
		dq := getDefaultQuery()
		dq.Host = "dns.google."
		dq.Port = 53

		res, err := dq.Query()

		require.NotNil(t, res, "response should not be nil")
		assert.Nil(t, err, "error should be nil")
		require.NotNil(t, res.ResponseMsg, "response should not be nil")
		assert.NotNil(t, res.ResponseMsg.Answer, "response should have an answer")
	})

	t.Run("IPv4", func(t *testing.T) {
		dq := getDefaultQuery()
		dq.Host = "8.8.8.8"
		dq.Port = 53

		res, err := dq.Query()

		require.NotNil(t, res, "response should not be nil")
		assert.Nil(t, err, "error should be nil")
		require.NotNil(t, res.ResponseMsg, "response should not be nil")
		assert.NotNil(t, res.ResponseMsg.Answer, "response should have an answer")
	})

	// t.Run("IPv6", func(t *testing.T) {
	// 	dq := getDefaultQuery()
	// 	dq.Host = "2001:4860:4860::8888" // google-public-dns-a.google.com

	// 	res, err := dq.Query()

	// 	require.NotNil(t, res, "response should not be nil")
	// 	assert.Nil(t, err, "error should be nil")
	// 	require.NotNil(t, res.ResponseMsg, "response should not be nil")
	// 	assert.NotNil(t, res.ResponseMsg.Answer, "response should have an answer")
	// })
}

// TestDNSQuery_InvalidProtocol tests the DNS query with an invalid protocol
func TestDNSQuery_InvalidProtocol(t *testing.T) {
	dq := getDefaultQuery()
	dq.Protocol = "invalid"

	_, err := dq.Query()
	assert.NotNil(t, err, "should have returned an error")
}

func TestDNSQuery_UDPAttempts(t *testing.T) {
	t.Run("one attempt on success", func(t *testing.T) {
		response := &dns.Msg{}

		handler := &mockedQueryHandler{}
		handler.On("Query", mock.Anything, mock.Anything, query.DNS_UDP, mock.Anything, mock.Anything).Return(response, time.Duration(0), nil)

		dq := getDefaultQuery()
		dq.QueryHandler = handler

		res, err := dq.Query()

		assert.Nil(t, err, "should not have returned an error")
		assert.Equal(t, 1, res.UDPAttempts, "should have exactly one UDP attempt")
		assert.Equal(t, response, res.ResponseMsg, "should have returned the response")
	})

	t.Run("max attempts on failure", func(t *testing.T) {
		handler := &mockedQueryHandler{}
		handler.On("Query", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil, time.Duration(0), fmt.Errorf("no response"))

		dq := getDefaultQuery()
		dq.QueryHandler = handler
		dq.MaxUDPRetries = 3

		res, err := dq.Query()

		assert.NotNil(t, err, "should have returned an error")
		assert.Equal(t, dq.MaxUDPRetries, res.UDPAttempts, "should have exactly max UDP attempts")
		assert.Nil(t, res.ResponseMsg, "should not have returned a DNS response")
	})
}

func TestDNSQuery_UDPRetries(t *testing.T) {
	t.Run("fallback", func(t *testing.T) {
		response := &dns.Msg{}

		handler := &mockedQueryHandler{}
		handler.On("Query", mock.Anything, mock.Anything, query.DNS_UDP, mock.Anything, mock.Anything).Return(response, time.Duration(0), nil)

		dq := getDefaultQuery()
		dq.QueryHandler = handler

		res, err := dq.Query()

		assert.Nil(t, err, "should not have returned an error")
		assert.Equal(t, dq.MaxUDPRetries, query.DEFAULT_UDP_RETRIES, "should fall back to default retries")
		assert.Equal(t, response, res.ResponseMsg, "should have returned the response")
	})

	t.Run("fallback on negative retries", func(t *testing.T) {
		response := &dns.Msg{}

		handler := &mockedQueryHandler{}
		handler.On("Query", mock.Anything, mock.Anything, query.DNS_UDP, mock.Anything, mock.Anything).Return(response, time.Duration(0), nil)

		dq := getDefaultQuery()
		dq.QueryHandler = handler
		dq.MaxUDPRetries = -1

		res, err := dq.Query()

		assert.Nil(t, err, "should not have returned an error")
		assert.Equal(t, query.DEFAULT_UDP_RETRIES, dq.MaxUDPRetries, "should fall back to default retries")
		assert.Equal(t, response, res.ResponseMsg, "should have returned the response")
	})
}

func TestDNSQuery_TCPAttempts(t *testing.T) {
	t.Run("one attempt on success", func(t *testing.T) {
		response := &dns.Msg{}

		handler := &mockedQueryHandler{}
		handler.On("Query", mock.Anything, mock.Anything, query.DNS_TCP, mock.Anything, mock.Anything).Return(response, time.Duration(0), nil)

		dq := getDefaultQuery()
		dq.QueryHandler = handler
		dq.Protocol = query.DNS_TCP

		res, err := dq.Query()

		assert.Nil(t, err, "should not have returned an error")
		assert.Equal(t, 1, res.TCPAttempts, "should have exactly one TCP attempt")
		assert.Equal(t, response, res.ResponseMsg, "should have returned the response")
	})

	t.Run("max attempts on failure", func(t *testing.T) {
		handler := &mockedQueryHandler{}
		handler.On("Query", mock.Anything, mock.Anything, query.DNS_TCP, mock.Anything, mock.Anything).Return(nil, time.Duration(0), fmt.Errorf("no response"))

		dq := getDefaultQuery()
		dq.QueryHandler = handler
		dq.Protocol = query.DNS_TCP
		dq.MaxTCPRetries = 3

		res, err := dq.Query()

		assert.NotNil(t, err, "should have returned an error")
		assert.Equal(t, dq.MaxTCPRetries, res.TCPAttempts, "should have exactly max TCP attempts")
		assert.Nil(t, res.ResponseMsg, "should not have returned a response")
	})
}

func TestDNSQuery_TCPRetries(t *testing.T) {
	t.Run("fallback", func(t *testing.T) {
		response := &dns.Msg{}

		handler := &mockedQueryHandler{}
		handler.On("Query", mock.Anything, mock.Anything, query.DNS_TCP, mock.Anything, mock.Anything).Return(response, time.Duration(0), nil)

		dq := getDefaultQuery()
		dq.QueryHandler = handler
		dq.Protocol = query.DNS_TCP

		res, err := dq.Query()

		assert.Nil(t, err, "should not have returned an error")
		assert.Equal(t, query.DEFAULT_TCP_RETRIES, dq.MaxTCPRetries, "should fall back to default retries")
		assert.Equal(t, response, res.ResponseMsg, "should have returned the response")
	})

	t.Run("fallback on negative retries", func(t *testing.T) {
		response := &dns.Msg{}

		handler := &mockedQueryHandler{}
		handler.On("Query", mock.Anything, mock.Anything, query.DNS_TCP, mock.Anything, mock.Anything).Return(response, time.Duration(0), nil)

		dq := getDefaultQuery()
		dq.QueryHandler = handler
		dq.Protocol = query.DNS_TCP
		dq.MaxTCPRetries = -1

		res, err := dq.Query()

		assert.Nil(t, err, "should not have returned an error")
		assert.Equal(t, query.DEFAULT_TCP_RETRIES, dq.MaxTCPRetries, "should fall back to default retries")
		assert.Equal(t, response, res.ResponseMsg, "should have returned the response")
	})
}

func TestDNSQuery_TCPFallback(t *testing.T) {
	t.Run("fallback on udp error", func(t *testing.T) {
		response := &dns.Msg{}

		handler := &mockedQueryHandler{}
		handler.On("Query", mock.Anything, mock.Anything, query.DNS_UDP, mock.Anything, mock.Anything).Return(nil, time.Duration(0), fmt.Errorf("no response"))
		handler.On("Query", mock.Anything, mock.Anything, query.DNS_TCP, mock.Anything, mock.Anything).Return(response, time.Duration(0), nil)

		dq := getDefaultQuery()
		dq.QueryHandler = handler
		dq.AutoFallbackTCP = true
		dq.Protocol = query.DNS_UDP

		res, err := dq.Query()

		assert.Nil(t, err, "should not have returned an error")
		assert.Equal(t, dq.MaxUDPRetries, res.UDPAttempts, "should have tried UDP max times")
		assert.Equal(t, 1, res.TCPAttempts, "should have exactly one TCP attempt")
		assert.Equal(t, response, res.ResponseMsg, "should have returned the response")
	})

	t.Run("no fallback if not set", func(t *testing.T) {
		response := &dns.Msg{}

		handler := &mockedQueryHandler{}
		handler.On("Query", mock.Anything, mock.Anything, query.DNS_UDP, mock.Anything, mock.Anything).Return(nil, time.Duration(0), fmt.Errorf("no response"))
		handler.On("Query", mock.Anything, mock.Anything, query.DNS_TCP, mock.Anything, mock.Anything).Return(response, time.Duration(0), nil)

		dq := getDefaultQuery()
		dq.QueryHandler = handler
		dq.AutoFallbackTCP = false
		dq.Protocol = query.DNS_UDP

		res, err := dq.Query()

		assert.NotNil(t, err, "should have returned an error (no response)")
		assert.Equal(t, dq.MaxUDPRetries, res.UDPAttempts, "should have tried UDP max times")
		assert.Equal(t, 0, res.TCPAttempts, "should have no TCP attempt")
		assert.Nil(t, res.ResponseMsg, "should not have returned a response")
	})

	t.Run("fallback on truncation bit", func(t *testing.T) {
		responseUDP := &dns.Msg{}
		responseUDP.Truncated = true

		responseTCP := &dns.Msg{}

		handler := &mockedQueryHandler{}
		handler.On("Query", mock.Anything, mock.Anything, query.DNS_UDP, mock.Anything, mock.Anything).Return(responseUDP, time.Duration(0), nil)
		handler.On("Query", mock.Anything, mock.Anything, query.DNS_TCP, mock.Anything, mock.Anything).Return(responseTCP, time.Duration(0), nil)

		dq := getDefaultQuery()
		dq.QueryHandler = handler
		dq.AutoFallbackTCP = true

		res, err := dq.Query()

		assert.Nil(t, err, "should not have returned an error")
		assert.Equal(t, 1, res.UDPAttempts, "should have tried UDP once")
		assert.Equal(t, 1, res.TCPAttempts, "should have tried TCP")
		assert.Equal(t, responseTCP, res.ResponseMsg, "should have returned the TCP response")
	})

	t.Run("no fallback on truncation bit if TCP fallback is not wanted", func(t *testing.T) {
		responseUDP := &dns.Msg{}
		responseUDP.Truncated = true

		responseTCP := &dns.Msg{}

		handler := &mockedQueryHandler{}
		handler.On("Query", mock.Anything, mock.Anything, query.DNS_UDP, mock.Anything, mock.Anything).Return(responseUDP, time.Duration(0), nil)
		handler.On("Query", mock.Anything, mock.Anything, query.DNS_TCP, mock.Anything, mock.Anything).Return(responseTCP, time.Duration(0), nil)

		dq := getDefaultQuery()
		dq.QueryHandler = handler
		dq.AutoFallbackTCP = false

		res, err := dq.Query()

		assert.Nil(t, err, "should not have returned an error")
		assert.Equal(t, 1, res.UDPAttempts, "should have tried UDP once")
		assert.Equal(t, 0, res.TCPAttempts, "should not have tried TCP")
		assert.Equal(t, responseUDP, res.ResponseMsg, "should have returned the UDP response")
	})
}

func TestDNSQuery_Protocol(t *testing.T) {
	t.Run("udp", func(t *testing.T) {
		response := &dns.Msg{}

		handler := &mockedQueryHandler{}
		handler.On("Query", mock.Anything, mock.Anything, query.DNS_UDP, mock.Anything, mock.Anything).Return(response, time.Duration(0), nil)

		dq := getDefaultQuery()
		dq.QueryHandler = handler
		dq.Protocol = query.DNS_UDP

		res, err := dq.Query()

		assert.Nil(t, err, "should not have returned an error")
		assert.Equal(t, 1, res.UDPAttempts, "should have exactly one UDP attempt")
		assert.Equal(t, 0, res.TCPAttempts, "should have no TCP attempt")
		assert.Equal(t, response, res.ResponseMsg, "should have returned the response")
	})

	t.Run("tcp", func(t *testing.T) {
		response := &dns.Msg{}

		handler := &mockedQueryHandler{}
		handler.On("Query", mock.Anything, mock.Anything, query.DNS_TCP, mock.Anything, mock.Anything).Return(response, time.Duration(0), nil)

		dq := getDefaultQuery()
		dq.QueryHandler = handler
		dq.Protocol = query.DNS_TCP

		res, err := dq.Query()

		assert.Nil(t, err, "should not have returned an error")
		assert.Equal(t, 0, res.UDPAttempts, "should have no UDP attempt")
		assert.Equal(t, 1, res.TCPAttempts, "should have exactly one TCP attempt")
		assert.Equal(t, response, res.ResponseMsg, "should have returned the response")
	})
}

func TestDNSQuery_EmptyHost(t *testing.T) {
	handler := &mockedQueryHandler{}
	handler.On("Query", mock.Anything, mock.Anything, query.DNS_UDP, mock.Anything, mock.Anything).Return(nil, time.Duration(0), fmt.Errorf("no UDP response"))
	handler.On("Query", mock.Anything, mock.Anything, query.DNS_TCP, mock.Anything, mock.Anything).Return(nil, time.Duration(0), fmt.Errorf("no TCP response"))

	dq := getDefaultQuery()
	dq.QueryHandler = handler
	dq.Host = ""

	res, err := dq.Query()

	assert.NotNil(t, err, "should have returned an error")
	require.NotNil(t, res, "response should not be nil")
	assert.Equal(t, 0, res.UDPAttempts, "should not have tried UDP")
	assert.Equal(t, 0, res.TCPAttempts, "should not have tried TCP")
	assert.Nil(t, res.ResponseMsg, "should not have returned any response")
}

func TestDNSQuery_NilQueryMessage(t *testing.T) {
	handler := &mockedQueryHandler{}
	handler.On("Query", mock.Anything, mock.Anything, query.DNS_UDP, mock.Anything, mock.Anything).Return(nil, time.Duration(0), fmt.Errorf("no UDP response"))
	handler.On("Query", mock.Anything, mock.Anything, query.DNS_TCP, mock.Anything, mock.Anything).Return(nil, time.Duration(0), fmt.Errorf("no TCP response"))

	dq := getDefaultQuery()
	dq.QueryHandler = handler
	dq.QueryMsg = nil

	res, err := dq.Query()

	assert.NotNil(t, err, "should have returned an error")
	require.NotNil(t, res, "response should not be nil")
	assert.Equal(t, 0, res.UDPAttempts, "should not have tried UDP")
	assert.Equal(t, 0, res.TCPAttempts, "should not have tried TCP")
	assert.Nil(t, res.ResponseMsg, "should not have returned any response")
}

func TestDNSQuery_NilQueryHandler(t *testing.T) {
	dq := getDefaultQuery()
	dq.QueryHandler = nil

	res, err := dq.Query()

	assert.NotNil(t, err, "should have returned an error")
	require.NotNil(t, res, "response should not be nil")
	assert.Equal(t, 0, res.UDPAttempts, "should not have tried UDP")
	assert.Equal(t, 0, res.TCPAttempts, "should not have tried TCP")
	assert.Nil(t, res.ResponseMsg, "should not have returned any response")
}

func TestDNSQuery_Port(t *testing.T) {
	t.Run("negative port", func(t *testing.T) {
		handler := &mockedQueryHandler{}
		handler.On("Query", mock.Anything, mock.Anything, query.DNS_UDP, mock.Anything, mock.Anything).Return(nil, time.Duration(0), fmt.Errorf("no UDP response"))
		handler.On("Query", mock.Anything, mock.Anything, query.DNS_TCP, mock.Anything, mock.Anything).Return(nil, time.Duration(0), fmt.Errorf("no TCP response"))

		dq := getDefaultQuery()
		dq.QueryHandler = handler
		dq.Port = -1

		res, err := dq.Query()

		assert.NotNil(t, err, "should have returned an error")
		require.NotNil(t, res, "response should not be nil")
		assert.Equal(t, 0, res.UDPAttempts, "should not have tried UDP")
		assert.Equal(t, 0, res.TCPAttempts, "should not have tried TCP")
		assert.Nil(t, res.ResponseMsg, "should not have returned any response")
	})

	t.Run("too large port", func(t *testing.T) {
		handler := &mockedQueryHandler{}
		handler.On("Query", mock.Anything, mock.Anything, query.DNS_UDP, mock.Anything, mock.Anything).Return(nil, time.Duration(0), fmt.Errorf("no UDP response"))
		handler.On("Query", mock.Anything, mock.Anything, query.DNS_TCP, mock.Anything, mock.Anything).Return(nil, time.Duration(0), fmt.Errorf("no TCP response"))

		dq := getDefaultQuery()
		dq.QueryHandler = handler
		dq.Port = 70000

		res, err := dq.Query()

		assert.NotNil(t, err, "should have returned an error")
		require.NotNil(t, res, "response should not be nil")
		assert.Equal(t, 0, res.UDPAttempts, "should not have tried UDP")
		assert.Equal(t, 0, res.TCPAttempts, "should not have tried TCP")
		assert.Nil(t, res.ResponseMsg, "should not have returned any response")
	})

	t.Run("default port fallback", func(t *testing.T) {
		msg := dns.Msg{}
		handler := &mockedQueryHandler{}
		handler.On("Query", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(msg, time.Duration(0), nil)

		dq := getDefaultQuery()
		dq.QueryHandler = handler
		dq.Port = 0

		res, err := dq.Query()

		assert.NotNil(t, err, "should have returned an error")
		assert.Nil(t, res.ResponseMsg, "response DNS should be nil")
		assert.Equal(t, 0, res.UDPAttempts, "should not have tried UDP")
		assert.Equal(t, 0, res.TCPAttempts, "should not have tried TCP")
	})
}

func TestDNSQuery_UDPTimeout(t *testing.T) {
	t.Run("negative timeout", func(t *testing.T) {
		response := &dns.Msg{}

		handler := &mockedQueryHandler{}
		handler.On("Query", mock.Anything, mock.Anything, query.DNS_UDP, mock.Anything, mock.Anything).Return(response, time.Duration(0), nil)

		dq := getDefaultQuery()
		dq.QueryHandler = handler
		dq.TimeoutUDP = -1

		res, err := dq.Query()

		assert.Nil(t, err, "should not have returned an error")
		assert.Equal(t, query.DEFAULT_UDP_TIMEOUT, dq.TimeoutUDP, "should have used the default UDP timeout")
		require.NotNil(t, res, "response should not be nil")
	})

	t.Run("accept zero timeout", func(t *testing.T) {
		response := &dns.Msg{}

		handler := &mockedQueryHandler{}
		handler.On("Query", mock.Anything, mock.Anything, query.DNS_UDP, mock.Anything, mock.Anything).Return(response, time.Duration(0), nil)

		dq := getDefaultQuery()
		dq.QueryHandler = handler
		dq.TimeoutUDP = 0

		res, err := dq.Query()

		assert.Nil(t, err, "should not have returned an error")
		require.NotNil(t, res, "response should not be nil")
		assert.Equal(t, 0*time.Millisecond, dq.TimeoutUDP, "should have used the zero timeout value")
	})

	t.Run("use timeout over UDPTimeout", func(t *testing.T) {
		response := &dns.Msg{}

		handler := &mockedQueryHandler{}
		handler.On("Query", mock.Anything, mock.Anything, query.DNS_UDP, mock.Anything, mock.Anything).Return(response, time.Duration(0), nil)

		dq := getDefaultQuery()
		dq.QueryHandler = handler
		dq.Timeout = 1000 * time.Millisecond
		dq.TimeoutUDP = -1

		res, err := dq.Query()

		assert.Nil(t, err, "should not have returned an error")
		require.NotNil(t, res, "response should not be nil")
		assert.Equal(t, 1000*time.Millisecond, dq.TimeoutUDP, "should have used the timeout value")
	})
}

func TestDNSQuery_TCPTimeout(t *testing.T) {
	t.Run("negative timeout", func(t *testing.T) {
		response := &dns.Msg{}

		handler := &mockedQueryHandler{}
		handler.On("Query", mock.Anything, mock.Anything, query.DNS_TCP, mock.Anything, mock.Anything).Return(response, time.Duration(0), nil)

		dq := getDefaultQuery()
		dq.QueryHandler = handler
		dq.TimeoutTCP = -1
		dq.Protocol = query.DNS_TCP

		res, err := dq.Query()

		assert.Nil(t, err, "should not have returned an error")
		assert.Equal(t, query.DEFAULT_TCP_TIMEOUT, dq.TimeoutTCP, "should have used the default TCP timeout")
		require.NotNil(t, res, "response should not be nil")
	})

	t.Run("accept zero timeout", func(t *testing.T) {
		response := &dns.Msg{}

		handler := &mockedQueryHandler{}
		handler.On("Query", mock.Anything, mock.Anything, query.DNS_TCP, mock.Anything, mock.Anything).Return(response, time.Duration(0), nil)

		dq := getDefaultQuery()
		dq.QueryHandler = handler
		dq.TimeoutTCP = 0
		dq.Protocol = query.DNS_TCP

		res, err := dq.Query()

		assert.Nil(t, err, "should not have returned an error")
		require.NotNil(t, res, "response should not be nil")
		assert.Equal(t, 0*time.Millisecond, dq.TimeoutTCP, "should have used the zero timeout value")
	})

	t.Run("use timeout over TCPTimeout", func(t *testing.T) {
		response := &dns.Msg{}

		handler := &mockedQueryHandler{}
		handler.On("Query", mock.Anything, mock.Anything, query.DNS_TCP, mock.Anything, mock.Anything).Return(response, time.Duration(0), nil)

		dq := getDefaultQuery()
		dq.QueryHandler = handler
		dq.Timeout = 1000 * time.Millisecond
		dq.TimeoutTCP = -1
		dq.Protocol = query.DNS_TCP

		res, err := dq.Query()

		assert.Nil(t, err, "should not have returned an error")
		require.NotNil(t, res, "response should not be nil")
		assert.Equal(t, 1000*time.Millisecond, dq.TimeoutTCP, "should have used the timeout value")
	})
}
