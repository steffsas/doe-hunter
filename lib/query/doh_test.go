package query_test

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/steffsas/doe-hunter/lib/query"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const exampleUri = "/dns-query{?dns}"
const dohNameQuery = "dns.google."

type mockedHttpQueryHandler struct {
	mock.Mock
}

func (m *mockedHttpQueryHandler) Query(httpReq *http.Request, httpVersion string, timeout time.Duration, transport http.RoundTripper) (*dns.Msg, time.Duration, *tls.ConnectionState, error) {
	args := m.Called(httpReq, httpVersion, timeout, transport)

	var res *dns.Msg
	var tlsConnState *tls.ConnectionState
	var err error

	if args.Get(0) != nil {
		res = args.Get(0).(*dns.Msg)
	}

	if args.Get(2) != nil {
		tlsConnState = args.Get(2).(*tls.ConnectionState)
	}

	if args.Get(3) != nil {
		err = args.Get(3).(error)
	}

	return res, args.Get(1).(time.Duration), tlsConnState, err
}

func getMockedHttpHandler() *mockedHttpQueryHandler {
	handler := new(mockedHttpQueryHandler)
	return handler
}

func TestGetPathParamFromDoHPath_EmptyPath(t *testing.T) {
	t.Parallel()

	t.Run("single param", func(t *testing.T) {
		t.Parallel()

		path, param, err := query.GetPathParamFromDoHPath(exampleUri)

		assert.Nil(t, err, "error should be nil")
		assert.Equal(t, "/dns-query", path)
		assert.Equal(t, "dns", param)
	})

	t.Run("malformed param", func(t *testing.T) {
		t.Parallel()

		path, param, err := query.GetPathParamFromDoHPath("/dns-query?dns")

		assert.NotNil(t, err, "error should not be nil")
		assert.Empty(t, path, "path should be empty")
		assert.Empty(t, param, "param should be empty")
	})

	t.Run("non standard param", func(t *testing.T) {
		t.Parallel()

		path, param, err := query.GetPathParamFromDoHPath("/dns-query{?dns,other}")

		assert.Nil(t, err, "error should be nil")
		assert.Equal(t, "/dns-query", path)
		assert.Equal(t, "dns,other", param)
	})
}

func TestDoHQuery_RealWorld(t *testing.T) {
	t.Parallel()

	// see dig @94.140.14.140 _dns.resolver.arpa. type64
	host := "94.140.14.14"
	port := 443
	uri := exampleUri

	queryMsg := new(dns.Msg)
	queryMsg.SetQuestion("google.de.", dns.TypeA)

	t.Run("retrieve ciphersuite from TLS connection (HTTP2)", func(t *testing.T) {
		t.Parallel()

		qh, err := query.NewDoHQueryHandler(nil)
		require.Nil(t, err, "error should be nil")

		q := query.NewDoHQuery()
		q.Host = host
		q.Port = port
		q.URI = uri
		q.Method = query.HTTP_GET
		q.HTTPVersion = query.HTTP_VERSION_2
		q.QueryMsg = queryMsg

		res, err := qh.Query(q)

		assert.Nil(t, err, "error should be nil")
		require.NotNil(t, res, "result should not be nil")

		assert.Contains(t, res.DoEResponse.TLSCipherSuite, "AES", "ciphersuite should be present")
	})

	t.Run("retrieve ciphersuite from TLS connection (HTTP3)", func(t *testing.T) {
		t.Parallel()

		qh, err := query.NewDoHQueryHandler(nil)
		require.Nil(t, err, "error should be nil")

		q := query.NewDoHQuery()
		q.Host = host
		q.Port = port
		q.URI = uri
		q.Method = query.HTTP_GET
		q.HTTPVersion = query.HTTP_VERSION_3
		q.QueryMsg = queryMsg

		res, err := qh.Query(q)

		assert.Nil(t, err, "error should be nil")
		require.NotNil(t, res, "result should not be nil")

		assert.Contains(t, res.DoEResponse.TLSCipherSuite, "AES", "ciphersuite should be present")
	})

	t.Run("retrieve version from TLS connection (HTTP2)", func(t *testing.T) {
		t.Parallel()

		qh, err := query.NewDoHQueryHandler(nil)
		require.Nil(t, err, "error should be nil")

		q := query.NewDoHQuery()
		q.Host = host
		q.Port = port
		q.URI = uri
		q.Method = query.HTTP_GET
		q.HTTPVersion = query.HTTP_VERSION_2
		q.QueryMsg = queryMsg

		res, err := qh.Query(q)

		assert.Nil(t, err, "error should be nil")
		require.NotNil(t, res, "result should not be nil")

		assert.Contains(t, res.DoEResponse.TLSVersion, "1.", "ciphersuite should be present")
	})

	t.Run("retrieve version from TLS connection (HTTP3)", func(t *testing.T) {
		t.Parallel()

		qh, err := query.NewDoHQueryHandler(nil)
		require.Nil(t, err, "error should be nil")

		q := query.NewDoHQuery()
		q.Host = host
		q.Port = port
		q.URI = uri
		q.Method = query.HTTP_GET
		q.HTTPVersion = query.HTTP_VERSION_3
		q.QueryMsg = queryMsg

		res, err := qh.Query(q)

		assert.Nil(t, err, "error should be nil")
		require.NotNil(t, res, "result should not be nil")

		assert.Contains(t, res.DoEResponse.TLSVersion, "1.", "ciphersuite should be present")
	})

	t.Run("http1 get", func(t *testing.T) {
		t.Parallel()

		qh, err := query.NewDoHQueryHandler(nil)
		require.Nil(t, err, "error should be nil")

		q := query.NewDoHQuery()
		q.Host = host
		q.Port = port
		q.URI = uri
		q.Method = query.HTTP_GET
		q.HTTPVersion = query.HTTP_VERSION_1
		q.QueryMsg = queryMsg

		res, err := qh.Query(q)

		assert.Nil(t, err, "error should be nil")
		require.NotNil(t, res, "result should not be nil")
		require.NotNil(t, res.ResponseMsg, "response should not be nil")
		assert.Greater(t, len(res.ResponseMsg.Answer), 0, "answer should have at least one answer")
		assert.NotEmpty(t, res.RTT.String(), "rtt should not be empty")
	})

	t.Run("http1 post", func(t *testing.T) {
		t.Parallel()

		qh, err := query.NewDoHQueryHandler(nil)
		require.Nil(t, err, "error should be nil")

		q := query.NewDoHQuery()
		q.Host = host
		q.Port = port
		q.URI = uri
		q.Method = query.HTTP_POST
		q.HTTPVersion = query.HTTP_VERSION_1
		q.QueryMsg = queryMsg

		res, err := qh.Query(q)

		assert.Nil(t, err, "error should be nil")
		require.NotNil(t, res, "result should not be nil")
		require.NotNil(t, res.ResponseMsg, "dns response should not be nil")
		assert.Greater(t, len(res.ResponseMsg.Answer), 0, "answer should have at least one answer")
		assert.NotEmpty(t, res.RTT.String(), "rtt should not be empty")
	})

	t.Run("http2 get", func(t *testing.T) {
		t.Parallel()

		qh, err := query.NewDoHQueryHandler(nil)
		require.Nil(t, err, "error should be nil")

		q := query.NewDoHQuery()
		q.Host = host
		q.Port = port
		q.URI = uri
		q.HTTPVersion = query.HTTP_VERSION_2
		q.Method = query.HTTP_GET
		q.QueryMsg = queryMsg

		res, err := qh.Query(q)

		assert.Nil(t, err, "error should be nil")
		require.NotNil(t, res, "result should not be nil")
		require.NotNil(t, res.ResponseMsg, "dns response should not be nil")
		assert.Greater(t, len(res.ResponseMsg.Answer), 0, "answer should have at least one answer")
		assert.NotEmpty(t, res.RTT.String(), "rtt should not be empty")
	})

	t.Run("http2 post", func(t *testing.T) {
		t.Parallel()

		qh, err := query.NewDoHQueryHandler(nil)
		require.Nil(t, err, "error should be nil")

		q := query.NewDoHQuery()
		q.Host = host
		q.Port = port
		q.URI = uri
		q.HTTPVersion = query.HTTP_VERSION_2
		q.Method = query.HTTP_POST
		q.QueryMsg = queryMsg

		res, err := qh.Query(q)

		assert.Nil(t, err, "error should be nil")
		require.NotNil(t, res, "result should not be nil")
		require.NotNil(t, res.ResponseMsg, "dns response should not be nil")
		assert.Greater(t, len(res.ResponseMsg.Answer), 0, "answer should have at least one answer")
		assert.NotEmpty(t, res.RTT.String(), "rtt should not be empty")
	})

	t.Run("http3 get", func(t *testing.T) {
		t.Parallel()

		qh, err := query.NewDoHQueryHandler(nil)
		require.Nil(t, err, "error should be nil")

		q := query.NewDoHQuery()
		q.Host = host
		q.Port = port
		q.URI = uri
		q.HTTPVersion = query.HTTP_VERSION_3
		q.Method = query.HTTP_GET
		q.QueryMsg = queryMsg

		res, err := qh.Query(q)

		assert.Nil(t, err, "error should be nil")
		require.NotNil(t, res, "result should not be nil")
		require.NotNil(t, res.ResponseMsg, "dns response should not be nil")
		assert.Greater(t, len(res.ResponseMsg.Answer), 0, "answer should have at least one answer")
		assert.NotEmpty(t, res.RTT.String(), "rtt should not be empty")
	})

	t.Run("http3 post", func(t *testing.T) {
		t.Parallel()

		qh, err := query.NewDoHQueryHandler(nil)
		require.Nil(t, err, "error should be nil")

		q := query.NewDoHQuery()
		q.Host = host
		q.Port = port
		q.URI = uri
		q.HTTPVersion = query.HTTP_VERSION_3
		q.Method = query.HTTP_POST
		q.QueryMsg = queryMsg

		res, err := qh.Query(q)

		assert.Nil(t, err, "error should be nil")
		require.NotNil(t, res, "result should not be nil")
		require.NotNil(t, res.ResponseMsg, "dns response should not be nil")
		assert.Greater(t, len(res.ResponseMsg.Answer), 0, "answer should have at least one answer")
		assert.NotEmpty(t, res.RTT.String(), "rtt should not be empty")
	})

	t.Run("http3 get dns.google.", func(t *testing.T) {
		t.Parallel()

		qh, err := query.NewDoHQueryHandler(nil)
		require.Nil(t, err, "error should be nil")

		q := query.NewDoHQuery()
		q.Host = "dns.google."
		q.Port = 443
		q.URI = "/dns-query{?dns}"
		q.HTTPVersion = query.HTTP_VERSION_3
		q.Method = query.HTTP_GET
		q.QueryMsg = queryMsg

		res, err := qh.Query(q)

		assert.Nil(t, err, "error should be nil")
		require.NotNil(t, res, "result should not be nil")
		require.NotNil(t, res.ResponseMsg, "dns response should not be nil")
		assert.Greater(t, len(res.ResponseMsg.Answer), 0, "answer should have at least one answer")
		assert.NotEmpty(t, res.RTT.String(), "rtt should not be empty")
	})

	t.Run("cloudflare", func(t *testing.T) {
		t.Parallel()

		qh, err := query.NewDoHQueryHandler(nil)
		require.Nil(t, err, "error should be nil")

		q := query.NewDoHQuery()
		q.Host = "1.1.1.1"
		q.Port = 443
		q.URI = "/dns-query{?dns}"
		q.HTTPVersion = query.HTTP_VERSION_1
		q.Method = query.HTTP_GET
		q.QueryMsg = queryMsg

		res, err := qh.Query(q)

		assert.Nil(t, err, "error should be nil")
		require.NotNil(t, res, "result should not be nil")
		require.NotNil(t, res.ResponseMsg, "dns response should not be nil")
		assert.Greater(t, len(res.ResponseMsg.Answer), 0, "answer should have at least one answer")
		assert.NotEmpty(t, res.RTT.String(), "rtt should not be empty")
	})

	t.Run("test multiple HTTP3 queries on same handler", func(t *testing.T) {
		t.Parallel()

		qh, err := query.NewDoHQueryHandler(nil)
		require.Nil(t, err, "error should be nil")

		for i := 0; i < 10; i++ {
			q := query.NewDoHQuery()
			q.Host = host
			q.Port = port
			q.URI = uri
			q.HTTPVersion = query.HTTP_VERSION_3
			q.Method = query.HTTP_GET
			q.QueryMsg = queryMsg

			res, err := qh.Query(q)

			assert.Nil(t, err, "error should be nil")
			require.NotNil(t, res, "result should not be nil")
			require.NotNil(t, res.ResponseMsg, "dns response should not be nil")
			assert.Greater(t, len(res.ResponseMsg.Answer), 0, "answer should have at least one answer")
			assert.NotEmpty(t, res.RTT.String(), "rtt should not be empty")
		}
	})

	t.Run("test multiple HTTP2 queries on same handler", func(t *testing.T) {
		t.Parallel()

		qh, err := query.NewDoHQueryHandler(nil)
		require.Nil(t, err, "error should be nil")

		for i := 0; i < 10; i++ {
			q := query.NewDoHQuery()
			q.Host = host
			q.Port = port
			q.URI = uri
			q.HTTPVersion = query.HTTP_VERSION_2
			q.Method = query.HTTP_GET
			q.QueryMsg = queryMsg

			res, err := qh.Query(q)

			assert.Nil(t, err, "error should be nil")
			require.NotNil(t, res, "result should not be nil")
			require.NotNil(t, res.ResponseMsg, "dns response should not be nil")
			assert.Greater(t, len(res.ResponseMsg.Answer), 0, "answer should have at least one answer")
			assert.NotEmpty(t, res.RTT.String(), "rtt should not be empty")
		}
	})

	t.Run("test multiple HTTP1 queries on same handler", func(t *testing.T) {
		t.Parallel()

		qh, err := query.NewDoHQueryHandler(nil)
		require.Nil(t, err, "error should be nil")

		for i := 0; i < 10; i++ {
			q := query.NewDoHQuery()
			q.Host = host
			q.Port = port
			q.URI = uri
			q.HTTPVersion = query.HTTP_VERSION_1
			q.Method = query.HTTP_GET
			q.QueryMsg = queryMsg

			res, err := qh.Query(q)

			assert.Nil(t, err, "error should be nil")
			require.NotNil(t, res, "result should not be nil")
			require.NotNil(t, res.ResponseMsg, "dns response should not be nil")
			assert.Greater(t, len(res.ResponseMsg.Answer), 0, "answer should have at least one answer")
			assert.NotEmpty(t, res.RTT.String(), "rtt should not be empty")
		}
	})

	// t.Run("ipv6 h2", func(t *testing.T) {
	// 	t.Parallel()

	// 	qh, err := query.NewDoHQueryHandler(nil)
	// 	require.Nil(t, err, "error should be nil")

	// 	q := query.NewDoHQuery()
	// 	// see dig @94.140.14.14 SVCB _dns.resolver.arpa
	// 	q.Host = "2a10:50c0::ad1:ff"
	// 	q.Port = 443
	// 	q.URI = "/dns-query{?dns}"
	// 	q.HTTPVersion = query.HTTP_VERSION_2
	// 	q.Method = query.HTTP_GET
	// 	q.QueryMsg = queryMsg

	// 	q.SNI = "dns.adguard-dns.com."

	// 	res, err := qh.Query(q)

	// 	assert.Nil(t, err, "error should be nil")
	// 	require.NotNil(t, res, "result should not be nil")
	// 	require.NotNil(t, res.ResponseMsg, "dns response should not be nil")
	// 	assert.Greater(t, len(res.ResponseMsg.Answer), 0, "answer should have at least one answer")
	// 	assert.NotEmpty(t, res.RTT.String(), "rtt should not be empty")
	// })
}

func TestDoHQuery_HTTPVersion(t *testing.T) {
	t.Parallel()

	t.Run("invalid version", func(t *testing.T) {
		t.Parallel()

		handler := getMockedHttpHandler()

		qh, err := query.NewDoHQueryHandler(nil)
		require.Nil(t, err, "error should be nil")
		qh.QueryHandler = handler

		queryMsg := new(dns.Msg)
		queryMsg.SetQuestion(dohNameQuery, dns.TypeA)

		q := query.NewDoHQuery()
		q.Host = dohNameQuery
		q.Port = 443
		q.URI = exampleUri
		q.QueryMsg = queryMsg
		q.HTTPVersion = "false"

		res, err := qh.Query(q)

		assert.NotNil(t, err, "error should not be nil")
		require.NotNil(t, res, "result should not be nil")
		require.Nil(t, res.ResponseMsg, "response should be nil")
	})
}

func TestDoHQuery_HTTPMethod(t *testing.T) {
	t.Parallel()

	t.Run("invalid method", func(t *testing.T) {
		t.Parallel()

		queryMsg := new(dns.Msg)
		queryMsg.SetQuestion(dohNameQuery, dns.TypeA)

		handler := getMockedHttpHandler()

		qh, err := query.NewDoHQueryHandler(nil)
		require.Nil(t, err, "error should be nil")
		qh.QueryHandler = handler

		q := query.NewDoHQuery()
		q.Host = dohNameQuery
		q.Port = 443
		q.URI = exampleUri
		q.QueryMsg = queryMsg
		q.Method = "INVALID"

		res, err := qh.Query(q)

		assert.NotNil(t, err, "error should not be nil")
		require.NotNil(t, res, "result should not be nil")
		assert.Nil(t, res.ResponseMsg, "response should be nil")
	})

	t.Run("post fallback", func(t *testing.T) {
		t.Parallel()

		handler := getMockedHttpHandler()
		handler.On("Query",
			mock.Anything,
			mock.Anything,
			mock.Anything,
			mock.Anything).Return(&dns.Msg{}, 1*time.Millisecond, nil, nil)

		qh, err := query.NewDoHQueryHandler(nil)
		require.Nil(t, err, "error should be nil")

		qh.QueryHandler = handler

		queryMsg := new(dns.Msg)
		queryMsg.SetQuestion(dohNameQuery, dns.TypeA)
		queryMsg.Extra = make([]dns.RR, 1000)

		for i := 0; i < 1000; i++ {
			queryMsg.Extra[i] = new(dns.OPT)
		}

		q := query.NewDoHQuery()
		q.Host = dohNameQuery
		q.Port = 443
		q.URI = "/dns-query{?dns}"
		q.QueryMsg = queryMsg
		q.Method = query.HTTP_GET
		q.POSTFallback = true

		res, err := qh.Query(q)

		assert.NoError(t, err, "error should be nil")
		require.NotNil(t, res, "result should not be nil")
		assert.GreaterOrEqual(t, res.RTT, time.Duration(0), "rtt should not be empty")
	})

	t.Run("no post fallback if not wanted", func(t *testing.T) {
		t.Parallel()

		handler := getMockedHttpHandler()

		qh, err := query.NewDoHQueryHandler(nil)
		require.Nil(t, err, "error should be nil")

		qh.QueryHandler = handler

		queryMsg := new(dns.Msg)
		queryMsg.SetQuestion(dohNameQuery, dns.TypeA)
		queryMsg.Extra = make([]dns.RR, 1000)

		for i := 0; i < 1000; i++ {
			queryMsg.Extra[i] = new(dns.OPT)
		}

		q := query.NewDoHQuery()
		q.Host = dohNameQuery
		q.Port = 443
		q.URI = "/dns-query{?dns,other}"
		q.QueryMsg = queryMsg
		q.Method = query.HTTP_GET
		q.POSTFallback = false

		res, err := qh.Query(q)

		assert.Error(t, err, "error should be nil")
		require.NotNil(t, res, "result should not be nil")
		require.Nil(t, res.ResponseMsg, "response should not be nil")
	})
}

func TestDoHQuery_Port(t *testing.T) {
	t.Parallel()

	t.Run("default port", func(t *testing.T) {
		t.Parallel()

		handler := getMockedHttpHandler()
		handler.On("Query",
			mock.Anything,
			mock.Anything,
			mock.Anything,
			mock.Anything).Return(&dns.Msg{}, 1*time.Millisecond, nil, nil)

		qh, err := query.NewDoHQueryHandler(nil)
		require.Nil(t, err, "error should be nil")
		qh.QueryHandler = handler

		queryMsg := new(dns.Msg)
		queryMsg.SetQuestion(dohNameQuery, dns.TypeA)

		q := query.NewDoHQuery()
		q.Host = dohNameQuery
		q.URI = exampleUri
		q.QueryMsg = queryMsg

		res, err := qh.Query(q)

		assert.Nil(t, err, "error should be nil")
		require.NotNil(t, res, "result should not be nil")
		require.NotNil(t, res.ResponseMsg, "dns response should not be nil")
		assert.Equal(t, query.DEFAULT_DOH_PORT, q.Port, "port should be set by default")
	})

	t.Run("negative port", func(t *testing.T) {
		t.Parallel()

		handler := getMockedHttpHandler()

		qh, err := query.NewDoHQueryHandler(nil)
		require.Nil(t, err, "error should be nil")
		qh.QueryHandler = handler

		q := query.NewDoHQuery()
		q.Host = dohNameQuery
		q.Port = -1
		q.URI = exampleUri

		res, err := qh.Query(q)

		assert.NotNil(t, err, "error should not be nil")
		require.NotNil(t, res, "result should not be nil")
		require.Nil(t, res.ResponseMsg, "response should be nil")
	})

	t.Run("too large port", func(t *testing.T) {
		t.Parallel()

		handler := getMockedHttpHandler()

		qh, err := query.NewDoHQueryHandler(nil)
		require.Nil(t, err, "error should be nil")
		qh.QueryHandler = handler

		q := query.NewDoHQuery()
		q.Host = dohNameQuery
		q.Port = 65536
		q.URI = exampleUri

		res, err := qh.Query(q)

		assert.NotNil(t, err, "error should not be nil")
		require.NotNil(t, res, "result should not be nil")
		assert.Nil(t, res.ResponseMsg, "response should be nil")
	})
}

func TestDoHQuery_DefaultTimeoutFallback(t *testing.T) {
	t.Parallel()

	handler := getMockedHttpHandler()
	handler.On("Query",
		mock.Anything,
		mock.Anything,
		mock.Anything,
		mock.Anything).Return(&dns.Msg{}, 1*time.Millisecond, nil, nil)

	qh, err := query.NewDoHQueryHandler(nil)
	require.Nil(t, err, "error should be nil")
	qh.QueryHandler = handler

	queryMsg := new(dns.Msg)
	queryMsg.SetQuestion(dohNameQuery, dns.TypeA)

	q := query.NewDoHQuery()
	q.Host = dohNameQuery
	q.URI = exampleUri
	q.QueryMsg = queryMsg

	res, err := qh.Query(q)

	// c.Arguments.Assert(t, DEFAULT_DOH_TIMEOUT*time.Millisecond)

	assert.Nil(t, err, "error should be nil")
	require.NotNil(t, res, "result should not be nil")
	assert.NotNil(t, res.ResponseMsg, "response should not be nil")
}

func TestDoHQuery_NoHostProvided(t *testing.T) {
	t.Parallel()

	handler := getMockedHttpHandler()

	qh, err := query.NewDoHQueryHandler(nil)
	require.Nil(t, err, "error should be nil")
	qh.QueryHandler = handler

	queryMsg := new(dns.Msg)
	queryMsg.SetQuestion(dohNameQuery, dns.TypeA)

	q := query.NewDoHQuery()
	q.URI = exampleUri
	q.QueryMsg = queryMsg

	res, err := qh.Query(q)

	assert.NotNil(t, err, "error should not be nil")
	require.NotNil(t, res, "result should not be nil")
	assert.Nil(t, res.ResponseMsg, "response should be nil")
}

func TestDoHQuery_EmptyURI(t *testing.T) {
	t.Parallel()

	handler := getMockedHttpHandler()

	qh, err := query.NewDoHQueryHandler(nil)
	require.Nil(t, err, "error should be nil")
	qh.QueryHandler = handler

	queryMsg := new(dns.Msg)
	queryMsg.SetQuestion(dohNameQuery, dns.TypeA)

	q := query.NewDoHQuery()
	q.Host = dohNameQuery
	q.URI = ""
	q.QueryMsg = queryMsg

	res, err := qh.Query(q)

	assert.NotNil(t, err, "error should not be nil")
	require.NotNil(t, res, "result should not be nil")
	assert.Nil(t, res.ResponseMsg, "response should be nil")
}

func TestDoHQuery_NilQueryMsg(t *testing.T) {
	t.Parallel()

	handler := getMockedHttpHandler()

	qh, err := query.NewDoHQueryHandler(nil)
	require.Nil(t, err, "error should be nil")
	qh.QueryHandler = handler

	q := query.NewDoHQuery()
	q.Host = dohNameQuery
	q.Port = 443
	q.URI = exampleUri
	q.QueryMsg = nil

	res, err := qh.Query(q)

	assert.Error(t, err, "error should not be nil")
	require.NotNil(t, res, "result should not be nil")
	assert.Nil(t, res.ResponseMsg, "response should be nil")
}

func TestDoHQuery_WronglyFormattedURI(t *testing.T) {
	t.Parallel()

	handler := getMockedHttpHandler()

	qh, err := query.NewDoHQueryHandler(nil)
	require.Nil(t, err, "error should be nil")
	qh.QueryHandler = handler

	queryMsg := new(dns.Msg)
	queryMsg.SetQuestion(dohNameQuery, dns.TypeA)

	q := query.NewDoHQuery()
	q.Host = dohNameQuery
	// should be /dns-query{?dns}
	q.URI = "/dns-query?dns"
	q.QueryMsg = queryMsg

	res, err := qh.Query(q)

	assert.NotNil(t, err, "error should not be nil")
	require.NotNil(t, res, "result should not be nil")
	assert.Nil(t, res.ResponseMsg, "response should be nil")
}

func TestDoHQuery_NilHttpHandler(t *testing.T) {
	t.Parallel()

	queryMsg := new(dns.Msg)
	queryMsg.SetQuestion(dohNameQuery, dns.TypeA)

	qh, err := query.NewDoHQueryHandler(nil)
	require.Nil(t, err, "error should be nil")
	qh.QueryHandler = nil

	q := query.NewDoHQuery()
	q.Host = dohNameQuery
	q.Port = 443
	q.URI = exampleUri
	q.QueryMsg = queryMsg

	res, err := qh.Query(q)

	assert.NotNil(t, err, "error should not be nil")
	require.NotNil(t, res, "result should not be nil")
	assert.Nil(t, res.ResponseMsg, "DNS response should be nil since handler was not set")
}

func TestDoHQuery_EmptyQuery(t *testing.T) {
	t.Parallel()

	qh, err := query.NewDoHQueryHandler(nil)
	require.Nil(t, err, "error should be nil")
	res, err := qh.Query(nil)

	assert.NotNil(t, err, "error should not be nil")
	require.NotNil(t, res, "result should not be nil")
	assert.Nil(t, res.ResponseMsg, "DNS response should be nil since handler was not set")
}

func TestDoHQuery_SNI(t *testing.T) {
	t.Parallel()

	handler := getMockedHttpHandler()
	handler.On("Query",
		mock.Anything,
		mock.Anything,
		mock.Anything,
		mock.Anything).Return(&dns.Msg{}, 1*time.Millisecond, nil, nil)

	qh, err := query.NewDoHQueryHandler(nil)
	require.Nil(t, err, "error should be nil")
	qh.QueryHandler = handler

	queryMsg := new(dns.Msg)
	queryMsg.SetQuestion(dohNameQuery, dns.TypeA)

	q := query.NewDoHQuery()
	q.Host = dohNameQuery
	q.Port = 443
	q.URI = exampleUri
	q.QueryMsg = queryMsg
	q.SNI = "example.com"

	res, err := qh.Query(q)

	assert.Nil(t, err, "error should be nil")
	require.NotNil(t, res, "result should not be nil")
	require.NotNil(t, res.ResponseMsg, "response should not be nil")
}

func TestDoHQueryHandler_HttpRequest(t *testing.T) {
	t.Parallel()

	t.Run("successful request", func(t *testing.T) {
		t.Parallel()

		handler := getMockedHttpHandler()
		handler.On("Query",
			mock.Anything,
			mock.Anything,
			mock.Anything,
			mock.Anything).Return(&dns.Msg{}, 1*time.Millisecond, nil, nil)

		qh, err := query.NewDoHQueryHandler(nil)
		require.Nil(t, err, "error should be nil")
		qh.QueryHandler = handler

		queryMsg := new(dns.Msg)
		queryMsg.SetQuestion(dohNameQuery, dns.TypeA)

		q := query.NewDoHQuery()
		q.Host = dohNameQuery
		q.Port = 443
		q.URI = exampleUri
		q.QueryMsg = queryMsg

		res, err := qh.Query(q)

		assert.Nil(t, err, "error should be nil")
		require.NotNil(t, res, "result should not be nil")
		require.NotNil(t, res.ResponseMsg, "response should not be nil")
	})

	t.Run("failed request", func(t *testing.T) {
		t.Parallel()

		handler := getMockedHttpHandler()
		handler.On("Query",
			mock.Anything,
			mock.Anything,
			mock.Anything,
			mock.Anything).Return(nil, 1*time.Millisecond, nil, fmt.Errorf("error"))

		qh, err := query.NewDoHQueryHandler(nil)
		require.Nil(t, err, "error should be nil")
		qh.QueryHandler = handler

		queryMsg := new(dns.Msg)
		queryMsg.SetQuestion(dohNameQuery, dns.TypeA)

		q := query.NewDoHQuery()
		q.Host = dohNameQuery
		q.Port = 443
		q.URI = exampleUri
		q.QueryMsg = queryMsg

		res, err := qh.Query(q)

		assert.NotNil(t, err, "error should not be nil")
		require.NotNil(t, res, "result should not be nil")
		assert.Nil(t, res.ResponseMsg, "response should be nil")
	})
}

func TestDohQueryHandler_Config(t *testing.T) {
	t.Parallel()

	t.Run("no config", func(t *testing.T) {
		t.Parallel()

		qh, err := query.NewDoHQueryHandler(nil)
		require.Nil(t, err, "error should be nil")
		require.NotNil(t, qh, "query handler should not be nil")
	})

	t.Run("with config", func(t *testing.T) {
		t.Parallel()

		config := &query.QueryConfig{
			LocalAddr: net.IP{127, 0, 0, 1},
		}

		qh, err := query.NewDoHQueryHandler(config)
		require.Nil(t, err, "error should be nil")
		require.NotNil(t, qh, "query handler should not be nil")
	})
}
