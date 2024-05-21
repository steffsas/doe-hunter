package query_test

import (
	"bytes"
	"fmt"
	"io"
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

type mockedHttpHandler struct {
	mock.Mock
}

func (m *mockedHttpHandler) Do(req *http.Request) (*http.Response, error) {
	args := m.Called(req)

	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(*http.Response), args.Error(1)
}

func (m *mockedHttpHandler) SetTransport(t http.RoundTripper) {
	m.Called(t)
}

func (m *mockedHttpHandler) SetTimeout(timeout time.Duration) {
	m.Called(timeout)
}

func (m *mockedHttpHandler) GetTimeout() time.Duration {
	args := m.Called()
	return args.Get(0).(time.Duration)
}

func mockDnsMsgHttpResponse() *http.Response {
	aRR := new(dns.A)
	aRR.Hdr = dns.RR_Header{Name: dohNameQuery, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}
	aRR.A = net.IPv4(8, 8, 8, 8)

	responseMsg := new(dns.Msg)
	responseMsg.SetQuestion(dohNameQuery, dns.TypeA)
	responseMsg.Answer = make([]dns.RR, 1)
	responseMsg.Answer[0] = aRR

	// Encode the message to bytes
	packedRes, err := responseMsg.Pack()
	if err != nil {
		panic(err)
	}

	body := io.NopCloser(bytes.NewReader(packedRes))

	httpResponse := new(http.Response)
	httpResponse.StatusCode = 200
	httpResponse.Body = body

	return httpResponse
}

func getMockedHttpHandler() *mockedHttpHandler {
	handler := new(mockedHttpHandler)
	handler.On("SetTransport", mock.Anything)
	handler.On("SetTimeout", mock.Anything)
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

	qh := query.NewDoHQueryHandler()

	t.Run("http1 get", func(t *testing.T) {
		t.Parallel()

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
}

func TestDoHQuery_HTTPVersion(t *testing.T) {
	t.Parallel()

	t.Run("invalid version", func(t *testing.T) {
		t.Parallel()

		handler := getMockedHttpHandler()
		handler.On("Do", mock.Anything, mock.Anything).Return(mockDnsMsgHttpResponse(), nil)

		qh := query.NewDoHQueryHandler()
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
		handler.On("Do", mock.Anything, mock.Anything).Return(mockDnsMsgHttpResponse(), nil)

		qh := query.NewDoHQueryHandler()
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

		httpRes := mockDnsMsgHttpResponse()
		httpRes.StatusCode = 200

		// use mocked query handler to simulate a too long URI
		handler := getMockedHttpHandler()
		handler.On("Do", mock.Anything, mock.Anything).Return(httpRes, nil)

		qh := query.NewDoHQueryHandler()
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
		q.POSTFallback = true

		res, err := qh.Query(q)

		assert.Nil(t, err, "error should be nil")
		require.NotNil(t, res, "result should not be nil")
		assert.GreaterOrEqual(t, res.RTT, time.Duration(0), "rtt should not be empty")
		assert.Equal(t, query.HTTP_POST, handler.Calls[2].Arguments[0].(*http.Request).Method, "method should be POST")
	})

	t.Run("no post fallback if not wanted", func(t *testing.T) {
		t.Parallel()

		httpRes := mockDnsMsgHttpResponse()
		httpRes.StatusCode = 413

		// use mocked query handler to simulate a too long URI
		handler := getMockedHttpHandler()
		handler.On("Do", mock.Anything, mock.Anything).Return(httpRes, nil)

		qh := query.NewDoHQueryHandler()
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

		assert.NotNil(t, err, "error should be nil")
		require.NotNil(t, res, "result should not be nil")
		require.Nil(t, res.ResponseMsg, "response should not be nil")
	})
}

func TestDoHQuery_Port(t *testing.T) {
	t.Parallel()

	t.Run("default port", func(t *testing.T) {
		t.Parallel()

		handler := getMockedHttpHandler()
		handler.On("Do", mock.Anything, mock.Anything).Return(mockDnsMsgHttpResponse(), nil)

		qh := query.NewDoHQueryHandler()
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
		handler.On("Do", mock.Anything, mock.Anything).Return(mockDnsMsgHttpResponse(), nil)

		qh := query.NewDoHQueryHandler()
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
		handler.On("Do", mock.Anything, mock.Anything).Return(mockDnsMsgHttpResponse(), nil)

		qh := query.NewDoHQueryHandler()
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
	handler.On("Do", mock.Anything, mock.Anything).Return(mockDnsMsgHttpResponse(), nil)

	qh := query.NewDoHQueryHandler()
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
	handler.On("Do", mock.Anything, mock.Anything).Return(mockDnsMsgHttpResponse(), nil)

	qh := query.NewDoHQueryHandler()
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
	handler.On("Do", mock.Anything, mock.Anything).Return(mockDnsMsgHttpResponse(), nil)

	qh := query.NewDoHQueryHandler()
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
	handler.On("Do", mock.Anything, mock.Anything).Return(mockDnsMsgHttpResponse(), nil)

	qh := query.NewDoHQueryHandler()
	qh.QueryHandler = handler

	q := query.NewDoHQuery()
	q.Host = dohNameQuery
	q.URI = exampleUri

	res, err := qh.Query(q)

	assert.NotNil(t, err, "error should not be nil")
	require.NotNil(t, res, "result should not be nil")
	assert.Nil(t, res.ResponseMsg, "response should be nil")
}

func TestDoHQuery_WronglyFormattedURI(t *testing.T) {
	t.Parallel()

	handler := getMockedHttpHandler()
	handler.On("Do", mock.Anything, mock.Anything).Return(mockDnsMsgHttpResponse(), nil)

	qh := query.NewDoHQueryHandler()
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

	qh := query.NewDoHQueryHandler()
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

	qh := query.NewDoHQueryHandler()
	res, err := qh.Query(nil)

	assert.NotNil(t, err, "error should not be nil")
	require.NotNil(t, res, "result should not be nil")
	assert.Nil(t, res.ResponseMsg, "DNS response should be nil since handler was not set")
}

func TestDoHQuery_SNI(t *testing.T) {
	t.Parallel()

	handler := getMockedHttpHandler()
	handler.On("Do", mock.Anything, mock.Anything).Return(mockDnsMsgHttpResponse(), nil)

	qh := query.NewDoHQueryHandler()
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
		handler.On("Do", mock.Anything).Return(mockDnsMsgHttpResponse(), nil)

		qh := query.NewDoHQueryHandler()
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
		handler.On("Do", mock.Anything).Return(nil, fmt.Errorf("error"))

		qh := query.NewDoHQueryHandler()
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

	t.Run("failed on status code other than 200", func(t *testing.T) {
		t.Parallel()

		handler := getMockedHttpHandler()

		response := mockDnsMsgHttpResponse()
		response.StatusCode = 404

		handler.On("Do", mock.Anything).Return(response, nil)

		qh := query.NewDoHQueryHandler()
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
