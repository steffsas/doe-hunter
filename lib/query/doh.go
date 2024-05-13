package query

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/steffsas/doe-hunter/lib/helper"
	"golang.org/x/net/http2"
)

const MAX_URI_LENGTH = 2048
const DOH_MEDIA_TYPE = "application/dns-message"
const HTTP_GET = "GET"
const HTTP_POST = "POST"

const HTTP_VERSION_1 = "HTTP/1.1"
const HTTP_VERSION_2 = "HTTP2"
const HTTP_VERSION_3 = "HTTP3"

const DEFAULT_DOH_TIMEOUT = 5000 * time.Millisecond
const DEFAULT_DOH_PORT = 443

type HttpHandler interface {
	Do(req *http.Request) (*http.Response, error)
	SetTransport(t http.RoundTripper)
	SetTimeout(timeout time.Duration)
	GetTimeout() time.Duration
}

type defaultHttpHandler struct {
	httpClient *http.Client
}

func (h *defaultHttpHandler) Do(req *http.Request) (*http.Response, error) {
	return h.httpClient.Do(req)
}

func (h *defaultHttpHandler) SetTransport(t http.RoundTripper) {
	h.httpClient.Transport = t
}

func (h *defaultHttpHandler) SetTimeout(timeout time.Duration) {
	h.httpClient.Timeout = timeout
}

func (h *defaultHttpHandler) GetTimeout() time.Duration {
	return h.httpClient.Timeout
}

func GetPathParamFromDoHPath(uri string) (path string, param string, err error) {
	// first we remove the query string by a regex fetching "{?<some-string>}"
	// see also https://datatracker.ietf.org/doc/html/rfc8484#section-4.1.1
	paramRegex := regexp.MustCompile(`^([^\{]+)\{\?(.*)\}$`)
	match := paramRegex.FindStringSubmatch(uri)

	if len(match) == 3 {
		return match[1], match[2], nil
	} else {
		return "", "", errors.New("URI does not match the expected format")
	}
}

type DoHQuery struct {
	DNSQuery

	// TLS configuration (defaults to nil which means basic TLS configuration)
	TLSConfig *tls.Config `json:"tls_config"`

	// the URI path for the DoH query, usually /dns-query{?dns}
	URI string `json:"uri"`

	// HTTP method, either GET or POST
	Method string `json:"method"`

	// fallback to POST request if GET request is too long for URI (default: true)
	POSTFallback bool `json:"post_fallback"`

	// HTTP1, HTTP2 or HTTP3 support (default:HTTP2)
	HTTPVersion string `json:"http_version"`
}

type DoHQueryResponse struct {
	Response     *DNSResponse   `json:"response"`
	Query        *DoHQuery      `json:"query"`
	HttpRequest  *http.Request  `json:"http_request"`
	HttpResponse *http.Response `json:"http_response"`
}

type DoHQueryHandler struct {
	// HttpHandler is an interface to execute HTTP requests
	HttpHandler HttpHandler
}

func (qh *DoHQueryHandler) Query(query *DoHQuery) (res *DoHQueryResponse, err error) {
	res = &DoHQueryResponse{}
	res.Response = &DNSResponse{}
	res.Query = query

	if query == nil {
		return res, ErrQueryMsgNil
	}

	if query.QueryMsg == nil {
		return res, ErrEmptyQueryMessage
	}

	if query.Method != HTTP_GET && query.Method != HTTP_POST {
		return res, fmt.Errorf("method must be either %s or %s", HTTP_GET, HTTP_POST)
	}

	if query.Host == "" {
		return res, ErrHostEmpty
	}

	if query.HTTPVersion != HTTP_VERSION_1 && query.HTTPVersion != HTTP_VERSION_2 && query.HTTPVersion != HTTP_VERSION_3 {
		return res, fmt.Errorf("HTTP version must be either %s, %s or %s", HTTP_VERSION_1, HTTP_VERSION_2, HTTP_VERSION_3)
	}

	if query.Port >= 65536 || query.Port < 0 {
		return res, fmt.Errorf("invalid port %d", query.Port)
	}

	if query.URI == "" {
		return res, fmt.Errorf("URI is empty")
	}

	if query.QueryMsg == nil {
		return res, ErrEmptyQueryMessage
	}

	if qh.HttpHandler == nil {
		return res, fmt.Errorf("httpClient is nil")
	}

	if query.Timeout >= 0 {
		qh.HttpHandler.SetTimeout(query.Timeout)
	} else {
		qh.HttpHandler.SetTimeout(DEFAULT_DOH_TIMEOUT)
	}

	// set the transport based on the HTTP version
	switch query.HTTPVersion {
	case HTTP_VERSION_1:
		qh.HttpHandler.SetTransport(&http.Transport{
			TLSClientConfig: query.TLSConfig,
			// we enforce http1, see https://pkg.go.dev/net/http#hdr-HTTP_2
			TLSNextProto: map[string]func(authority string, c *tls.Conn) http.RoundTripper{},
		})
	case HTTP_VERSION_2:
		qh.HttpHandler.SetTransport(&http2.Transport{
			TLSClientConfig: query.TLSConfig,
			AllowHTTP:       true,
		})
	case HTTP_VERSION_3:
		qh.HttpHandler.SetTransport(&http3.RoundTripper{
			TLSClientConfig: query.TLSConfig,
			QUICConfig:      &quic.Config{},
		})
	}

	// see RFC for DoH: https://datatracker.ietf.org/doc/html/rfc8484
	// see https://gist.github.com/cherrot/384eb7d9d537ead18462b5c462a07690
	var (
		buf, b64 []byte
	)

	// let's calculate params first
	path, param, err := GetPathParamFromDoHPath(query.URI)
	if err != nil {
		return res, err
	}

	// Set DNS ID as zero according to RFC8484 (cache friendly)
	buf, err = query.QueryMsg.Pack()
	if err != nil {
		return res, err
	}

	// see https://datatracker.ietf.org/doc/html/rfc8484#section-6
	if len(buf) > 65535 {
		return res, fmt.Errorf("DNS query message too large, got %d bytes but max is 65535", len(buf))
	}

	b64 = make([]byte, base64.RawURLEncoding.EncodedLen(len(buf)))
	base64.RawURLEncoding.Encode(b64, buf)

	endpoint := fmt.Sprintf("https://%s", helper.GetFullHostFromHostPort(query.Host, query.Port))
	fullGetURI := fmt.Sprintf("%s%s?%s=%s", endpoint, path, param, string(b64))

	if query.Method == HTTP_GET && len(fullGetURI) <= MAX_URI_LENGTH {
		// ready to try GET request
		httpReq, _ := http.NewRequestWithContext(context.Background(), HTTP_GET, fullGetURI, nil)
		httpReq.Header.Add("accept", DOH_MEDIA_TYPE)

		res.HttpRequest = httpReq
		res.Response.ResponseMsg, res.HttpResponse, res.Response.RTT, err = qh.doHttpRequest(httpReq)

		return
	} else if query.POSTFallback || query.Method == HTTP_POST {
		// let's try POST instead
		fullPostURI := fmt.Sprintf("%s%s", endpoint, path)
		body := bytes.NewReader(buf)
		httpReq, _ := http.NewRequestWithContext(context.Background(), HTTP_POST, fullPostURI, body)
		httpReq.Header.Add("accept", DOH_MEDIA_TYPE)
		// content-type is required on POST requests, see RFC8484
		httpReq.Header.Add("content-type", DOH_MEDIA_TYPE)

		res.HttpRequest = httpReq
		res.Response.ResponseMsg, res.HttpResponse, res.Response.RTT, err = qh.doHttpRequest(httpReq)
		return
	}

	return res, fmt.Errorf("URI too long for GET request (%d characters), POST fallback disabled", len(fullGetURI))
}

func (q *DoHQueryHandler) doHttpRequest(httpReq *http.Request) (r *dns.Msg, httpRes *http.Response, rtt time.Duration, err error) {
	begin := time.Now()
	httpRes, err = q.HttpHandler.Do(httpReq)

	if httpRes != nil && httpRes.Body != nil {
		defer httpRes.Body.Close()
	}

	if err != nil {
		return
	}

	rtt = time.Since(begin)

	content, err := io.ReadAll(httpRes.Body)
	if err != nil {
		return
	}

	if httpRes.StatusCode != http.StatusOK {
		err = fmt.Errorf("DoH query failed with status code %d: \n %s", httpRes.StatusCode, string(content))
		return
	}

	r = new(dns.Msg)
	err = r.Unpack(content)
	if err != nil {
		return
	}

	return
}

func NewDoHQuery() (q *DoHQuery) {
	q = &DoHQuery{
		Method:       HTTP_GET,
		POSTFallback: true,
		HTTPVersion:  HTTP_VERSION_2,
	}

	q.Timeout = DEFAULT_DOH_TIMEOUT
	q.Port = DEFAULT_DOH_PORT

	return
}

func NewDoHQueryHandler() (qh *DoHQueryHandler) {
	qh = &DoHQueryHandler{
		HttpHandler: &defaultHttpHandler{
			httpClient: &http.Client{},
		},
	}

	return
}
