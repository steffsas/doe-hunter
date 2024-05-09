package query

import (
	"bytes"
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
	"golang.org/x/net/http2"
)

const MAX_URI_LENGTH = 2048
const DOH_MEDIA_TYPE = "application/dns-message"
const HTTP_GET = "GET"
const HTTP_POST = "POST"

const HTTP_VERSION_1 = "HTTP/1.1"
const HTTP_VERSION_2 = "HTTP2"
const HTTP_VERSION_3 = "HTTP3"

const DEFAULT_DOH_TIMEOUT = 5000
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

	// HttpHandler is an interface to execute HTTP requests
	HttpHandler HttpHandler

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
	DNSResponse
	HttpRequest  *http.Request  `json:"http_request"`
	HttpResponse *http.Response `json:"http_response"`
}

func (q *DoHQuery) Query() (response *DoHQueryResponse, err error) {
	response = &DoHQueryResponse{}
	response.QueryMsg = q.QueryMsg

	if q.Method != HTTP_GET && q.Method != HTTP_POST {
		return response, fmt.Errorf("method must be either %s or %s", HTTP_GET, HTTP_POST)
	}

	if q.Host == "" {
		return response, ErrHostEmpty
	}

	if q.HTTPVersion != HTTP_VERSION_1 && q.HTTPVersion != HTTP_VERSION_2 && q.HTTPVersion != HTTP_VERSION_3 {
		return response, fmt.Errorf("HTTP version must be either %s, %s or %s", HTTP_VERSION_1, HTTP_VERSION_2, HTTP_VERSION_3)
	}

	if q.Port >= 65536 || q.Port < 0 {
		return response, fmt.Errorf("invalid port %d", q.Port)
	}

	if q.URI == "" {
		return response, fmt.Errorf("URI is empty")
	}

	if q.QueryMsg == nil {
		return response, ErrEmptyQueryMessage
	}

	if q.HttpHandler == nil {
		return response, fmt.Errorf("httpClient is nil")
	}

	if q.Timeout >= 0 {
		q.HttpHandler.SetTimeout(time.Duration(q.Timeout) * time.Millisecond)
	} else {
		q.HttpHandler.SetTimeout(DEFAULT_DOH_TIMEOUT * time.Millisecond)
	}

	// set the transport based on the HTTP version
	switch q.HTTPVersion {
	case HTTP_VERSION_1:
		q.HttpHandler.SetTransport(&http.Transport{
			TLSClientConfig: q.TLSConfig,
			// we enforce http1, see https://pkg.go.dev/net/http#hdr-HTTP_2
			TLSNextProto: map[string]func(authority string, c *tls.Conn) http.RoundTripper{},
		})
	case HTTP_VERSION_2:
		q.HttpHandler.SetTransport(&http2.Transport{
			TLSClientConfig: q.TLSConfig,
			AllowHTTP:       true,
		})
	case HTTP_VERSION_3:
		q.HttpHandler.SetTransport(&http3.RoundTripper{
			TLSClientConfig: q.TLSConfig,
			QUICConfig:      &quic.Config{},
		})
	}

	// see RFC for DoH: https://datatracker.ietf.org/doc/html/rfc8484
	// see https://gist.github.com/cherrot/384eb7d9d537ead18462b5c462a07690
	var (
		buf, b64 []byte
	)

	// let's calculate params first
	path, param, err := GetPathParamFromDoHPath(q.URI)
	if err != nil {
		return response, err
	}

	// Set DNS ID as zero according to RFC8484 (cache friendly)
	buf, err = q.QueryMsg.Pack()
	if err != nil {
		return response, err
	}

	// see https://datatracker.ietf.org/doc/html/rfc8484#section-6
	if len(buf) > 65535 {
		return response, fmt.Errorf("DNS query message too large, got %d bytes but max is 65535", len(buf))
	}

	b64 = make([]byte, base64.RawURLEncoding.EncodedLen(len(buf)))
	base64.RawURLEncoding.Encode(b64, buf)

	endpoint := fmt.Sprintf("https://%s:%d", q.Host, q.Port)
	fullGetURI := fmt.Sprintf("%s%s?%s=%s", endpoint, path, param, string(b64))

	if q.Method == HTTP_GET && len(fullGetURI) <= MAX_URI_LENGTH {
		// ready to try GET request
		httpReq, _ := http.NewRequest(HTTP_GET, fullGetURI, nil)
		httpReq.Header.Add("accept", DOH_MEDIA_TYPE)

		response.HttpRequest = httpReq
		response.ResponseMsg, response.HttpResponse, response.RTT, err = q.doHttpRequest(httpReq)
		return
	} else if q.POSTFallback || q.Method == HTTP_POST {
		// let's try POST instead
		fullPostURI := fmt.Sprintf("%s%s", endpoint, path)
		body := bytes.NewReader(buf)
		httpReq, _ := http.NewRequest(HTTP_POST, fullPostURI, body)
		httpReq.Header.Add("accept", DOH_MEDIA_TYPE)
		// content-type is required on POST requests, see RFC8484
		httpReq.Header.Add("content-type", DOH_MEDIA_TYPE)

		response.HttpRequest = httpReq
		response.ResponseMsg, response.HttpResponse, response.RTT, err = q.doHttpRequest(httpReq)
		return
	}

	return response, fmt.Errorf("URI too long for GET request (%d characters), POST fallback disabled", len(fullGetURI))
}

func (q *DoHQuery) doHttpRequest(httpReq *http.Request) (r *dns.Msg, httpRes *http.Response, rtt time.Duration, err error) {
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
		err = fmt.Errorf("DoH query failed: \n %s", string(content))
		return
	}

	r = new(dns.Msg)
	err = r.Unpack(content)
	if err != nil {
		err = fmt.Errorf("could not unpack DNS response: %v", err)
	}

	return
}

func NewDoHQuery() (q *DoHQuery) {
	q = &DoHQuery{
		HttpHandler: &defaultHttpHandler{
			httpClient: &http.Client{},
		},
		Method:       HTTP_GET,
		POSTFallback: true,
		HTTPVersion:  HTTP_VERSION_2,
	}

	q.Timeout = DEFAULT_DOH_TIMEOUT
	q.Port = DEFAULT_DOH_PORT

	return
}
