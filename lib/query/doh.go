package query

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/steffsas/doe-hunter/lib/custom_errors"
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

const DEFAULT_DOH_PATH = "/dns-query{?dns}"

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

func GetPathParamFromDoHPath(uri string) (path string, param string, err *custom_errors.DoEError) {
	const ERROR_LOCATION = "GetPathParamFromDoHPath"
	// first we remove the query string by a regex fetching "{?<some-string>}"
	// see also https://datatracker.ietf.org/doc/html/rfc8484#section-4.1.1
	paramRegex := regexp.MustCompile(`^([^\{]+)\{\?(.*)\}$`)
	match := paramRegex.FindStringSubmatch(uri)

	if len(match) == 3 {
		return match[1], match[2], nil
	} else {
		return "", "", custom_errors.NewQueryConfigError(custom_errors.ErrUnexpectedURIPath)
	}
}

type DoHQuery struct {
	DoEQuery

	SkipCertificateVerify bool `json:"skip_certificate_verify"`

	// the URI path for the DoH query, usually /dns-query{?dns}
	URI string `json:"uri"`

	// the full URI including the query param
	FullEndpointURI string `json:"full_endpoint_uri"`

	// HTTP method, either GET or POST
	Method string `json:"method"`

	// fallback to POST request if GET request is too long for URI (default: true)
	POSTFallback bool `json:"post_fallback"`

	// HTTP1, HTTP2 or HTTP3 support (default:HTTP2)
	HTTPVersion string `json:"http_version"`
}

type DoHResponse struct {
	DoEResponse
}

type DoHQueryHandler struct {
	// HttpHandler is an interface to execute HTTP requests
	HttpHandler HttpHandler
}

func (qh *DoHQueryHandler) Query(query *DoHQuery) (res *DoHResponse, err custom_errors.DoEErrors) {
	res = &DoHResponse{}

	if query == nil {
		return res, custom_errors.NewQueryConfigError(custom_errors.ErrQueryNil)
	}

	if err := query.Check(); err != nil {
		return res, err
	}

	if query.Method != HTTP_GET && query.Method != HTTP_POST {
		return res, custom_errors.NewQueryConfigError(custom_errors.ErrInvalidHttpMethod)
	}

	if query.HTTPVersion != HTTP_VERSION_1 && query.HTTPVersion != HTTP_VERSION_2 && query.HTTPVersion != HTTP_VERSION_3 {
		return res, custom_errors.NewQueryConfigError(custom_errors.ErrInvalidHttpVersion)
	}

	if query.URI == "" {
		return res, custom_errors.NewQueryConfigError(custom_errors.ErrEmptyURIPath)
	}

	if qh.HttpHandler == nil {
		return res, custom_errors.NewGenericError(custom_errors.ErrHttpHandlerNil)
	}

	if query.Timeout >= 0 {
		qh.HttpHandler.SetTimeout(query.Timeout)
	} else {
		qh.HttpHandler.SetTimeout(DEFAULT_DOH_TIMEOUT)
	}

	// set the TLS config
	tlsConfig := &tls.Config{
		InsecureSkipVerify: query.SkipCertificateVerify,
	}

	// set the transport based on the HTTP version
	switch query.HTTPVersion {
	case HTTP_VERSION_1:
		qh.HttpHandler.SetTransport(&http.Transport{
			TLSClientConfig: tlsConfig,
			// we enforce http1, see https://pkg.go.dev/net/http#hdr-HTTP_2
			TLSNextProto: map[string]func(authority string, c *tls.Conn) http.RoundTripper{},
		})
	case HTTP_VERSION_2:
		qh.HttpHandler.SetTransport(&http2.Transport{
			TLSClientConfig: tlsConfig,
		})
	case HTTP_VERSION_3:
		qh.HttpHandler.SetTransport(&http3.RoundTripper{
			TLSClientConfig: tlsConfig,
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
	var packErr error
	buf, packErr = query.QueryMsg.Pack()
	if packErr != nil {
		err = custom_errors.NewQueryError(custom_errors.ErrDNSPackFailed).AddInfo(packErr)
		return res, err
	}

	// see https://datatracker.ietf.org/doc/html/rfc8484#section-6
	if len(buf) > 65535 {
		// return res, fmt.Errorf("DNS query message too large, got %d bytes but max is 65535", len(buf))
	}

	b64 = make([]byte, base64.RawURLEncoding.EncodedLen(len(buf)))
	base64.RawURLEncoding.Encode(b64, buf)

	endpoint := fmt.Sprintf("https://%s", helper.GetFullHostFromHostPort(query.Host, query.Port))
	query.FullEndpointURI = endpoint

	fullGetURI := fmt.Sprintf("%s%s?%s=%s", endpoint, path, param, string(b64))

	var httpRes *http.Response
	var queryErr error
	if query.Method == HTTP_GET && len(fullGetURI) <= MAX_URI_LENGTH {
		// ready to try GET request
		httpReq, _ := http.NewRequestWithContext(context.Background(), HTTP_GET, fullGetURI, nil)
		httpReq.Header.Add("accept", DOH_MEDIA_TYPE)

		res.ResponseMsg, httpRes, res.RTT, queryErr = qh.doHttpRequest(httpReq)
	} else if query.POSTFallback || query.Method == HTTP_POST {
		// let's try POST instead
		fullPostURI := fmt.Sprintf("%s%s", endpoint, path)
		body := bytes.NewReader(buf)
		httpReq, _ := http.NewRequestWithContext(context.Background(), HTTP_POST, fullPostURI, body)
		httpReq.Header.Add("accept", DOH_MEDIA_TYPE)
		// content-type is required on POST requests, see RFC8484
		httpReq.Header.Add("content-type", DOH_MEDIA_TYPE)

		res.ResponseMsg, httpRes, res.RTT, queryErr = qh.doHttpRequest(httpReq)
	} else {
		err = custom_errors.NewQueryConfigError(custom_errors.ErrURITooLong, ERROR_DOH_LOCATION)
		return
	}

	if queryErr != nil {
		// we need to check for certificate error
		if helper.IsCertificateError(err) {
			err = custom_errors.NewCertificateError(err, ERROR_DOH_LOCATION)
		} else {
			err = custom_errors.NewQueryError(err, ERROR_DOH_LOCATION)
		}
	}

	return
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
		URI:          DEFAULT_DOH_PATH,
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
