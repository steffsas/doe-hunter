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
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/sirupsen/logrus"
	"github.com/steffsas/doe-hunter/lib/custom_errors"
	"github.com/steffsas/doe-hunter/lib/helper"
)

const MAX_URI_LENGTH = 2048
const DOH_MEDIA_TYPE = "application/dns-message"
const DEFAULT_DOH_PARAM = "dns"
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
}

type defaultHttpHandler struct {
	httpClient *http.Client
}

func (h *defaultHttpHandler) Do(req *http.Request) (*http.Response, error) {
	res, err := h.httpClient.Do(req)
	return res, err
}

func (h *defaultHttpHandler) SetTransport(t http.RoundTripper) {
	h.httpClient.Transport = t
}

func (h *defaultHttpHandler) SetTimeout(timeout time.Duration) {
	h.httpClient.Timeout = timeout
}

func GetPathParamFromDoHPath(uri string) (path string, param string, err *custom_errors.DoEError) {
	// first we remove the query string by a regex fetching "{?<some-string>}"
	// see also https://datatracker.ietf.org/doc/html/rfc8484#section-4.1.1
	paramRegex := regexp.MustCompile(`^([^\{]+)\{\?(.*)\}$`)
	match := paramRegex.FindStringSubmatch(uri)

	if len(match) == 3 {
		return match[1], match[2], nil
	} else {
		return "", "", custom_errors.NewQueryConfigError(custom_errors.ErrUnexpectedURIPath, true)
	}
}

type DoHQuery struct {
	DoEQuery

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
	// QueryHandler is an interface to execute HTTP requests
	QueryHandler HttpHandler
}

func (qh *DoHQueryHandler) Query(query *DoHQuery) (*DoHResponse, custom_errors.DoEErrors) {
	res := &DoHResponse{}

	res.CertificateValid = false
	res.CertificateVerified = false

	if query == nil {
		return res, custom_errors.NewQueryConfigError(custom_errors.ErrQueryNil, true)
	}

	if err := query.Check(true); err != nil {
		return res, err
	}

	if qh.QueryHandler == nil {
		return res, custom_errors.NewGenericError(custom_errors.ErrQueryHandlerNil, true)
	}

	if query.Method != HTTP_GET && query.Method != HTTP_POST {
		return res, custom_errors.NewQueryConfigError(custom_errors.ErrInvalidHttpMethod, true)
	}

	if query.HTTPVersion != HTTP_VERSION_1 && query.HTTPVersion != HTTP_VERSION_2 && query.HTTPVersion != HTTP_VERSION_3 {
		return res, custom_errors.NewQueryConfigError(custom_errors.ErrInvalidHttpVersion, true)
	}

	if query.URI == "" {
		return res, custom_errors.NewQueryConfigError(custom_errors.ErrEmptyURIPath, true)
	}

	qh.QueryHandler.SetTimeout(query.Timeout)

	// set the TLS config
	tlsConfig := &tls.Config{
		InsecureSkipVerify: query.SkipCertificateVerify,
	}

	if query.SNI != "" {
		tlsConfig.ServerName = query.SNI
	}

	// set the transport based on the HTTP version
	switch query.HTTPVersion {
	case HTTP_VERSION_1:
		qh.QueryHandler.SetTransport(&http.Transport{
			TLSClientConfig: tlsConfig,
			// we enforce http1, see https://pkg.go.dev/net/http#hdr-HTTP_2
			TLSNextProto:        map[string]func(authority string, c *tls.Conn) http.RoundTripper{},
			IdleConnTimeout:     query.Timeout,
			TLSHandshakeTimeout: query.Timeout,
			MaxConnsPerHost:     1,
			MaxIdleConns:        1,
			DisableKeepAlives:   true,
			ForceAttemptHTTP2:   false,
		})
	case HTTP_VERSION_2:
		// qh.QueryHandler.SetTransport(&http2.Transport{
		// 	TLSClientConfig: tlsConfig,
		// 	AllowHTTP:       false,
		// })
		qh.QueryHandler.SetTransport(&http.Transport{
			TLSClientConfig: tlsConfig,
			// we enforce http1, see https://pkg.go.dev/net/http#hdr-HTTP_2
			TLSNextProto:        map[string]func(authority string, c *tls.Conn) http.RoundTripper{},
			IdleConnTimeout:     query.Timeout,
			TLSHandshakeTimeout: query.Timeout,
			MaxConnsPerHost:     1,
			MaxIdleConns:        1,
			DisableKeepAlives:   true,
			ForceAttemptHTTP2:   true,
		})
	case HTTP_VERSION_3:
		qh.QueryHandler.SetTransport(&http3.RoundTripper{
			TLSClientConfig: tlsConfig,
			QUICConfig: &quic.Config{
				Allow0RTT:       true,
				MaxIdleTimeout:  query.Timeout,
				KeepAlivePeriod: 0,
			},
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

	if strings.ToLower(param) != "dns" {
		logrus.Warnf("DoH query param %s is not 'dns', this is not a standard DoH query", param)
	}

	// Set DNS ID as zero according to RFC8484 (cache friendly)
	var packErr error
	buf, packErr = query.QueryMsg.Pack()
	if packErr != nil {
		return res, custom_errors.NewQueryError(custom_errors.ErrDNSPackFailed, true).AddInfo(packErr)
	}

	b64 = make([]byte, base64.RawURLEncoding.EncodedLen(len(buf)))
	base64.RawURLEncoding.Encode(b64, buf)

	endpoint := fmt.Sprintf("https://%s", helper.GetFullHostFromHostPort(query.Host, query.Port))
	query.FullEndpointURI = endpoint

	fullGetURI := fmt.Sprintf("%s%s?%s=%s", endpoint, path, param, string(b64))

	var queryErr error
	if query.Method == HTTP_GET && len(fullGetURI) <= MAX_URI_LENGTH {
		// ready to try GET request
		httpReq, _ := http.NewRequestWithContext(context.Background(), HTTP_GET, fullGetURI, nil)
		httpReq.Header.Add("accept", DOH_MEDIA_TYPE)

		res.ResponseMsg, _, res.RTT, queryErr = qh.doHttpRequest(httpReq)
	} else if query.POSTFallback || query.Method == HTTP_POST {
		// let's try POST instead
		fullPostURI := fmt.Sprintf("%s%s", endpoint, path)
		body := bytes.NewReader(buf)
		httpReq, _ := http.NewRequestWithContext(context.Background(), HTTP_POST, fullPostURI, body)
		httpReq.Header.Add("accept", DOH_MEDIA_TYPE)
		// content-type is required on POST requests, see RFC8484
		httpReq.Header.Add("content-type", DOH_MEDIA_TYPE)

		res.ResponseMsg, _, res.RTT, queryErr = qh.doHttpRequest(httpReq)
	} else {
		return res, custom_errors.NewQueryConfigError(custom_errors.ErrURITooLong, true).AddInfo(fmt.Errorf("URI length is %d characters", len(fullGetURI)))
	}

	return res, validateCertificateError(
		queryErr,
		custom_errors.NewQueryError(custom_errors.ErrUnknownQueryErr, true),
		&res.DoEResponse,
		query.SkipCertificateVerify,
	)
}

func (q *DoHQueryHandler) doHttpRequest(httpReq *http.Request) (r *dns.Msg, httpRes *http.Response, rtt time.Duration, err error) {
	begin := time.Now()
	httpRes, err = q.QueryHandler.Do(httpReq)

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

	r = &dns.Msg{}
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
		QueryHandler: &defaultHttpHandler{
			httpClient: &http.Client{},
		},
	}

	return
}
