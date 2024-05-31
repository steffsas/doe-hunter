package query

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
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

type HttpQueryHandler interface {
	Query(
		host string,
		port int,
		method string,
		path string,
		param string,
		protocol string,
		msg *dns.Msg,
		timeout time.Duration,
		tlsConfig *tls.Config,
		postFallback bool,
	) (r *dns.Msg, rtt time.Duration, err custom_errors.DoEErrors)
}

type defaultHttpQueryHandler struct {
	Dialer *net.Dialer
	Conn   net.PacketConn
}

func (h *defaultHttpQueryHandler) DoHttpRequest(httpReq *http.Request, timeout time.Duration, transport http.RoundTripper) (*dns.Msg, time.Duration, custom_errors.DoEErrors) {
	begin := time.Now()

	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}

	httpRes, err := client.Do(httpReq)

	if httpRes != nil && httpRes.Body != nil {
		defer httpRes.Body.Close()
	}

	if err != nil {
		return nil, 0, custom_errors.NewQueryError(custom_errors.ErrDoHRequestError, true).AddInfo(err)
	}

	rtt := time.Since(begin)

	content, err := io.ReadAll(httpRes.Body)
	if err != nil {
		return nil, 0, custom_errors.NewQueryError(custom_errors.ErrDoHRequestError, true).AddInfo(err)
	}

	if httpRes.StatusCode != http.StatusOK {
		return nil, 0, custom_errors.NewQueryError(custom_errors.ErrDoHRequestError, true).AddInfo(
			fmt.Errorf("DoH query failed with status code %d: \n %s", httpRes.StatusCode, string(content)),
		)
	}

	r := &dns.Msg{}
	err = r.Unpack(content)
	if err != nil {
		return nil, 0, custom_errors.NewQueryError(custom_errors.ErrDNSUnpackFailed, true).AddInfo(err)
	}

	return r, rtt, nil
}

func (h *defaultHttpQueryHandler) Query(
	host string,
	port int,
	method string,
	path string,
	param string,
	protocol string,
	msg *dns.Msg,
	timeout time.Duration,
	tlsConfig *tls.Config,
	postFallback bool,
) (r *dns.Msg, rtt time.Duration, err custom_errors.DoEErrors) {

	// set the transport based on the HTTP version
	var transport http.RoundTripper

	switch protocol {
	case HTTP_VERSION_1:
		transport = &http.Transport{
			TLSClientConfig: tlsConfig,
			// we enforce http1, see https://pkg.go.dev/net/http#hdr-HTTP_2
			TLSNextProto:      map[string]func(authority string, c *tls.Conn) http.RoundTripper{},
			MaxConnsPerHost:   1,
			MaxIdleConns:      1,
			DisableKeepAlives: true,
			ForceAttemptHTTP2: false,
			Dial:              h.Dialer.Dial,
		}
	case HTTP_VERSION_2:
		transport = &http.Transport{
			TLSClientConfig: tlsConfig,
			// we enforce http1, see https://pkg.go.dev/net/http#hdr-HTTP_2
			TLSNextProto:      map[string]func(authority string, c *tls.Conn) http.RoundTripper{},
			MaxConnsPerHost:   1,
			MaxIdleConns:      1,
			DisableKeepAlives: true,
			ForceAttemptHTTP2: true,
			Dial:              h.Dialer.Dial,
		}
	case HTTP_VERSION_3:
		transport = &http3.RoundTripper{
			TLSClientConfig: tlsConfig,
			QUICConfig: &quic.Config{
				Allow0RTT:       true,
				KeepAlivePeriod: 0,
			},
			Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
				// parse addr to UDPAddr
				udpAddr, err := net.ResolveUDPAddr("udp", addr)
				if err != nil {
					return nil, err
				}

				// we use the default QUIC dialer with an axisting connection
				return quic.DialEarly(context.Background(), h.Conn, udpAddr, tlsCfg, cfg)
			},
		}
	}

	// see RFC for DoH: https://datatracker.ietf.org/doc/html/rfc8484
	// see https://gist.github.com/cherrot/384eb7d9d537ead18462b5c462a07690
	var (
		buf, b64 []byte
	)

	if strings.ToLower(param) != "dns" {
		logrus.Warnf("DoH query param %s is not 'dns', this is not a standard DoH query", param)
	}

	// Set DNS ID as zero according to RFC8484 (cache friendly)
	msg.Id = 0

	var packErr error
	buf, packErr = msg.Pack()
	if packErr != nil {
		return nil, 0, custom_errors.NewQueryError(custom_errors.ErrDNSPackFailed, true).AddInfo(packErr)
	}

	b64 = make([]byte, base64.RawURLEncoding.EncodedLen(len(buf)))
	base64.RawURLEncoding.Encode(b64, buf)

	endpoint := fmt.Sprintf("https://%s", helper.GetFullHostFromHostPort(host, port))

	fullGetURI := fmt.Sprintf("%s%s?%s=%s", endpoint, path, param, string(b64))

	fmt.Println(method == HTTP_GET, len(fullGetURI) <= MAX_URI_LENGTH)
	fmt.Println(postFallback, method == HTTP_POST)

	//nolint:gocritic
	if method == HTTP_GET && len(fullGetURI) <= MAX_URI_LENGTH {
		// ready to try GET request
		httpReq, _ := http.NewRequestWithContext(context.Background(), HTTP_GET, fullGetURI, nil)
		httpReq.Header.Add("accept", DOH_MEDIA_TYPE)

		return h.DoHttpRequest(httpReq, timeout, transport)
	} else if postFallback || method == HTTP_POST {
		// let's try POST instead
		fullPostURI := fmt.Sprintf("%s%s", endpoint, path)
		body := bytes.NewReader(buf)
		httpReq, _ := http.NewRequestWithContext(context.Background(), HTTP_POST, fullPostURI, body)
		httpReq.Header.Add("accept", DOH_MEDIA_TYPE)
		// content-type is required on POST requests, see RFC8484
		httpReq.Header.Add("content-type", DOH_MEDIA_TYPE)

		return h.DoHttpRequest(httpReq, timeout, transport)
	} else {
		return nil, 0, custom_errors.NewQueryConfigError(custom_errors.ErrURITooLong, true).AddInfo(fmt.Errorf("URI length is %d characters", len(fullGetURI)))
	}
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
	QueryHandler HttpQueryHandler
}

func (qh *DoHQueryHandler) Query(query *DoHQuery) (*DoHResponse, custom_errors.DoEErrors) {
	res := &DoHResponse{}

	res.CertificateValid = false
	res.CertificateVerified = false

	var err custom_errors.DoEErrors

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

	// set the TLS config
	tlsConfig := &tls.Config{
		InsecureSkipVerify: query.SkipCertificateVerify,
	}

	if query.SNI != "" {
		tlsConfig.ServerName = query.SNI
	}

	// let's calculate params first
	path, param, paramErr := GetPathParamFromDoHPath(query.URI)
	if paramErr != nil {
		return res, paramErr
	}

	if strings.ToLower(param) != "dns" {
		logrus.Warnf("DoH query param %s is not 'dns', this is not a standard DoH query", param)
	}

	res.ResponseMsg, res.RTT, err = qh.QueryHandler.Query(
		query.Host,
		query.Port,
		query.Method,
		path,
		param,
		query.HTTPVersion,
		query.QueryMsg,
		query.Timeout,
		tlsConfig,
		query.POSTFallback)

	return res, validateCertificateError(
		err,
		custom_errors.NewQueryError(custom_errors.ErrUnknownQuery, true),
		&res.DoEResponse,
		query.SkipCertificateVerify,
	)
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

	q.QueryMsg = GetDefaultQueryMsg()

	return
}

func NewDoHQueryHandler(config *QueryConfig) (*DoHQueryHandler, error) {
	dialer := &net.Dialer{}
	var conn net.PacketConn

	if config != nil {
		localAddr := &net.UDPAddr{
			IP:   config.LocalAddr,
			Port: 0,
		}

		// set dialer for http1/http2
		dialer.LocalAddr = localAddr

		// create udp connection
		var err error
		conn, err = net.ListenUDP("udp", localAddr)
		if err != nil {
			logrus.Errorf("Failed to create UDP connection: %s", err)
		}
	} else {
		var err error
		// create udp connection on any local address
		conn, err = net.ListenUDP("udp", nil)
		if err != nil {
			logrus.Errorf("Failed to create UDP connection: %s", err)
		}
	}

	qh := &DoHQueryHandler{
		QueryHandler: &defaultHttpQueryHandler{
			// http1/http2
			Dialer: dialer,
			// http3
			Conn: conn,
		},
	}

	return qh, nil
}
