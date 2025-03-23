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
	"net/url"
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

const DEFAULT_DOH_TIMEOUT = 10000 * time.Millisecond
const DEFAULT_DOH_PORT = 443

type HttpQueryHandler interface {
	Query(httpReq *http.Request, httpVersion string, timeout time.Duration, transport http.RoundTripper) (*dns.Msg, time.Duration, *tls.ConnectionState, error)
}

type defaultHttpQueryHandler struct {
	Dialer        *net.Dialer
	QuicTransport *quic.Transport
}

func (h *defaultHttpQueryHandler) Query(httpReq *http.Request, httpVersion string, timeout time.Duration, transport http.RoundTripper) (*dns.Msg, time.Duration, *tls.ConnectionState, error) {
	// set dialer for http1/http2/http3
	switch httpVersion {
	case HTTP_VERSION_1, HTTP_VERSION_2:
		transport.(*http.Transport).DialContext = h.Dialer.DialContext
	case HTTP_VERSION_3:
		// see https://quic-go.net/docs/http3/client/#using-a-quictransport
		transport.(*http3.Transport).Dial = func(ctx context.Context, addr string, tlsConf *tls.Config, quicConf *quic.Config) (quic.EarlyConnection, error) {
			a, err := net.ResolveUDPAddr("udp", addr)
			if err != nil {
				return nil, err
			}
			return h.QuicTransport.DialEarly(ctx, a, tlsConf, quicConf)
		}
	}

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
		return nil, 0, nil, err
	}

	// obviously we have established a connection now
	// le'ts retrieve the TLS connection state
	connState := httpRes.TLS

	rtt := time.Since(begin)

	content, err := io.ReadAll(httpRes.Body)
	if err != nil {
		return nil, 0, connState, err
	}

	if httpRes.StatusCode != http.StatusOK {
		return nil, 0, connState, fmt.Errorf("DoH query failed with status code %d: \n %s", httpRes.StatusCode, string(content))
	}

	r := &dns.Msg{}
	err = r.Unpack(content)
	if err != nil {
		return nil, 0, connState, err
	}

	return r, rtt, connState, nil
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
		// let's support all TLS versions, including TLS 1.0 and TLS 1.1
		// codeql [go/insecure-tls]: This is intentional
		MinVersion: tls.VersionTLS10,
		MaxVersion: tls.VersionTLS13,
		// let's support all ciphers
		CipherSuites: getAllTLSCipherSuites(),
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

	query.SetDNSSEC()

	// set the transport based on the HTTP version
	var transport http.RoundTripper

	switch query.HTTPVersion {
	case HTTP_VERSION_1:
		// see https://pkg.go.dev/net/http#hdr-HTTP_2
		tlsConfig.NextProtos = []string{"http/1.1"}
		transport = &http.Transport{
			TLSClientConfig:   tlsConfig,
			DisableKeepAlives: true,
			ForceAttemptHTTP2: false,
		}
	case HTTP_VERSION_2:
		// see https://pkg.go.dev/net/http#hdr-HTTP_2
		tlsConfig.NextProtos = []string{"h2"}
		transport = &http.Transport{
			TLSClientConfig:   tlsConfig,
			DisableKeepAlives: true,
			ForceAttemptHTTP2: true,
		}
	case HTTP_VERSION_3:
		// we should set this, got it from error anlysis
		// see https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml
		tlsConfig.NextProtos = []string{"h3"}
		transport = &http3.Transport{
			TLSClientConfig: tlsConfig,
			QUICConfig: &quic.Config{
				Allow0RTT:       true,
				KeepAlivePeriod: 0,
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
	query.QueryMsg.Id = 0

	var packErr error
	buf, packErr = query.QueryMsg.Pack()
	if packErr != nil {
		return res, custom_errors.NewQueryError(custom_errors.ErrDNSPackFailed, true).AddInfo(packErr)
	}

	b64 = make([]byte, base64.RawURLEncoding.EncodedLen(len(buf)))
	base64.RawURLEncoding.Encode(b64, buf)

	endpoint := fmt.Sprintf("https://%s", helper.GetFullHostFromHostPort(query.Host, query.Port))

	baseUri, err := url.JoinPath(endpoint, path)
	if err != nil {
		return res, custom_errors.NewQueryError(custom_errors.ErrFailedToJoinURLPath, true).AddInfo(err)
	}

	fullGetURI := fmt.Sprintf("%s?%s=%s", baseUri, param, string(b64))

	var queryErr error
	var tlsConnState *tls.ConnectionState
	//nolint:gocritic
	if query.Method == HTTP_GET && len(fullGetURI) <= MAX_URI_LENGTH {
		// ready to try GET request
		httpReq, err := http.NewRequestWithContext(context.Background(), HTTP_GET, fullGetURI, nil)
		if err != nil {
			return res, custom_errors.NewQueryError(custom_errors.ErrFailedFailedToCreateHTTPReq, true).AddInfo(err)
		}
		httpReq.Header.Add("accept", DOH_MEDIA_TYPE)

		res.ResponseMsg, res.RTT, tlsConnState, queryErr = qh.QueryHandler.Query(httpReq, query.HTTPVersion, query.Timeout, transport)
	} else if query.POSTFallback || query.Method == HTTP_POST {
		// let's try POST instead
		fullPostURI := fmt.Sprintf("%s%s", endpoint, path)
		body := bytes.NewReader(buf)
		httpReq, err := http.NewRequestWithContext(context.Background(), HTTP_POST, fullPostURI, body)
		if err != nil {
			return res, custom_errors.NewQueryError(custom_errors.ErrFailedFailedToCreateHTTPReq, true).AddInfo(err)
		}
		httpReq.Header.Add("accept", DOH_MEDIA_TYPE)
		// content-type is required on POST requests, see RFC8484
		httpReq.Header.Add("content-type", DOH_MEDIA_TYPE)

		res.ResponseMsg, res.RTT, tlsConnState, queryErr = qh.QueryHandler.Query(httpReq, query.HTTPVersion, query.Timeout, transport)
	} else {
		return res, custom_errors.NewQueryConfigError(custom_errors.ErrURITooLong, true).AddInfo(fmt.Errorf("URI length is %d characters", len(fullGetURI)))
	}

	// let's retrieve ciphersuite and TLS version from the connection state
	if tlsConnState != nil && tlsConnState.HandshakeComplete {
		res.TLSVersion = tls.VersionName(tlsConnState.Version)
		res.TLSCipherSuite = tls.CipherSuiteName(tlsConnState.CipherSuite)
	}

	return res, validateCertificateError(
		queryErr,
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
	quicTransport := &quic.Transport{}

	if config != nil {
		// HTTP1 / HTTP2 based on TCP
		localTCPAddr := &net.TCPAddr{
			IP:   config.LocalAddr,
			Port: 0,
		}
		dialer.LocalAddr = localTCPAddr

		// HTTP3 based on UDP
		localUDPAddr := &net.UDPAddr{
			IP:   config.LocalAddr,
			Port: 0,
		}
		conn, err := net.ListenUDP("udp", localUDPAddr)
		if err != nil {
			logrus.Errorf("Failed to create UDP connection: %s", err)
			return nil, err
		}
		quicTransport.Conn = conn
	} else {
		var err error
		// create udp connection on any local address
		conn, err := net.ListenUDP("udp", nil)
		if err != nil {
			logrus.Errorf("Failed to create UDP connection: %s", err)
			return nil, err
		}
		quicTransport.Conn = conn
	}

	qh := &DoHQueryHandler{
		QueryHandler: &defaultHttpQueryHandler{
			// http1/http2
			Dialer: dialer,
			// http3/quic
			QuicTransport: quicTransport,
		},
	}

	return qh, nil
}
