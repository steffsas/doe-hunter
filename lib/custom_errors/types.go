package custom_errors

import (
	"errors"
	"fmt"
	"runtime"
)

const UNKNOWN_ERROR = "unknown_error"
const GENERIC_ERROR = "scan_error"
const QUERY_ERROR = "query_error"
const QUERY_CONFIG_ERROR = "query_config_error"
const CERTIFICATE_ERROR = "certificate_error"

// generic query errors
var ErrHostEmpty = errors.New("query host is empty")
var ErrQueryNil = errors.New("query is nil")
var ErrQueryMsgNil = errors.New("query message is nil")
var ErrQueryHandlerNil = errors.New("query handler is nil")
var ErrEmptyQueryMessage = errors.New("query message must not be nil")
var ErrInvalidPort = errors.New("query invalid port")
var ErrInvalidProtocol = errors.New("query invalid protocol")
var ErrInvalidTimeout = errors.New("query invalid timeout")
var ErrUnknownQuery = errors.New("unknown query error")
var ErrInvalidMaxUDPRetries = errors.New("invalid max udp retries")
var ErrInvalidMaxTCPRetries = errors.New("invalid max tcp retries")

// specific dns query errors
var ErrUDPAttemptFailed = errors.New("UDP DNS query attempt failed")
var ErrTCPAttemptFailed = errors.New("TCP DNS query attempt failed")
var ErrNoResponse = errors.New("no response received")

// specific DoH query errors
var ErrInvalidHttpMethod = errors.New("invalid HTTP method")
var ErrInvalidHttpVersion = errors.New("invalid HTTP version")
var ErrEmptyURIPath = errors.New("URI path is empty")
var ErrURITooLong = errors.New("URI too long for GET request, POST fallback disabled")
var ErrUnexpectedURIPath = errors.New("URI does not match the expected format")
var ErrDNSPackFailed = errors.New("failed to pack DNS message")
var ErrDNSUnpackFailed = errors.New("failed to unpack DNS message")
var ErrDoHRequestError = errors.New("DoH request failed")
var ErrFailedFailedToCreateHTTPReq = errors.New("failed to create HTTP request")
var ErrFailedToJoinURLPath = errors.New("failed to join URL path")

// specific DoQ query errors
var ErrSessionEstablishmentFailed = errors.New("quic session establishment failed")
var ErrOpenStreamFailed = errors.New("failed to open quic stream")
var ErrWriteToStreamFailed = errors.New("failed to write to quic stream")
var ErrStreamReadFailed = errors.New("failed to read from quic stream")
var ErrEmptyStreamResponse = errors.New("received empty response from stream")
var ErrUnpackFailed = errors.New("failed to unpack DNS message")
var ErrResolveHostFailed = errors.New("failed to resolve IP address for target host")

// specific PTR query errors
var ErrFailedToReverseIP = errors.New("failed to reverse IP address")

// specific EDSR query errors
var ErrInvalidEDSRHopQuery = errors.New("invalid EDSR hop query")
var ErrFoundMultipleHops = errors.New("found multiple hops in EDSR response")
var ErrResolverDoesNotAdvertiseProtocol = errors.New("resolver does not advertise protocol")
var ErrHopParsingFailed = errors.New("failed to parse EDSR hop")
var ErrResolvingIPsOfTargetName = errors.New("failed to resolve IPv4 and/or IPv6 addresses for targetName of SVCB record")
var ErrNoGlueRecords = errors.New("no glue records found for targetName of SVCB record")
var ErrResolvingHost = errors.New("failed to resolve host")

// parsing SVCB
var ErrUnknownSvcbKey = errors.New("unknown SVCB key")
var ErrParsingSvcbKey = errors.New("failed to parse SVCB key")
var ErrDoHPathNotProvided = errors.New("DoH path not provided")
var ErrUnknownALPN = errors.New("unknown ALPN in SVCB record")
var ErrInvalidSVCBRR = errors.New("invalid DNS RR")

// specific certificate errors
var ErrCertificateInvalid = errors.New("certificate is invalid")
var ErrUnknownProtocolForTLS = errors.New("unknown protocol for TLS")

// generic producer generation
var ErrProducerCreationFailed = errors.New("failed to create producer")
var ErrProducerProduceFailed = errors.New("failed to produce message")

// SSH query errors
var ErrQueryDial = errors.New("failed to dial SSH server")

// generic consumer errors
var ErrQueryBlockList = errors.New("query host is on blocklist")

// RESINFO errors
var ErrParsingResInfo = errors.New("failed to parse RESINFO record")

type DoEErrors interface {
	Error() string
	IsError(errId string) bool
	IsCritical() bool
	AddInfo(err error) DoEErrors
	AddInfoString(err string) DoEErrors
	GetErrorId() string
	IsCertificateError() bool
}

type DoEError struct {
	DoEErrors

	ErrId          string `json:"error_id"`
	Location       string `json:"location"`
	AdditionalInfo string `json:"additional_info"`
	Err            string `json:"error"`
	Critical       bool   `json:"critical"`
}

func (ce *DoEError) Error() string {
	if ce.AdditionalInfo == "" {
		return fmt.Sprintf(`%s in %s: %s`, ce.ErrId, ce.Location, ce.Err)
	} else {
		return fmt.Sprintf(`%s in %s: %s - additional info: %s`, ce.ErrId, ce.Location, ce.Err, ce.AdditionalInfo)
	}
}

func (ce *DoEError) IsCritical() bool {
	return ce.Critical
}

func (ce *DoEError) IsError(errId string) bool {
	return ce.ErrId == errId
}

func (ce *DoEError) AddInfo(err error) DoEErrors {
	if err != nil {
		return ce.addInfoStr(err.Error())
	}
	return ce
}

func (ce *DoEError) AddInfoString(err string) DoEErrors {
	return ce.addInfoStr(err)
}

func (ce *DoEError) addInfoStr(err string) DoEErrors {
	if ce.AdditionalInfo == "" {
		ce.AdditionalInfo = err
	} else {
		ce.AdditionalInfo += ", " + err
	}

	return ce
}

func (ce *DoEError) GetErrorId() string {
	return ce.ErrId
}

func (ce *DoEError) IsCertificateError() bool {
	return ce.ErrId == CERTIFICATE_ERROR
}

func getCallerName() string {
	pc, _, _, ok := runtime.Caller(3) // +1 to skip current frame
	if !ok {
		return "unknown"
	}
	f := runtime.FuncForPC(pc)
	if f == nil {
		return "unknown"
	}
	return f.Name()
}

func NewUnknownError(err error, critical bool) *DoEError {
	return &DoEError{ErrId: "unknown_error", Err: err.Error(), Location: getCallerName(), Critical: critical}
}

func NewGenericError(err error, critical bool) *DoEError {
	return &DoEError{ErrId: GENERIC_ERROR, Err: err.Error(), Location: getCallerName(), Critical: critical}
}

func NewQueryError(err error, critical bool) *DoEError {
	return &DoEError{ErrId: QUERY_ERROR, Err: err.Error(), Location: getCallerName(), Critical: critical}
}

func NewQueryConfigError(err error, critical bool) *DoEError {
	return &DoEError{ErrId: QUERY_CONFIG_ERROR, Err: err.Error(), Location: getCallerName(), Critical: critical}
}

func NewCertificateError(err error, critical bool) *DoEError {
	return &DoEError{ErrId: CERTIFICATE_ERROR, Err: err.Error(), Location: getCallerName(), Critical: critical}
}

func ContainsCriticalErr(errColl []DoEErrors) bool {
	for _, err := range errColl {
		if err.IsCritical() {
			return true
		}
	}

	return false
}
