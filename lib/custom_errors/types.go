package custom_errors

import (
	"errors"
	"fmt"
	"runtime"
)

const UNKOWN_ERROR = "unknown_error"
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

// specific dns query errors
var ErrUDPAttemptFailed = errors.New("UDP DNS query attempt failed")
var ErrTCPAttemptFailed = errors.New("TCP DNS query attempt failed")
var ErrNoResponse = errors.New("no response received")

// specific DoH query errors
var ErrInvalidHttpMethod = errors.New("invalid HTTP method")
var ErrInvalidHttpVersion = errors.New("invalid HTTP version")
var ErrEmptyURIPath = errors.New("URI path is empty")
var ErrHttpHandlerNil = errors.New("HTTP handler is nil")
var ErrURITooLong = errors.New("URI too long for GET request, POST fallback disabled")
var ErrUnexpectedURIPath = errors.New("URI does not match the expected format")
var ErrDNSPackFailed = errors.New("failed to pack DNS message")

// specific certificate errors
var ErrCertificateInvalid = errors.New("certificate is invalid")

type DoEErrors interface {
	Error() string
	IsError(errId string) bool
	AddInfo(err error) DoEErrors
	AddInfoString(err string) DoEErrors
}

type DoEError struct {
	DoEErrors

	errId    string
	location string
	addInfo  string
	Err      error
}

func (ce *DoEError) Error() string {
	if ce.addInfo != "" {
		return fmt.Sprintf(`%s in %s: %s`, ce.errId, ce.location, ce.Err.Error())
	} else {
		return fmt.Sprintf(`%s in %s: %s - additional info: %s`, ce.errId, ce.location, ce.Err.Error(), ce.addInfo)
	}
}

func (ce *DoEError) IsError(errId string) bool {
	return ce.errId == errId
}

func (ce *DoEError) AddInfo(err error) DoEErrors {
	return ce.addInfoStr(err.Error())
}

func (ce *DoEError) AddInfoString(err string) DoEErrors {
	return ce.addInfoStr(err)
}

func (ce *DoEError) addInfoStr(err string) DoEErrors {
	if ce.addInfo == "" {
		ce.addInfo = err
	} else {
		ce.addInfo += ", " + err
	}

	return ce
}

func getCallerName(skip int) string {
	pc, _, _, ok := runtime.Caller(skip + 1) // +1 to skip current frame
	if !ok {
		return "unknown"
	}
	f := runtime.FuncForPC(pc)
	if f == nil {
		return "unknown"
	}
	return f.Name()
}

func NewUnknownError(err error) *DoEError {
	return &DoEError{errId: "unknown_error", Err: err, location: getCallerName(2)}
}

func NewGenericError(err error) *DoEError {
	return &DoEError{errId: GENERIC_ERROR, Err: err, location: getCallerName(2)}
}

func NewQueryError(err error) *DoEError {
	return &DoEError{errId: QUERY_ERROR, Err: err, location: getCallerName(2)}
}

func NewQueryConfigError(err error) *DoEError {
	return &DoEError{errId: QUERY_CONFIG_ERROR, Err: err, location: getCallerName(2)}
}

func NewCertificateError(err error) *DoEError {
	return &DoEError{errId: CERTIFICATE_ERROR, Err: err, location: getCallerName(2)}
}
