package query

import "errors"

var ErrHostEmpty = errors.New("host is empty")
var ErrQueryNil = errors.New("query is nil")
var ErrQueryMsgNil = errors.New("query message is nil")
var ErrQueryHandlerNil = errors.New("query handler is nil")
var ErrEmptyQueryMessage = errors.New("query message must not be nil")
var ErrCertificateInvalid = errors.New("certificate is invalid")
