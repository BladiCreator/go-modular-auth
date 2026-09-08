package httpauth

import "errors"

var (
	// ErrTokenNotFound is returned when no session or bearer token is found in any configured source.
	ErrTokenNotFound = errors.New("httpauth: token not found")

	// ErrNilRequest is returned when an HTTP operation is called with a nil *http.Request.
	ErrNilRequest = errors.New("httpauth: nil http request")

	// ErrNilResponseWriter is returned when a cookie operation is called with a nil http.ResponseWriter.
	ErrNilResponseWriter = errors.New("httpauth: nil http response writer")
)
