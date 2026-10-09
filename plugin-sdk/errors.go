package sdk

import (
	"errors"
	"fmt"
)

var (
	// ErrNotFound is returned when a requested capability or module is not found.
	ErrNotFound = errors.New("plugin-sdk: not found")
	// ErrDuplicate is returned when a module or capability is registered more than once.
	ErrDuplicate = errors.New("plugin-sdk: duplicate registration")
	// ErrPluginDependency is returned when a required plugin dependency is missing or cyclic.
	ErrPluginDependency = errors.New("plugin-sdk: dependency error")
)

// ErrorKind classifies domain errors into architectural categories for transport adapters.
type ErrorKind int

const (
	KindUnknown ErrorKind = iota
	KindValidation
	KindNotFound
	KindConflict
	KindUnauthorized
	KindForbidden
	KindInternal
)

func (k ErrorKind) String() string {
	switch k {
	case KindValidation:
		return "validation"
	case KindNotFound:
		return "not_found"
	case KindConflict:
		return "conflict"
	case KindUnauthorized:
		return "unauthorized"
	case KindForbidden:
		return "forbidden"
	case KindInternal:
		return "internal"
	default:
		return "unknown"
	}
}

// Error represents a categorized plugin error that transport adapters can map to HTTP/gRPC codes.
type Error struct {
	Kind    ErrorKind
	Message string
	Err     error
}

func (e *Error) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("[%s] %s: %v", e.Kind, e.Message, e.Err)
	}
	return fmt.Sprintf("[%s] %s", e.Kind, e.Message)
}

func (e *Error) Unwrap() error {
	return e.Err
}

// NewError creates a categorized plugin error.
func NewError(kind ErrorKind, message string, err error) *Error {
	return &Error{Kind: kind, Message: message, Err: err}
}
