package scim

import "errors"

var (
	ErrNotFound       = errors.New("scim: resource not found")
	ErrConflict       = errors.New("scim: resource conflict")
	ErrInvalidRequest = errors.New("scim: invalid request")
	ErrSchemaMismatch = errors.New("scim: schema mismatch")
)
