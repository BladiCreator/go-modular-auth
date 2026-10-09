package audit

import "errors"

// Sentinel errors returned by the audit plugin and store implementations.
var (
	// ErrStoreRequired indicates that an AuditStore implementation was not supplied in configuration.
	ErrStoreRequired = errors.New("audit: audit store is required")

	// ErrEventRequired indicates an attempt to write an audit record with an empty event identifier.
	ErrEventRequired = errors.New("audit: event identifier cannot be empty")

	// ErrRecordNotFound indicates that the requested audit record does not exist in storage.
	ErrRecordNotFound = errors.New("audit: record not found")

	// ErrNilRecord indicates that an audit record pointer provided for persistence was nil.
	ErrNilRecord = errors.New("audit: record cannot be nil")

	// ErrInvalidFilter indicates invalid query or pagination criteria.
	ErrInvalidFilter = errors.New("audit: invalid filter criteria")
)
