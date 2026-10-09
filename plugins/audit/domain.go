package audit

import (
	"github.com/BladiCreator/go-modular-auth-audit/store"
)

// Outcome classifies the result of an audited operation.
type Outcome = store.Outcome

const (
	// OutcomeSuccess denotes an operation that completed successfully.
	OutcomeSuccess = store.OutcomeSuccess
	// OutcomeFailure denotes an operation that failed, was rejected, or unauthorized.
	OutcomeFailure = store.OutcomeFailure
	// OutcomeUnknown denotes an operation whose explicit result was indeterminate.
	OutcomeUnknown = store.OutcomeUnknown
)

// TargetResource specifies the subject or resource affected by an audited event.
type TargetResource = store.TargetResource

// Actor encapsulates the security principal initiating or associated with the audited action.
type Actor = store.Actor

// AuditRecord represents an immutable audit log entry capturing a security-relevant event.
type AuditRecord = store.AuditRecord

// ListFilter defines search and pagination parameters for querying audit records.
type ListFilter = store.ListFilter

// ListResult wraps the matching audit entries and total count for pagination.
type ListResult = store.ListResult
