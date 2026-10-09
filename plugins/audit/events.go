package audit

import (
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
)

// Event names emitted or tracked by the audit plugin.
const (
	EventAuditRecorded auth.EventName = "audit.record.created"
)

// AuditRecordedPayload describes an audit log creation event.
type AuditRecordedPayload struct {
	RecordID  string    `json:"record_id"`
	Event     string    `json:"event"`
	Timestamp time.Time `json:"timestamp"`
}
