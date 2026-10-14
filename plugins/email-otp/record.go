package emailotp

import (
	"time"

	"github.com/BladiCreator/go-modular-auth/schema"
)

// OTPRecord represents the persistent state of an issued email OTP token.
type OTPRecord struct {
	ID          string     `json:"id"`
	Email       string     `json:"email"`
	Subject     string     `json:"subject"`
	Purpose     string     `json:"purpose"`
	OTPHash     string     `json:"otp_hash"`
	Salt        string     `json:"salt"`
	ExpiresAt   time.Time  `json:"expires_at"`
	MaxAttempts int        `json:"max_attempts"`
	Attempts    int        `json:"attempts"`
	UsedAt      *time.Time `json:"used_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
}

// Used reports whether the OTP token has already been consumed.
func (r *OTPRecord) Used() bool {
	return r.UsedAt != nil
}

// Expired reports whether the OTP token has expired at the given instant.
func (r *OTPRecord) Expired(now time.Time) bool {
	return !now.Before(r.ExpiresAt)
}

// Locked reports whether failed verification attempts have exceeded the allowed limit.
func (r *OTPRecord) Locked() bool {
	return r.Attempts >= r.MaxAttempts
}

const (
	ModelEmailOTPs = "email_otps"
)

// RegisterSchema registers the email_otps model with the unified schema.
func RegisterSchema(s *schema.Schema) error {
	m := schema.NewModel(ModelEmailOTPs, ModelEmailOTPs, "id")
	_ = m.AddField(schema.Field{Name: "id", Type: schema.TypeString, Required: true})
	_ = m.AddField(schema.Field{Name: "email", Type: schema.TypeString, Required: true})
	_ = m.AddField(schema.Field{Name: "subject", Type: schema.TypeString, Required: true})
	_ = m.AddField(schema.Field{Name: "purpose", Type: schema.TypeString, Required: true})
	_ = m.AddField(schema.Field{Name: "otp_hash", Type: schema.TypeString, Required: true})
	_ = m.AddField(schema.Field{Name: "salt", Type: schema.TypeString, Required: true})
	_ = m.AddField(schema.Field{Name: "expires_at", Type: schema.TypeTime, Required: true})
	_ = m.AddField(schema.Field{Name: "max_attempts", Type: schema.TypeInt64, Required: true})
	_ = m.AddField(schema.Field{Name: "attempts", Type: schema.TypeInt64, Required: true})
	_ = m.AddField(schema.Field{Name: "used_at", Type: schema.TypeTime})
	_ = m.AddField(schema.Field{Name: "created_at", Type: schema.TypeTime, Required: true})

	m.Indexes = []schema.Index{
		{Name: "idx_email_otps_email", Fields: []string{"email"}},
		{Name: "idx_email_otps_subject", Fields: []string{"subject"}},
	}

	return s.AddModel(m)
}
