package phone

import (
	"time"

	"github.com/BladiCreator/go-modular-auth/schema"
)

// PhoneRecord represents the persistent mapping between a Core User and a validated phone number.
type PhoneRecord struct {
	ID          string     `json:"id"`
	UserID      string     `json:"user_id"`
	PhoneNumber string     `json:"phone_number"` // Canonical E.164 string
	Verified    bool       `json:"verified"`
	VerifiedAt  *time.Time `json:"verified_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

// OTPRecord represents the persistent verification state of an issued phone OTP.
type OTPRecord struct {
	ID          string     `json:"id"`
	PhoneNumber string     `json:"phone_number"`
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

// Expired reports whether the OTP token has expired at the specified instant.
func (r *OTPRecord) Expired(now time.Time) bool {
	return !now.Before(r.ExpiresAt)
}

// Locked reports whether failed verification attempts have exceeded the maximum threshold.
func (r *OTPRecord) Locked() bool {
	return r.Attempts >= r.MaxAttempts
}

const (
	ModelPhones    = "phones"
	ModelPhoneOTPs = "phone_otps"
)

// RegisterSchema registers the phone identity and OTP verification models in the compiled schema.
func RegisterSchema(s *schema.Schema) error {
	mPhones := schema.NewModel(ModelPhones, ModelPhones, "id")
	_ = mPhones.AddField(schema.Field{Name: "id", Type: schema.TypeString, Required: true})
	_ = mPhones.AddField(schema.Field{Name: "user_id", Type: schema.TypeString, Required: true, Unique: true})
	_ = mPhones.AddField(schema.Field{Name: "phone_number", Type: schema.TypeString, Required: true, Unique: true})
	_ = mPhones.AddField(schema.Field{Name: "verified", Type: schema.TypeBool, Required: true})
	_ = mPhones.AddField(schema.Field{Name: "verified_at", Type: schema.TypeTime})
	_ = mPhones.AddField(schema.Field{Name: "created_at", Type: schema.TypeTime, Required: true})
	_ = mPhones.AddField(schema.Field{Name: "updated_at", Type: schema.TypeTime, Required: true})
	mPhones.Indexes = []schema.Index{
		{Name: "uq_phones_user_id", Fields: []string{"user_id"}, Unique: true},
		{Name: "uq_phones_phone_number", Fields: []string{"phone_number"}, Unique: true},
	}
	if err := s.AddModel(mPhones); err != nil {
		return err
	}

	mOTPs := schema.NewModel(ModelPhoneOTPs, ModelPhoneOTPs, "id")
	_ = mOTPs.AddField(schema.Field{Name: "id", Type: schema.TypeString, Required: true})
	_ = mOTPs.AddField(schema.Field{Name: "phone_number", Type: schema.TypeString, Required: true})
	_ = mOTPs.AddField(schema.Field{Name: "subject", Type: schema.TypeString, Required: true})
	_ = mOTPs.AddField(schema.Field{Name: "purpose", Type: schema.TypeString, Required: true})
	_ = mOTPs.AddField(schema.Field{Name: "otp_hash", Type: schema.TypeString, Required: true})
	_ = mOTPs.AddField(schema.Field{Name: "salt", Type: schema.TypeString, Required: true})
	_ = mOTPs.AddField(schema.Field{Name: "expires_at", Type: schema.TypeTime, Required: true})
	_ = mOTPs.AddField(schema.Field{Name: "max_attempts", Type: schema.TypeInt64, Required: true})
	_ = mOTPs.AddField(schema.Field{Name: "attempts", Type: schema.TypeInt64, Required: true})
	_ = mOTPs.AddField(schema.Field{Name: "used_at", Type: schema.TypeTime})
	_ = mOTPs.AddField(schema.Field{Name: "created_at", Type: schema.TypeTime, Required: true})
	mOTPs.Indexes = []schema.Index{
		{Name: "idx_phone_otps_active", Fields: []string{"phone_number", "purpose"}},
	}
	return s.AddModel(mOTPs)
}
