package passwordpolicy

import (
	"time"

	"github.com/BladiCreator/go-modular-auth/schema"
)

// PasswordHistory records a historical password hash for reuse prevention.
type PasswordHistory struct {
	ID           string    `json:"id"`
	UserID       string    `json:"user_id"`
	PasswordHash string    `json:"password_hash"`
	CreatedAt    time.Time `json:"created_at"`
}

const (
	ModelPasswordHistory = "password_history"
)

// RegisterSchema registers the password history model in the compiled schema.
func RegisterSchema(s *schema.Schema) error {
	m := schema.NewModel(ModelPasswordHistory, ModelPasswordHistory, "id")
	_ = m.AddField(schema.Field{Name: "id", Type: schema.TypeString, Required: true})
	_ = m.AddField(schema.Field{Name: "user_id", Type: schema.TypeString, Required: true})
	_ = m.AddField(schema.Field{Name: "password_hash", Type: schema.TypeString, Required: true})
	_ = m.AddField(schema.Field{Name: "created_at", Type: schema.TypeTime, Required: true})
	m.Indexes = []schema.Index{
		{Name: "idx_password_history_user_created", Fields: []string{"user_id", "created_at"}},
	}
	return s.AddModel(m)
}

// Policy specifies password strength, complexity, history, and compromised checks.
type Policy struct {
	// MinLength specifies the minimum number of characters required. Defaults to 8.
	MinLength int `json:"min_length"`

	// MaxLength specifies the maximum number of characters permitted. Defaults to 128.
	MaxLength int `json:"max_length"`

	// RequireUppercase requires at least one uppercase letter (A-Z).
	RequireUppercase bool `json:"require_uppercase"`

	// RequireLowercase requires at least one lowercase letter (a-z).
	RequireLowercase bool `json:"require_lowercase"`

	// RequireDigit requires at least one numeric digit (0-9).
	RequireDigit bool `json:"require_digit"`

	// RequireSymbol requires at least one special punctuation/symbol character.
	RequireSymbol bool `json:"require_symbol"`

	// HistoryCount specifies how many past passwords to check against reuse. If 0, history check is disabled.
	HistoryCount int `json:"history_count"`

	// RejectCompromised enables checking against known breached or weak passwords.
	RejectCompromised bool `json:"reject_compromised"`
}

// DefaultPolicy returns a recommended baseline security policy.
func DefaultPolicy() Policy {
	return Policy{
		MinLength:         8,
		MaxLength:         128,
		RequireUppercase:  true,
		RequireLowercase:  true,
		RequireDigit:      true,
		RequireSymbol:     false,
		HistoryCount:      3,
		RejectCompromised: true,
	}
}

// ValidationResult carries detailed status of a password policy evaluation.
type ValidationResult struct {
	Valid      bool     `json:"valid"`
	Violations []string `json:"violations,omitempty"`
	Error      error    `json:"-"`
}

// ChangePasswordInput specifies parameters for policy-enforced password change.
type ChangePasswordInput struct {
	UserID            string `json:"user_id"`
	CurrentPassword   string `json:"current_password"`
	NewPassword       string `json:"new_password"`
	CurrentSessionID  string `json:"current_session_id,omitempty"`
	KeepOtherSessions bool   `json:"keep_other_sessions,omitempty"`
}

// ResetPasswordInput specifies parameters for policy-enforced password reset.
type ResetPasswordInput struct {
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}
