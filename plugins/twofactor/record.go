package twofactor

import (
	"time"

	"github.com/BladiCreator/go-modular-auth/schema"
)

// FactorRecord is the persistent model for an MFA factor.
type FactorRecord struct {
	ID               string     `json:"id"`
	UserID           string     `json:"user_id"`
	Type             string     `json:"type"`
	Label            string     `json:"label,omitempty"`
	EncryptedSecret  string     `json:"encrypted_secret"`
	Confirmed        bool       `json:"confirmed"`
	ConfirmedAt      *time.Time `json:"confirmed_at,omitempty"`
	LastUsedAt       *time.Time `json:"last_used_at,omitempty"`
	LastUsedTimeStep int64      `json:"last_used_time_step"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
}

// RecoveryCodeRecord is the persistent model for a hashed backup recovery code.
type RecoveryCodeRecord struct {
	ID        string     `json:"id"`
	UserID    string     `json:"user_id"`
	CodeHash  string     `json:"code_hash"`
	UsedAt    *time.Time `json:"used_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

// ChallengeRecord is the persistent fallback model for ephemeral MFA challenges.
type ChallengeRecord struct {
	ID        string     `json:"id"`
	UserID    string     `json:"user_id"`
	ExpiresAt time.Time  `json:"expires_at"`
	UsedAt    *time.Time `json:"used_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

const (
	ModelTwoFactors       = "twofactor_factors"
	ModelRecoveryCodes    = "twofactor_recovery_codes"
	ModelMFAChallenges    = "twofactor_challenges"
)

// RegisterSchema registers all two-factor authentication models into the compiled schema.
func RegisterSchema(s *schema.Schema) error {
	// 1. Extend core users table
	_ = s.ExtendModel("users", schema.Field{
		Name:    "two_factor_enabled",
		Type:    schema.TypeBool,
		Default: false,
	})

	// 2. Register twofactor_factors
	factorsModel := schema.NewModel(ModelTwoFactors, ModelTwoFactors, "id")
	_ = factorsModel.AddField(schema.Field{Name: "id", Type: schema.TypeString, Required: true})
	_ = factorsModel.AddField(schema.Field{Name: "user_id", Type: schema.TypeString, Required: true, References: &schema.Reference{Model: "users", Field: "id", OnDelete: "CASCADE"}})
	_ = factorsModel.AddField(schema.Field{Name: "type", Type: schema.TypeString, Required: true})
	_ = factorsModel.AddField(schema.Field{Name: "label", Type: schema.TypeString})
	_ = factorsModel.AddField(schema.Field{Name: "encrypted_secret", Type: schema.TypeString, Required: true})
	_ = factorsModel.AddField(schema.Field{Name: "confirmed", Type: schema.TypeBool})
	_ = factorsModel.AddField(schema.Field{Name: "confirmed_at", Type: schema.TypeTime})
	_ = factorsModel.AddField(schema.Field{Name: "last_used_at", Type: schema.TypeTime})
	_ = factorsModel.AddField(schema.Field{Name: "last_used_time_step", Type: schema.TypeInt64})
	_ = factorsModel.AddField(schema.Field{Name: "created_at", Type: schema.TypeTime, Required: true})
	_ = factorsModel.AddField(schema.Field{Name: "updated_at", Type: schema.TypeTime, Required: true})
	factorsModel.Indexes = []schema.Index{
		{Name: "idx_twofactor_factors_user", Fields: []string{"user_id"}},
		{Name: "idx_twofactor_factors_user_confirmed", Fields: []string{"user_id", "confirmed"}},
	}
	if err := s.AddModel(factorsModel); err != nil {
		return err
	}

	// 3. Register twofactor_recovery_codes
	codesModel := schema.NewModel(ModelRecoveryCodes, ModelRecoveryCodes, "id")
	_ = codesModel.AddField(schema.Field{Name: "id", Type: schema.TypeString, Required: true})
	_ = codesModel.AddField(schema.Field{Name: "user_id", Type: schema.TypeString, Required: true, References: &schema.Reference{Model: "users", Field: "id", OnDelete: "CASCADE"}})
	_ = codesModel.AddField(schema.Field{Name: "code_hash", Type: schema.TypeString, Required: true})
	_ = codesModel.AddField(schema.Field{Name: "used_at", Type: schema.TypeTime})
	_ = codesModel.AddField(schema.Field{Name: "created_at", Type: schema.TypeTime, Required: true})
	codesModel.Indexes = []schema.Index{
		{Name: "idx_twofactor_recovery_codes_user", Fields: []string{"user_id"}},
		{Name: "idx_twofactor_recovery_codes_hash", Fields: []string{"user_id", "code_hash"}},
	}
	if err := s.AddModel(codesModel); err != nil {
		return err
	}

	// 4. Register twofactor_challenges
	challengesModel := schema.NewModel(ModelMFAChallenges, ModelMFAChallenges, "id")
	_ = challengesModel.AddField(schema.Field{Name: "id", Type: schema.TypeString, Required: true})
	_ = challengesModel.AddField(schema.Field{Name: "user_id", Type: schema.TypeString, Required: true})
	_ = challengesModel.AddField(schema.Field{Name: "expires_at", Type: schema.TypeTime, Required: true})
	_ = challengesModel.AddField(schema.Field{Name: "used_at", Type: schema.TypeTime})
	_ = challengesModel.AddField(schema.Field{Name: "created_at", Type: schema.TypeTime, Required: true})
	challengesModel.Indexes = []schema.Index{
		{Name: "idx_twofactor_challenges_user", Fields: []string{"user_id"}},
	}
	return s.AddModel(challengesModel)
}
