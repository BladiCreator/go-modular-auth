package oauth

import (
	"time"

	"github.com/BladiCreator/go-modular-auth/schema"
)

// Action defines the intent of an in-flight OAuth flow.
type Action string

const (
	// ActionSignIn indicates an OAuth flow intended for authentication or sign up.
	ActionSignIn Action = "sign_in"

	// ActionLink indicates an OAuth flow intended for linking to an existing authenticated user.
	ActionLink Action = "link"
)

const (
	ModelOAuthStates = "oauth_states"
)

// StateSession represents an in-flight, transient OAuth state session with PKCE binding.
type StateSession struct {
	State        string            `json:"state"`
	Provider     string            `json:"provider"`
	RedirectURI  string            `json:"redirect_uri"`
	CodeVerifier string            `json:"code_verifier,omitempty"`
	Action       Action            `json:"action"`
	UserID       string            `json:"user_id,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
	ExpiresAt    time.Time         `json:"expires_at"`
	ConsumedAt   *time.Time        `json:"consumed_at,omitempty"`
	CreatedAt    time.Time         `json:"created_at"`
}

// Expired reports whether the state session has expired relative to the given time.
func (s *StateSession) Expired(now time.Time) bool {
	if s == nil || s.ExpiresAt.IsZero() {
		return false
	}
	return !now.Before(s.ExpiresAt)
}

// Consumed reports whether the state session has already been redeemed.
func (s *StateSession) Consumed() bool {
	return s != nil && s.ConsumedAt != nil
}

// Valid reports whether the state is neither expired nor consumed.
func (s *StateSession) Valid(now time.Time) bool {
	return s != nil && !s.Consumed() && !s.Expired(now)
}

// RegisterSchema registers the OAuth transient state session model.
func RegisterSchema(s *schema.Schema) error {
	m := schema.NewModel(ModelOAuthStates, ModelOAuthStates, "state")
	_ = m.AddField(schema.Field{Name: "state", Type: schema.TypeString, Required: true, Unique: true})
	_ = m.AddField(schema.Field{Name: "provider", Type: schema.TypeString, Required: true})
	_ = m.AddField(schema.Field{Name: "redirect_uri", Type: schema.TypeString, Required: true})
	_ = m.AddField(schema.Field{Name: "code_verifier", Type: schema.TypeString})
	_ = m.AddField(schema.Field{Name: "action", Type: schema.TypeString, Required: true})
	_ = m.AddField(schema.Field{Name: "user_id", Type: schema.TypeString})
	_ = m.AddField(schema.Field{Name: "metadata", Type: schema.TypeJSON})
	_ = m.AddField(schema.Field{Name: "expires_at", Type: schema.TypeTime, Required: true})
	_ = m.AddField(schema.Field{Name: "consumed_at", Type: schema.TypeTime})
	_ = m.AddField(schema.Field{Name: "created_at", Type: schema.TypeTime, Required: true})
	m.Indexes = []schema.Index{
		{Name: "idx_oauth_states_state", Fields: []string{"state"}, Unique: true},
		{Name: "idx_oauth_states_expires", Fields: []string{"expires_at"}},
	}
	return s.AddModel(m)
}
