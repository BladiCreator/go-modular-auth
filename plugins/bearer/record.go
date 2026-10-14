package bearer

import (
	"slices"
	"time"

	"github.com/BladiCreator/go-modular-auth/schema"
)

// TokenRecord represents the persistent data model of a bearer token.
// The plaintext token secret is never stored; only TokenHash is persisted.
type TokenRecord struct {
	ID            string            `json:"id"`
	TokenHash     string            `json:"token_hash"`
	Subject       string            `json:"subject"`
	PrincipalType string            `json:"principal_type"`
	Scopes        []string          `json:"scopes"`
	Metadata      map[string]string `json:"metadata,omitempty"`
	ExpiresAt     time.Time         `json:"expires_at"`
	RevokedAt     *time.Time        `json:"revoked_at,omitempty"`
	CreatedAt     time.Time         `json:"created_at"`
	UpdatedAt     time.Time         `json:"updated_at"`
}

// Expired reports whether the token has expired relative to the given time.
func (r *TokenRecord) Expired(now time.Time) bool {
	if r.ExpiresAt.IsZero() {
		return false
	}
	return !now.Before(r.ExpiresAt)
}

// Revoked reports whether the token has been marked as revoked.
func (r *TokenRecord) Revoked() bool {
	return r.RevokedAt != nil
}

// Active reports whether the token is neither expired nor revoked.
func (r *TokenRecord) Active(now time.Time) bool {
	return !r.Revoked() && !r.Expired(now)
}

// HasScope reports whether the record contains the specified scope.
func (r *TokenRecord) HasScope(scope string) bool {
	return slices.Contains(r.Scopes, scope)
}

// HasScopes reports whether the record satisfies all required scopes.
func (r *TokenRecord) HasScopes(required ...string) bool {
	for _, req := range required {
		if !r.HasScope(req) {
			return false
		}
	}
	return true
}

const (
	ModelBearerTokens = "bearer_tokens"
)

// RegisterSchema registers the bearer_tokens model into the compiled schema.
func RegisterSchema(s *schema.Schema) error {
	m := schema.NewModel(ModelBearerTokens, ModelBearerTokens, "id")
	_ = m.AddField(schema.Field{Name: "id", Type: schema.TypeString, Required: true})
	_ = m.AddField(schema.Field{Name: "token_hash", Type: schema.TypeString, Required: true, Unique: true})
	_ = m.AddField(schema.Field{Name: "subject", Type: schema.TypeString, Required: true})
	_ = m.AddField(schema.Field{Name: "principal_type", Type: schema.TypeString, Required: true})
	_ = m.AddField(schema.Field{Name: "scopes", Type: schema.TypeJSON})
	_ = m.AddField(schema.Field{Name: "metadata", Type: schema.TypeJSON})
	_ = m.AddField(schema.Field{Name: "expires_at", Type: schema.TypeTime, Required: true})
	_ = m.AddField(schema.Field{Name: "revoked_at", Type: schema.TypeTime})
	_ = m.AddField(schema.Field{Name: "created_at", Type: schema.TypeTime, Required: true})
	_ = m.AddField(schema.Field{Name: "updated_at", Type: schema.TypeTime, Required: true})

	m.Indexes = []schema.Index{
		{Name: "idx_bearer_token_hash", Fields: []string{"token_hash"}, Unique: true},
		{Name: "idx_bearer_subject", Fields: []string{"subject"}},
	}

	return s.AddModel(m)
}
