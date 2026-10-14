package admin

import (
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	"github.com/BladiCreator/go-modular-auth/schema"
	"github.com/BladiCreator/go-modular-auth/user"
)

// UserRecord represents administrative metadata and lifecycle state associated with a Core User.
type UserRecord struct {
	UserID         string            `json:"user_id"`
	Email          string            `json:"email"`
	Disabled       bool              `json:"disabled"`
	DisabledAt     *time.Time        `json:"disabled_at,omitempty"`
	DisabledReason string            `json:"disabled_reason,omitempty"`
	IsAdmin        bool              `json:"is_admin"`
	Role           string            `json:"role,omitempty"`
	Metadata       map[string]string `json:"metadata,omitempty"`
	CreatedAt      time.Time         `json:"created_at"`
	UpdatedAt      time.Time         `json:"updated_at"`
}

// Active reports whether the user is not disabled.
func (r *UserRecord) Active() bool {
	return r != nil && !r.Disabled
}

// ListFilter specifies parameters for querying administrative user lists.
type ListFilter struct {
	Limit  int
	Offset int
	Search string // Prefix or substring match for email
	Status string // "all", "active", "disabled"
}

// AccountDetail exposes non-sensitive external account linkage details for administrative inspection.
type AccountDetail struct {
	ID         string    `json:"id"`
	UserID     string    `json:"user_id"`
	Provider   string    `json:"provider"`
	ProviderID string    `json:"provider_id"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// CredentialDetail exposes sanitized credential metadata.
type CredentialDetail struct {
	ID        string     `json:"id"`
	UserID    string     `json:"user_id"`
	AccountID string     `json:"account_id,omitempty"`
	Type      string     `json:"type"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

// SessionDetail exposes active session metadata without exposing raw session tokens or hashes.
type SessionDetail struct {
	ID        string     `json:"id"`
	UserID    string     `json:"user_id"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt time.Time  `json:"expires_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

// UserDetail provides comprehensive administrative inspection data for a Core User.
type UserDetail struct {
	User        *user.User         `json:"user"`
	Record      *UserRecord        `json:"record"`
	Accounts    []AccountDetail    `json:"accounts"`
	Credentials []CredentialDetail `json:"credentials"`
	Sessions    []SessionDetail    `json:"sessions,omitempty"`
}

// UserListResult encapsulates a paginated set of administrative user summaries.
type UserListResult struct {
	Users  []*UserRecord `json:"users"`
	Total  int           `json:"total"`
	Limit  int           `json:"limit"`
	Offset int           `json:"offset"`
}

// ScopedAdminPrincipal encapsulates an authenticated Principal along with an optional organization scope.
type ScopedAdminPrincipal struct {
	Principal      auth.Principal
	OrganizationID string
}

const (
	ModelAdminUsers = "admin_users"
)

// RegisterSchema registers the admin_users model in the compiled schema.
func RegisterSchema(s *schema.Schema) error {
	m := schema.NewModel(ModelAdminUsers, ModelAdminUsers, "user_id")
	_ = m.AddField(schema.Field{Name: "user_id", Type: schema.TypeString, Required: true})
	_ = m.AddField(schema.Field{Name: "email", Type: schema.TypeString, Required: true})
	_ = m.AddField(schema.Field{Name: "disabled", Type: schema.TypeBool})
	_ = m.AddField(schema.Field{Name: "disabled_at", Type: schema.TypeTime})
	_ = m.AddField(schema.Field{Name: "disabled_reason", Type: schema.TypeString})
	_ = m.AddField(schema.Field{Name: "is_admin", Type: schema.TypeBool})
	_ = m.AddField(schema.Field{Name: "role", Type: schema.TypeString})
	_ = m.AddField(schema.Field{Name: "metadata", Type: schema.TypeJSON})
	_ = m.AddField(schema.Field{Name: "created_at", Type: schema.TypeTime, Required: true})
	_ = m.AddField(schema.Field{Name: "updated_at", Type: schema.TypeTime, Required: true})
	m.Indexes = []schema.Index{
		{Name: "idx_admin_users_email", Fields: []string{"email"}},
		{Name: "idx_admin_users_disabled", Fields: []string{"disabled"}},
		{Name: "idx_admin_users_is_admin", Fields: []string{"is_admin"}},
		{Name: "idx_admin_users_created_at", Fields: []string{"created_at"}},
	}
	return s.AddModel(m)
}
