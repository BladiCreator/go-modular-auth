package admin

import (
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	"github.com/BladiCreator/go-modular-auth-admin/store"
	"github.com/BladiCreator/go-modular-auth/user"
)

// UserRecord is an alias for the persistent store's UserRecord.
type UserRecord = store.UserRecord

// ListFilter defines parameters for paginated user queries.
type ListFilter = store.ListFilter

// AccountDetail exposes non-sensitive external account linkage details for administrative inspection.
// It explicitly omits tokens or private OAuth/OIDC state.
type AccountDetail struct {
	ID         string    `json:"id"`
	UserID     string    `json:"user_id"`
	Provider   string    `json:"provider"`
	ProviderID string    `json:"provider_id"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// CredentialDetail exposes sanitized credential metadata.
// CRITICAL: It NEVER exposes Secret, password hash, salt, or cryptographic private keys.
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
