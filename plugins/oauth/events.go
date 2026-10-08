package oauth

import (
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
)

// OAuth event names published through the core Event dispatcher.
const (
	// EventOAuthStateCreated is emitted when a new OAuth state session is initiated.
	EventOAuthStateCreated auth.EventName = "oauth.state_created"

	// EventOAuthAuthenticated is emitted when a user successfully authenticates via OAuth.
	EventOAuthAuthenticated auth.EventName = "oauth.authenticated"

	// EventOAuthUserCreated is emitted when a new Core User is registered during OAuth flow.
	EventOAuthUserCreated auth.EventName = "oauth.user_created"

	// EventOAuthAccountLinked is emitted when a provider account is linked to a Core User.
	EventOAuthAccountLinked auth.EventName = "oauth.account_linked"

	// EventOAuthAccountUnlinked is emitted when a provider account link is removed.
	EventOAuthAccountUnlinked auth.EventName = "oauth.account_unlinked"

	// EventOAuthFailed is emitted when an OAuth authentication flow fails.
	EventOAuthFailed auth.EventName = "oauth.failed"
)

// StateCreatedPayload contains non-sensitive audit details for state creation.
type StateCreatedPayload struct {
	Provider  string    `json:"provider"`
	State     string    `json:"state"`
	Action    string    `json:"action"`
	UserID    string    `json:"user_id,omitempty"`
	ExpiresAt time.Time `json:"expires_at"`
}

// AuthenticatedPayload contains details for successful authentication.
type AuthenticatedPayload struct {
	UserID     string `json:"user_id"`
	AccountID  string `json:"account_id"`
	Provider   string `json:"provider"`
	ProviderID string `json:"provider_id"`
	IsNewUser  bool   `json:"is_new_user"`
}

// UserCreatedPayload contains details for new user creation via OAuth.
type UserCreatedPayload struct {
	UserID     string `json:"user_id"`
	Email      string `json:"email"`
	Provider   string `json:"provider"`
	ProviderID string `json:"provider_id"`
}

// AccountLinkedPayload contains details for account link events.
type AccountLinkedPayload struct {
	UserID     string `json:"user_id"`
	AccountID  string `json:"account_id"`
	Provider   string `json:"provider"`
	ProviderID string `json:"provider_id"`
}

// AccountUnlinkedPayload contains details for account unlink events.
type AccountUnlinkedPayload struct {
	UserID    string `json:"user_id"`
	AccountID string `json:"account_id"`
	Provider  string `json:"provider"`
}

// FailedPayload contains details for failed OAuth operations.
type FailedPayload struct {
	Provider string `json:"provider"`
	Reason   string `json:"reason"`
}
