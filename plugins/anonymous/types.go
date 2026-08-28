package anonymous

import (
	"context"

	"github.com/BladiCreator/go-modular-auth/domain/entity"
)

// SignInAnonymousParams holds optional request parameters when initiating an anonymous sign-in session.
type SignInAnonymousParams struct {
	IPAddress string `json:"ip_address,omitempty"`
	UserAgent string `json:"user_agent,omitempty"`
}

// SignInAnonymousResult contains the created anonymous User, Session, and raw token.
type SignInAnonymousResult struct {
	User    *entity.User    `json:"user"`
	Session *entity.Session `json:"session"`
	Token   string          `json:"token"`
}

// DeleteAnonymousUserResult indicates whether the anonymous user deletion completed successfully.
type DeleteAnonymousUserResult struct {
	Success bool `json:"success"`
}

// UserSessionPair pairs an entity.User with their active entity.Session.
type UserSessionPair struct {
	User    *entity.User    `json:"user"`
	Session *entity.Session `json:"session"`
}

// OnLinkAccountData contains previous anonymous account details and new authenticated user details during account linking.
type OnLinkAccountData struct {
	AnonymousUser UserSessionPair `json:"anonymous_user"`
	NewUser       UserSessionPair `json:"new_user"`
}

// LinkAccountCallback is a function signature for custom account linking / data migration logic.
type LinkAccountCallback func(ctx context.Context, data *OnLinkAccountData) error

// GenerateNameCallback is a function signature for generating a custom display name for an anonymous user.
type GenerateNameCallback func(ctx context.Context) (string, error)

// GenerateEmailCallback is a function signature for generating a custom random email address for an anonymous user.
type GenerateEmailCallback func(ctx context.Context) (string, error)
