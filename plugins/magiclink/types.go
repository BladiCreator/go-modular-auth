package magiclink

import (
	"time"

	"github.com/BladiCreator/go-modular-auth/domain/entity"
	"github.com/BladiCreator/go-modular-auth/plugin"
)

// DTO Parameter and Result Structs

// SignInMagicLinkParams defines input parameters to generate and send a magic link email.
type SignInMagicLinkParams struct {
	// Email is the target recipient email address (required).
	Email string `json:"email"`

	// Name is an optional recipient display name.
	Name string `json:"name,omitempty"`

	// CallbackURL is the target redirect URL after successful verification.
	CallbackURL string `json:"callback_url,omitempty"`

	// NewUserCallbackURL is an optional target redirect URL for newly created users.
	NewUserCallbackURL string `json:"new_user_callback_url,omitempty"`

	// ErrorCallbackURL is an optional target redirect URL on verification error.
	ErrorCallbackURL string `json:"error_callback_url,omitempty"`

	plugin.ExtraContainer
}

// SignInMagicLinkResult contains delivery status and expiration of the generated magic link.
type SignInMagicLinkResult struct {
	// Success indicates if the magic link was generated and dispatched.
	Success bool `json:"success"`

	// ExpiresAt indicates when the dispatched magic link token will expire.
	ExpiresAt time.Time `json:"expires_at"`
}

// VerifyMagicLinkParams defines input parameters to verify a magic link token.
type VerifyMagicLinkParams struct {
	// Token is the magic link verification token string (required).
	Token string `json:"token"`

	// Email is an optional email address parameter for token scoping.
	Email string `json:"email,omitempty"`

	// CallbackURL overrides post-verification redirect URL.
	CallbackURL string `json:"callback_url,omitempty"`

	// NewUserCallbackURL overrides new-user redirect URL.
	NewUserCallbackURL string `json:"new_user_callback_url,omitempty"`

	// ErrorCallbackURL overrides error redirect URL.
	ErrorCallbackURL string `json:"error_callback_url,omitempty"`

	plugin.ExtraContainer
}

// VerifyMagicLinkResult contains the authenticated user, session, and redirect URL output.
type VerifyMagicLinkResult struct {
	// User is the authenticated or newly created user entity.
	User *entity.User `json:"user"`

	// Session is the newly created active user session.
	Session *entity.Session `json:"session"`

	// IsNewUser reports whether a new user account was registered during verification.
	IsNewUser bool `json:"is_new_user"`

	// RedirectURL is the calculated destination URL for browser navigation.
	RedirectURL string `json:"redirect_url"`
}
