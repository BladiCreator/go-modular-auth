package oauth

import (
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	"github.com/BladiCreator/go-modular-auth-oauth/provider"
	"github.com/BladiCreator/go-modular-auth/account"
	"github.com/BladiCreator/go-modular-auth/session"
	"github.com/BladiCreator/go-modular-auth/user"
)

// LinkingPolicy determines how the OAuth plugin resolves collisions when an external
// OAuth profile presents an email address that already belongs to an existing user in Core.
type LinkingPolicy string

const (
	// LinkingPolicyExplicitOnly requires account linking to be initiated explicitly
	// by an authenticated user (via BeginLink/CompleteLink).
	// If an unlinked user with a matching email attempts OAuth sign-in, it fails with
	// ErrAccountLinkingRequiresConsent, preventing unsafe automatic account linking.
	LinkingPolicyExplicitOnly LinkingPolicy = "explicit_only"

	// LinkingPolicyVerifiedEmail permits automatic account linking ONLY IF:
	// 1. The external OAuth provider asserts profile.EmailVerified == true.
	// 2. The existing Core User has user.EmailVerified == true.
	// 3. The email addresses match.
	// If either email is not verified, it fails with ErrUnverifiedEmailLinkingProhibited.
	LinkingPolicyVerifiedEmail LinkingPolicy = "verified_email"

	// LinkingPolicyDisabled completely disallows account linking. If a user with the same
	// email already exists, it fails with ErrAccountConflict.
	LinkingPolicyDisabled LinkingPolicy = "disabled"
)

// BeginAuthInput contains parameters for initiating an OAuth authorization code flow.
type BeginAuthInput struct {
	// Provider is the identifier of the registered OAuth provider (e.g. "google").
	Provider string

	// RedirectURI is the target callback URI to which the provider should redirect.
	RedirectURI string

	// Scopes specifies scopes for this request, overriding provider defaults if provided.
	Scopes []string

	// Prompt controls the IdP prompt behavior (e.g. "consent", "select_account").
	Prompt string

	// AccessType controls whether offline access / refresh tokens are requested ("offline").
	AccessType string

	// Metadata stores custom client state associated with this in-flight flow.
	Metadata map[string]string

	// UsePKCE overrides the default PKCE setting for this request (nil uses plugin default, which is true).
	UsePKCE *bool
}

// BeginAuthResult contains the computed authorization URL and state session metadata.
type BeginAuthResult struct {
	// AuthURL is the complete provider URL the client browser should navigate to.
	AuthURL string

	// State is the unique, cryptographically random state identifier.
	State string

	// CodeVerifier is the generated PKCE verifier (stored securely in state session).
	CodeVerifier string

	// ExpiresAt specifies when the state session expires.
	ExpiresAt time.Time
}

// BeginLinkInput contains parameters for initiating an account linking ceremony.
type BeginLinkInput struct {
	// UserID is the ID of the currently authenticated Core user who is linking an account.
	UserID string

	// Provider is the identifier of the registered OAuth provider.
	Provider string

	// RedirectURI is the callback URI.
	RedirectURI string

	// Scopes specifies requested scopes.
	Scopes []string

	// Prompt controls the IdP prompt behavior.
	Prompt string

	// AccessType controls access type.
	AccessType string

	// Metadata stores custom client state.
	Metadata map[string]string

	// UsePKCE overrides default PKCE behavior.
	UsePKCE *bool
}

// CompleteAuthInput contains parameters received from the provider's OAuth callback.
type CompleteAuthInput struct {
	// Provider is the identifier of the OAuth provider.
	Provider string

	// Code is the authorization code returned by the provider.
	Code string

	// State is the state parameter returned by the provider.
	State string

	// RedirectURI is the redirect URI supplied to the provider callback.
	RedirectURI string

	// Session holds optional metadata (IP address, user agent) recorded when creating the core session.
	Session auth.SessionOptions
}

// CompleteLinkInput contains parameters to finalize an explicit account linking flow.
type CompleteLinkInput struct {
	// Code is the authorization code returned by the provider.
	Code string

	// State is the state parameter returned by the provider.
	State string

	// RedirectURI is the callback redirect URI.
	RedirectURI string
}

// AuthResult represents the outcome of a successful OAuth authentication flow.
type AuthResult struct {
	// User is the resolved or newly created Core User.
	User *user.User

	// Account is the Core Account linking the User to this OAuth provider.
	Account *account.Account

	// Session is the newly issued Core Session.
	Session *session.Session

	// Token is the plaintext session token returned strictly once at session creation.
	Token string

	// IsNewUser indicates whether this authentication caused a new user to be registered.
	IsNewUser bool

	// TokenResponse holds the tokens returned by the OAuth provider.
	TokenResponse *provider.TokenResponse

	// Profile holds the normalized profile attributes fetched from the provider.
	Profile *provider.ProviderProfile
}

// LinkResult represents the outcome of a successful explicit account linking operation.
type LinkResult struct {
	// User is the authenticated Core User who owns the linked account.
	User *user.User

	// Account is the newly created Core Account link.
	Account *account.Account

	// Profile is the normalized profile claims fetched from the provider.
	Profile *provider.ProviderProfile
}
