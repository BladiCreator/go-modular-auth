package oauth2

import "time"

// OAuthClient represents a registered OAuth 2.1 / OpenID Connect client application.
type OAuthClient struct {
	// ID is the internal unique identifier of the client record in the database.
	ID string `json:"id"`

	// ClientID is the unique public client identifier used in OAuth requests.
	ClientID string `json:"client_id"`

	// ClientSecret is the hashed or encrypted client secret (nil for public clients).
	ClientSecret *string `json:"client_secret,omitempty"`

	// ClientSecretExpiresAt is the expiration timestamp for the client secret, if applicable.
	ClientSecretExpiresAt *time.Time `json:"client_secret_expires_at,omitempty"`

	// Name is the human-readable display name of the client application.
	Name string `json:"name"`

	// URI is the home page URL of the client application.
	URI string `json:"uri,omitempty"`

	// Icon is the URL of the client application logo or icon.
	Icon string `json:"icon,omitempty"`

	// Contacts is a list of contact email addresses for the client application.
	Contacts []string `json:"contacts,omitempty"`

	// TOS is the Terms of Service URL for the client application.
	TOS string `json:"tos,omitempty"`

	// Policy is the Privacy Policy URL for the client application.
	Policy string `json:"policy,omitempty"`

	// SoftwareID is an identifier assigned by the client developer (RFC 7591).
	SoftwareID string `json:"software_id,omitempty"`

	// SoftwareVersion is a version identifier assigned by the client developer (RFC 7591).
	SoftwareVersion string `json:"software_version,omitempty"`

	// SoftwareStatement is a signed software statement JWT (RFC 7591).
	SoftwareStatement string `json:"software_statement,omitempty"`

	// RedirectURIs is the list of authorized callback redirect URIs for this client.
	RedirectURIs []string `json:"redirect_uris"`

	// PostLogoutRedirectURIs is the list of allowed post-logout redirect URIs (RP-Initiated Logout).
	PostLogoutRedirectURIs []string `json:"post_logout_redirect_uris,omitempty"`

	// TokenEndpointAuthMethod specifies the authentication method used at the token endpoint ("client_secret_basic", "client_secret_post", "none").
	TokenEndpointAuthMethod TokenEndpointAuthMethod `json:"token_endpoint_auth_method"`

	// GrantTypes is the list of OAuth 2.1 grant types allowed for this client ("authorization_code", "client_credentials", "refresh_token").
	GrantTypes []GrantType `json:"grant_types"`

	// ResponseTypes is the list of response types allowed for this client (typically ["code"]).
	ResponseTypes []ResponseType `json:"response_types"`

	// Scopes is the list of authorized scopes the client may request.
	Scopes []string `json:"scopes,omitempty"`

	// Public indicates if the client is a public client (e.g. SPA, mobile) incapable of protecting secrets.
	Public bool `json:"public"`

	// Type specifies the client category (e.g., "confidential", "public").
	Type ClientType `json:"type,omitempty"`

	// RequirePKCE enforces PKCE code challenge verification (defaults to true in OAuth 2.1).
	RequirePKCE bool `json:"require_pkce"`

	// SubjectType specifies the subject identifier type for OIDC ("public" or "pairwise").
	SubjectType SubjectType `json:"subject_type,omitempty"`

	// SkipConsent indicates if the user consent prompt can be bypassed for trusted first-party clients.
	SkipConsent bool `json:"skip_consent"`

	// EnableEndSession allows this client to trigger RP-Initiated Logout (OIDC End Session).
	EnableEndSession bool `json:"enable_end_session"`

	// Disabled indicates if the client has been administratively disabled.
	Disabled bool `json:"disabled"`

	// UserID is the optional ID of the user who registered/owns this client.
	UserID *string `json:"user_id,omitempty"`

	// ReferenceID is an optional external identifier for multi-tenant or organization mapping.
	ReferenceID *string `json:"reference_id,omitempty"`

	// Metadata holds arbitrary custom properties and client configuration.
	Metadata map[string]any `json:"metadata,omitempty"`

	// CreatedAt is the timestamp when the client record was created.
	CreatedAt time.Time `json:"created_at"`

	// UpdatedAt is the timestamp when the client record was last updated.
	UpdatedAt time.Time `json:"updated_at"`
}

// OAuthAuthorizationCode represents a single-use authorization code issued during the authorization code flow.
type OAuthAuthorizationCode struct {
	// ID is the internal unique identifier of the authorization code record.
	ID string `json:"id"`

	// Code is the raw or hashed authorization code string.
	Code string `json:"code"`

	// ClientID is the client application that requested the authorization code.
	ClientID string `json:"client_id"`

	// UserID is the authenticated user ID granting authorization.
	UserID string `json:"user_id"`

	// SessionID is the active user session ID at the time of authorization.
	SessionID string `json:"session_id"`

	// RedirectURI is the redirect URI verified and locked during the authorization step.
	RedirectURI string `json:"redirect_uri"`

	// CodeChallenge is the Base64URL-encoded SHA-256 PKCE challenge (RFC 7636).
	CodeChallenge string `json:"code_challenge"`

	// CodeChallengeMethod is the PKCE transform method (always "S256" in OAuth 2.1).
	CodeChallengeMethod string `json:"code_challenge_method"`

	// Scopes is the list of granted scopes associated with this authorization code.
	Scopes []string `json:"scopes"`

	// Nonce is an optional string value used to associate a client session with an ID Token (OIDC).
	Nonce string `json:"nonce,omitempty"`

	// Resource is an optional target resource indicator (RFC 8707).
	Resource string `json:"resource,omitempty"`

	// ExpiresAt is the timestamp after which this authorization code is invalid (default: 10m).
	ExpiresAt time.Time `json:"expires_at"`

	// CreatedAt is the timestamp when the authorization code was issued.
	CreatedAt time.Time `json:"created_at"`
}

// OAuthRefreshToken represents a persisted refresh token with rotation and family tracking.
type OAuthRefreshToken struct {
	// ID is the internal unique identifier of the refresh token record.
	ID string `json:"id"`

	// Token is the SHA-256 hash or encrypted refresh token string.
	Token string `json:"token"`

	// ClientID is the client application holding this refresh token.
	ClientID string `json:"client_id"`

	// UserID is the user ID associated with the issued refresh token.
	UserID string `json:"user_id"`

	// SessionID is the optional session ID tied to the refresh token.
	SessionID *string `json:"session_id,omitempty"`

	// ReferenceID is an optional external identifier.
	ReferenceID *string `json:"reference_id,omitempty"`

	// FamilyID is a unique identifier linking all rotated refresh tokens in the same token family.
	// If a revoked token in this family is reused, the entire family is revoked (RFC 6749 Section 10.4).
	FamilyID string `json:"family_id"`

	// Scopes is the list of granted scopes bound to this refresh token.
	Scopes []string `json:"scopes"`

	// ExpiresAt is the timestamp when the refresh token expires.
	ExpiresAt time.Time `json:"expires_at"`

	// CreatedAt is the timestamp when the refresh token was issued.
	CreatedAt time.Time `json:"created_at"`

	// RevokedAt is the timestamp when the refresh token was revoked, if applicable.
	RevokedAt *time.Time `json:"revoked_at,omitempty"`

	// AuthTime is the timestamp when the user originally performed authentication.
	AuthTime *time.Time `json:"auth_time,omitempty"`
}

// OAuthAccessToken represents an issued access token (stored for opaque tokens or introspection).
type OAuthAccessToken struct {
	// ID is the internal unique identifier of the access token record.
	ID string `json:"id"`

	// Token is the SHA-256 hash or encrypted representation of the access token string.
	Token string `json:"token"`

	// ClientID is the client application that received this token.
	ClientID string `json:"client_id"`

	// UserID is the authenticated user ID (nil for machine-to-machine client credentials).
	UserID *string `json:"user_id,omitempty"`

	// SessionID is the optional session ID tied to this token.
	SessionID *string `json:"session_id,omitempty"`

	// RefreshID is the optional ID of the parent refresh token that spawned this access token.
	RefreshID *string `json:"refresh_id,omitempty"`

	// ReferenceID is an optional external identifier.
	ReferenceID *string `json:"reference_id,omitempty"`

	// Scopes is the list of granted scopes authorized by this token.
	Scopes []string `json:"scopes"`

	// ExpiresAt is the timestamp when the access token expires.
	ExpiresAt time.Time `json:"expires_at"`

	// CreatedAt is the timestamp when the access token was issued.
	CreatedAt time.Time `json:"created_at"`
}

// OAuthConsent represents explicit consent granted by an end-user to a client application for a set of scopes.
type OAuthConsent struct {
	// ID is the internal unique identifier of the consent record.
	ID string `json:"id"`

	// ClientID is the client application identifier.
	ClientID string `json:"client_id"`

	// UserID is the user ID who granted the consent.
	UserID string `json:"user_id"`

	// ReferenceID is an optional external identifier.
	ReferenceID *string `json:"reference_id,omitempty"`

	// Scopes is the list of scopes approved by the user.
	Scopes []string `json:"scopes"`

	// CreatedAt is the timestamp when consent was first granted.
	CreatedAt time.Time `json:"created_at"`

	// UpdatedAt is the timestamp when consent was last modified.
	UpdatedAt time.Time `json:"updated_at"`
}
