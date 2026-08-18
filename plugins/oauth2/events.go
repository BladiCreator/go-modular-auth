package oauth2

import (
	"time"
)

// Event topic constants dispatched on the shared plugin.Context EventBus.
const (
	// EventClientCreated is dispatched when a new OAuth client is registered.
	EventClientCreated = "oauth2:client:created"

	// EventClientUpdated is dispatched when an existing OAuth client is updated.
	EventClientUpdated = "oauth2:client:updated"

	// EventClientDeleted is dispatched when an OAuth client is deleted.
	EventClientDeleted = "oauth2:client:deleted"

	// EventAuthorizeSuccess is dispatched when an authorization request successfully issues an authorization code.
	EventAuthorizeSuccess = "oauth2:authorize:success"

	// EventAuthorizeFailed is dispatched when an authorization request fails validation or is rejected.
	EventAuthorizeFailed = "oauth2:authorize:failed"

	// EventTokenIssued is dispatched when an access token, refresh token, or ID token is issued.
	EventTokenIssued = "oauth2:token:issued"

	// EventTokenRefreshed is dispatched when a refresh token exchange succeeds with token rotation.
	EventTokenRefreshed = "oauth2:token:refreshed"

	// EventTokenRevoked is dispatched when an access token or refresh token is explicitly revoked.
	EventTokenRevoked = "oauth2:token:revoked"

	// EventConsentGranted is dispatched when an end-user approves requested scopes for a client.
	EventConsentGranted = "oauth2:consent:granted"

	// EventConsentRevoked is dispatched when an end-user revokes previously granted scopes for a client.
	EventConsentRevoked = "oauth2:consent:revoked"

	// EventSessionEnded is dispatched when an RP-Initiated Logout flow completes.
	EventSessionEnded = "oauth2:session:ended"
)

// ClientEventPayload represents the payload dispatched for client lifecycle events.
type ClientEventPayload struct {
	// Client is the OAuth client entity created, updated, or deleted.
	Client *OAuthClient `json:"client"`

	// Timestamp is the moment the event occurred.
	Timestamp time.Time `json:"timestamp"`
}

// AuthorizeSuccessEventPayload represents the payload dispatched upon successful authorization code issuance.
type AuthorizeSuccessEventPayload struct {
	// ClientID is the client ID that received the authorization code.
	ClientID string `json:"client_id"`

	// UserID is the authenticated user ID granting authorization.
	UserID string `json:"user_id"`

	// RedirectURI is the validated callback redirect URI.
	RedirectURI string `json:"redirect_uri"`

	// Scopes is the list of granted scopes.
	Scopes []string `json:"scopes"`

	// Code is the issued authorization code string.
	Code string `json:"code"`

	// Timestamp is the moment the code was issued.
	Timestamp time.Time `json:"timestamp"`
}

// AuthorizeFailedEventPayload represents the payload dispatched when an authorization request fails.
type AuthorizeFailedEventPayload struct {
	// ClientID is the client ID involved in the failed request, if known.
	ClientID string `json:"client_id,omitempty"`

	// Error is the error description of the failure.
	Error string `json:"error"`

	// RedirectURI is the callback URI if available for error redirection.
	RedirectURI string `json:"redirect_uri,omitempty"`

	// Timestamp is the moment the failure occurred.
	Timestamp time.Time `json:"timestamp"`
}

// TokenIssuedEventPayload represents the payload dispatched when tokens are minted.
type TokenIssuedEventPayload struct {
	// ClientID is the client receiving tokens.
	ClientID string `json:"client_id"`

	// UserID is the user ID if issued in user context (nil for M2M client credentials).
	UserID *string `json:"user_id,omitempty"`

	// GrantType is the grant type used for issuance.
	GrantType GrantType `json:"grant_type"`

	// Scopes is the list of scopes granted to the tokens.
	Scopes []string `json:"scopes"`

	// AccessToken is the raw access token string.
	AccessToken string `json:"access_token"`

	// RefreshToken is the raw refresh token string, if issued.
	RefreshToken *string `json:"refresh_token,omitempty"`

	// IDToken is the raw ID token string, if issued.
	IDToken *string `json:"id_token,omitempty"`

	// Timestamp is the moment the tokens were issued.
	Timestamp time.Time `json:"timestamp"`
}

// TokenRefreshedEventPayload represents the payload dispatched upon token refresh rotation.
type TokenRefreshedEventPayload struct {
	// ClientID is the client refreshing tokens.
	ClientID string `json:"client_id"`

	// UserID is the user ID associated with the tokens.
	UserID string `json:"user_id"`

	// FamilyID is the token family identifier.
	FamilyID string `json:"family_id"`

	// NewAccessToken is the newly issued access token.
	NewAccessToken string `json:"new_access_token"`

	// NewRefreshToken is the newly rotated refresh token.
	NewRefreshToken string `json:"new_refresh_token"`

	// Timestamp is the moment the refresh occurred.
	Timestamp time.Time `json:"timestamp"`
}

// TokenRevokedEventPayload represents the payload dispatched when a token is revoked.
type TokenRevokedEventPayload struct {
	// TokenHash is the SHA-256 hash of the revoked token.
	TokenHash string `json:"token_hash"`

	// TokenType is the hinted type ("access_token" or "refresh_token").
	TokenType string `json:"token_type"`

	// ClientID is the client ID associated with the token, if known.
	ClientID string `json:"client_id,omitempty"`

	// Timestamp is the moment revocation occurred.
	Timestamp time.Time `json:"timestamp"`
}

// ConsentEventPayload represents the payload dispatched for user consent events.
type ConsentEventPayload struct {
	// Consent is the consent record granted or revoked.
	Consent *OAuthConsent `json:"consent"`

	// Timestamp is the moment the consent event occurred.
	Timestamp time.Time `json:"timestamp"`
}

// SessionEndedEventPayload represents the payload dispatched when RP-Initiated Logout completes.
type SessionEndedEventPayload struct {
	// UserID is the user ID whose session ended.
	UserID string `json:"user_id"`

	// ClientID is the client that initiated the logout, if known.
	ClientID string `json:"client_id,omitempty"`

	// PostLogoutRedirectURI is the redirect destination after logout.
	PostLogoutRedirectURI string `json:"post_logout_redirect_uri,omitempty"`

	// Timestamp is the moment the session ended.
	Timestamp time.Time `json:"timestamp"`
}
