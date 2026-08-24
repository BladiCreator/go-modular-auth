package oidcprovider

const (
	// EventOIDCClientRegistered is published when a new OAuth client is registered.
	EventOIDCClientRegistered = "oidc:client_registered"

	// EventOIDCAuthCodeIssued is published when an authorization code is successfully generated.
	EventOIDCAuthCodeIssued = "oidc:auth_code_issued"

	// EventOIDCTokenIssued is published when tokens (Access, Refresh, ID Token) are issued.
	EventOIDCTokenIssued = "oidc:token_issued"

	// EventOIDCTokenRefreshed is published when tokens are exchanged via a refresh token.
	EventOIDCTokenRefreshed = "oidc:token_refreshed"

	// EventOIDCConsentGranted is published when a user grants scope consent to a client.
	EventOIDCConsentGranted = "oidc:consent_granted"

	// EventOIDCConsentRevoked is published when user consent for a client is revoked.
	EventOIDCConsentRevoked = "oidc:consent_revoked"
)

// OIDCClientRegisteredPayload defines the event bus payload when a client application is created.
type OIDCClientRegisteredPayload struct {
	Client *OAuthClient `json:"client"`
}

// OIDCAuthCodeIssuedPayload defines the event bus payload when an authorization code is issued.
type OIDCAuthCodeIssuedPayload struct {
	Code     string `json:"code"`
	ClientID string `json:"client_id"`
	UserID   string `json:"user_id"`
}

// OIDCTokenIssuedPayload defines the event bus payload when an access/id token is issued.
type OIDCTokenIssuedPayload struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	ClientID     string `json:"client_id"`
	UserID       string `json:"user_id"`
}

// OIDCTokenRefreshedPayload defines the event bus payload when tokens are refreshed.
type OIDCTokenRefreshedPayload struct {
	NewAccessToken  string `json:"new_access_token"`
	NewRefreshToken string `json:"new_refresh_token,omitempty"`
	ClientID        string `json:"client_id"`
	UserID          string `json:"user_id"`
}

// OIDCConsentGrantedPayload defines the event bus payload when consent is given.
type OIDCConsentGrantedPayload struct {
	ClientID string   `json:"client_id"`
	UserID   string   `json:"user_id"`
	Scopes   []string `json:"scopes"`
}

// OIDCConsentRevokedPayload defines the event bus payload when consent is revoked.
type OIDCConsentRevokedPayload struct {
	ClientID string `json:"client_id"`
	UserID   string `json:"user_id"`
}
