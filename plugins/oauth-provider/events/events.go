package events

import (
	auth "github.com/BladiCreator/go-modular-auth"
)

// Event names published by the OAuth 2.1 Provider plugin.
const (
	EventClientRegistered        auth.EventName = "oauth_provider.client_registered"
	EventAuthorizationCodeIssued auth.EventName = "oauth_provider.code_issued"
	EventTokenIssued             auth.EventName = "oauth_provider.token_issued"
	EventTokenRevoked            auth.EventName = "oauth_provider.token_revoked"
	EventTokenRefreshed          auth.EventName = "oauth_provider.token_refreshed"
)

// ClientRegisteredPayload contains metadata for ClientRegistered events.
type ClientRegisteredPayload struct {
	ClientID   string `json:"client_id"`
	ClientName string `json:"client_name"`
	ClientType string `json:"client_type"`
}

// CodeIssuedPayload contains metadata for CodeIssued events.
type CodeIssuedPayload struct {
	ClientID string `json:"client_id"`
	UserID   string `json:"user_id"`
}

// TokenIssuedPayload contains metadata for TokenIssued events.
type TokenIssuedPayload struct {
	ClientID  string   `json:"client_id"`
	UserID    string   `json:"user_id,omitempty"`
	GrantType string   `json:"grant_type"`
	Scopes    []string `json:"scopes"`
}

// TokenRevokedPayload contains metadata for TokenRevoked events.
type TokenRevokedPayload struct {
	ClientID string `json:"client_id,omitempty"`
	UserID   string `json:"user_id,omitempty"`
}
