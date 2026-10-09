// Package store defines the persistence contracts and data structures for the OAuth 2.1 Provider.
package store

import (
	"context"
	"errors"
	"time"
)

var (
	// ErrNotFound indicates the requested entity does not exist.
	ErrNotFound = errors.New("oauth_provider store: not found")

	// ErrConflict indicates a uniqueness constraint was violated.
	ErrConflict = errors.New("oauth_provider store: conflict")
)

// ClientType defines the OAuth 2.1 client confidentiality classification.
type ClientType string

const (
	// ClientTypePublic applies to clients incapable of maintaining credential confidentiality (e.g. SPAs, mobile apps).
	ClientTypePublic ClientType = "public"

	// ClientTypeConfidential applies to clients capable of maintaining credential confidentiality (e.g. backend servers).
	ClientTypeConfidential ClientType = "confidential"
)

// ClientStatus defines the operational lifecycle status of an OAuth 2.1 client.
type ClientStatus string

const (
	ClientStatusActive  ClientStatus = "active"
	ClientStatusRevoked ClientStatus = "revoked"
)

// Client represents a registered OAuth 2.1 client application.
type Client struct {
	ID                string       `json:"id"`
	SecretHash        string       `json:"-"` // Never exposed in JSON
	Name              string       `json:"name"`
	ClientType        ClientType   `json:"client_type"`
	RedirectURIs      []string     `json:"redirect_uris"`
	AllowedGrantTypes []string     `json:"allowed_grant_types"`
	AllowedScopes     []string     `json:"allowed_scopes"`
	Status            ClientStatus `json:"status"`
	CreatedAt         time.Time    `json:"created_at"`
	UpdatedAt         time.Time    `json:"updated_at"`
}

// AuthorizationCode represents a short-lived authorization code issued during the authorize flow.
type AuthorizationCode struct {
	ID                  string     `json:"id"`
	CodeHash            string     `json:"-"`
	ClientID            string     `json:"client_id"`
	UserID              string     `json:"user_id"`
	RedirectURI         string     `json:"redirect_uri"`
	Scopes              []string   `json:"scopes"`
	CodeChallenge       string     `json:"code_challenge"`
	CodeChallengeMethod string     `json:"code_challenge_method"`
	ExpiresAt           time.Time  `json:"expires_at"`
	ConsumedAt          *time.Time `json:"consumed_at,omitempty"`
	CreatedAt           time.Time  `json:"created_at"`
}

// AccessToken represents an opaque bearer access token.
type AccessToken struct {
	ID        string     `json:"id"`
	TokenHash string     `json:"-"`
	ClientID  string     `json:"client_id"`
	UserID    string     `json:"user_id,omitempty"` // Empty if issued via client_credentials
	Scopes    []string   `json:"scopes"`
	ExpiresAt time.Time  `json:"expires_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

// RefreshToken represents a long-lived token used to obtain fresh access tokens.
type RefreshToken struct {
	ID            string     `json:"id"`
	TokenHash     string     `json:"-"`
	AccessTokenID string     `json:"access_token_id"`
	ClientID      string     `json:"client_id"`
	UserID        string     `json:"user_id,omitempty"`
	Scopes        []string   `json:"scopes"`
	ExpiresAt     time.Time  `json:"expires_at"`
	RevokedAt     *time.Time `json:"revoked_at,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
}

// Store aggregates the persistence stores for the OAuth 2.1 Provider.
type Store interface {
	Clients() ClientStore
	Codes() CodeStore
	Tokens() TokenStore
	Transaction(ctx context.Context, fn func(ctx context.Context) error) error
}

// ClientStore persists registered client applications.
type ClientStore interface {
	Create(ctx context.Context, c *Client) error
	GetByID(ctx context.Context, id string) (*Client, error)
	Update(ctx context.Context, c *Client) error
	Revoke(ctx context.Context, id string, now time.Time) error
	Delete(ctx context.Context, id string) error
}

// CodeStore manages authorization codes with strict atomic single-use semantics.
type CodeStore interface {
	Create(ctx context.Context, c *AuthorizationCode) error
	GetByHash(ctx context.Context, codeHash string) (*AuthorizationCode, error)
	// Consume atomically consumes an authorization code. Returns ErrConflict if already consumed.
	Consume(ctx context.Context, codeHash string, now time.Time) (*AuthorizationCode, error)
	DeleteExpired(ctx context.Context, now time.Time) (int, error)
}

// TokenStore manages access and refresh tokens.
type TokenStore interface {
	CreateAccessToken(ctx context.Context, t *AccessToken) error
	GetAccessTokenByHash(ctx context.Context, tokenHash string) (*AccessToken, error)
	RevokeAccessToken(ctx context.Context, tokenHash string, now time.Time) error

	CreateRefreshToken(ctx context.Context, t *RefreshToken) error
	GetRefreshTokenByHash(ctx context.Context, tokenHash string) (*RefreshToken, error)
	RevokeRefreshToken(ctx context.Context, tokenHash string, now time.Time) error

	RevokeTokensByClient(ctx context.Context, clientID string, now time.Time) error
	RevokeTokensByUser(ctx context.Context, userID string, now time.Time) error
	DeleteExpired(ctx context.Context, now time.Time) (int, error)
}
