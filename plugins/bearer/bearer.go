package bearer

import (
	"context"
	"strings"
	"time"

	"github.com/BladiCreator/go-modular-auth/domain/entity"
	"github.com/BladiCreator/go-modular-auth/plugin"
)

// PluginID is the unique string identifier for the Bearer plugin ("bearer").
const PluginID = "bearer"

// Parameter and Result Structs
type (
	// VerifyParams defines parameters required to verify an incoming Bearer token.
	VerifyParams struct {
		// Token is the raw or signed token string or extracted authorization header (required).
		Token string `json:"token"`

		// Secret optionally overrides the default secret key configured on the plugin.
		Secret string `json:"secret,omitempty"`

		// Extra holds dynamic metadata passed through event interceptors (optional).
		Extra map[string]any `json:"extra,omitempty"`
	}

	// VerifyResult contains the outcome of a successful token validation.
	VerifyResult struct {
		// RawToken is the extracted unsigned token identifier.
		RawToken string `json:"raw_token"`

		// SignedToken is the complete signed token representation.
		SignedToken string `json:"signed_token"`

		// Valid indicates whether the cryptographic signature was valid.
		Valid bool `json:"valid"`
	}

	// CreateTokenParams defines parameters to generate and sign a Bearer token.
	CreateTokenParams struct {
		// Token is the base session token or unique string identifier to sign (required).
		Token string `json:"token"`

		// Secret optionally overrides the default secret key configured on the plugin.
		Secret string `json:"secret,omitempty"`

		// UserID optionally associates an owner user ID with the created token.
		UserID string `json:"user_id,omitempty"`

		// Extra holds dynamic metadata passed through event interceptors (optional).
		Extra map[string]any `json:"extra,omitempty"`
	}

	// CreateTokenResult contains the generated signed token and ready-to-use HTTP header values.
	CreateTokenResult struct {
		// RawToken is the base unsigned token string.
		RawToken string `json:"raw_token"`

		// SignedToken is the HMAC-SHA256 signed token.
		SignedToken string `json:"signed_token"`

		// HeaderValue is the formatted Authorization header string ("Bearer <signed_token>").
		HeaderValue string `json:"header_value"`

		// AuthTokenHeader is the response header name (default: "set-auth-token").
		AuthTokenHeader string `json:"auth_token_header"`
	}

	// ResolveSessionParams defines parameters to extract, verify, and look up an active session entity.
	ResolveSessionParams struct {
		// Header is the full HTTP Authorization header value (e.g. "Bearer <token>.<sig>").
		Header string `json:"header,omitempty"`

		// Token is the direct token string if already extracted.
		Token string `json:"token,omitempty"`

		// Secret optionally overrides the secret key.
		Secret string `json:"secret,omitempty"`

		// Extra holds dynamic metadata passed through event interceptors (optional).
		Extra map[string]any `json:"extra,omitempty"`
	}

	// ResolveSessionResult contains the active session entity and processed token values.
	ResolveSessionResult struct {
		// Session is the active, non-expired session entity retrieved from storage.
		Session *entity.Session `json:"session"`

		// RawToken is the verified raw token string used for querying the session.
		RawToken string `json:"raw_token"`

		// SignedToken is the verified signed token string.
		SignedToken string `json:"signed_token"`
	}
)

// Set attaches dynamic metadata to VerifyParams.
func (p *VerifyParams) Set(key string, value any) {
	if p.Extra == nil {
		p.Extra = make(map[string]any)
	}
	p.Extra[key] = value
}

// Get safely retrieves dynamic metadata from VerifyParams.
func (p *VerifyParams) Get(key string) (any, bool) {
	if p.Extra == nil {
		return nil, false
	}
	val, ok := p.Extra[key]
	return val, ok
}

// Set attaches dynamic metadata to CreateTokenParams.
func (p *CreateTokenParams) Set(key string, value any) {
	if p.Extra == nil {
		p.Extra = make(map[string]any)
	}
	p.Extra[key] = value
}

// Get safely retrieves dynamic metadata from CreateTokenParams.
func (p *CreateTokenParams) Get(key string) (any, bool) {
	if p.Extra == nil {
		return nil, false
	}
	val, ok := p.Extra[key]
	return val, ok
}

// Set attaches dynamic metadata to ResolveSessionParams.
func (p *ResolveSessionParams) Set(key string, value any) {
	if p.Extra == nil {
		p.Extra = make(map[string]any)
	}
	p.Extra[key] = value
}

// Get safely retrieves dynamic metadata from ResolveSessionParams.
func (p *ResolveSessionParams) Get(key string) (any, bool) {
	if p.Extra == nil {
		return nil, false
	}
	val, ok := p.Extra[key]
	return val, ok
}

// Plugin implements Bearer Token Authentication capabilities.
type Plugin struct {
	repo   Repository
	config Config
	ctx    *plugin.Context
}

// New creates a new Bearer plugin instance configured with an optional repository and functional options.
//
// Arguments:
//   - repo: Implementation of bearer.Repository interface (can be nil if only token crypto is required).
//   - opts: Functional configuration options (WithSecret, WithRequireSignature, WithTokenHeader, etc.).
//
// Returns:
//   - *Plugin: The configured Bearer plugin instance.
func New(repo Repository, opts ...Option) *Plugin {
	cfg := DefaultConfig()
	for _, opt := range opts {
		opt(&cfg)
	}
	return &Plugin{
		repo:   repo,
		config: cfg,
	}
}

// ID returns the unique identifier for the Bearer plugin ("bearer").
func (p *Plugin) ID() string {
	return PluginID
}

// Init initializes the plugin within the global GoModularAuth context.
func (p *Plugin) Init(ctx *plugin.Context) error {
	p.ctx = ctx
	return nil
}

// Config returns the active configuration settings of the Bearer plugin.
func (p *Plugin) Config() Config {
	return p.config
}

// Verify validates the HMAC-SHA256 signature of a token, auto-signs raw tokens if enabled,
// and caches the resulting token in the shared context.
//
// Brief Explanation:
//
//	Validates token format, decodes percent-encoded characters, validates HMAC signature in constant time,
//	and publishes EventBearerVerifyBefore and EventBearerVerifyAfter.
//
// Arguments:
//   - ctx: Request cancellation context.
//   - params: VerifyParams containing the token string and optional Secret override.
//
// Returns:
//   - *VerifyResult: Contains the raw token and signed token.
//   - error: ErrTokenEmpty, ErrInvalidTokenFormat, ErrInvalidSignature, or ErrSecretRequired.
//
// Example:
//
//	res, err := bearerPlugin.Verify(ctx, bearer.VerifyParams{
//		Token: "my_token.3hA9...sig",
//	})
//	if err != nil {
//		log.Fatalf("Invalid bearer token: %v", err)
//	}
//	fmt.Println("Verified raw token:", res.RawToken)
func (p *Plugin) Verify(ctx context.Context, params VerifyParams) (*VerifyResult, error) {
	token := strings.TrimSpace(params.Token)
	if token == "" {
		return nil, ErrTokenEmpty
	}

	secret := p.config.Secret
	if params.Secret != "" {
		secret = params.Secret
	}

	p.publishEvent(EventBearerVerifyBefore, ctx, &BearerVerifyBeforeEventPayload{
		RawToken: token,
		Params:   &params,
	})

	var rawToken, signedToken string

	if strings.Contains(token, ".") {
		decoded := TryDecodeToken(token)
		verifiedRaw, err := VerifyToken(decoded, secret)
		if err != nil {
			p.publishEvent(EventBearerVerifyAfter, ctx, &BearerVerifyAfterEventPayload{
				Token: token,
				Valid: false,
			})
			return nil, err
		}
		rawToken = verifiedRaw
		signedToken = decoded
	} else {
		if p.config.RequireSignature {
			p.publishEvent(EventBearerVerifyAfter, ctx, &BearerVerifyAfterEventPayload{
				Token: token,
				Valid: false,
			})
			return nil, ErrInvalidTokenFormat
		}
		if secret == "" {
			return nil, ErrSecretRequired
		}
		rawToken = token
		signedToken = SignToken(token, secret)
	}

	if p.ctx != nil {
		p.ctx.Set(plugin.ContextKeyBearerToken, signedToken)
	}

	p.publishEvent(EventBearerVerifyAfter, ctx, &BearerVerifyAfterEventPayload{
		Token: signedToken,
		Valid: true,
	})

	return &VerifyResult{
		RawToken:    rawToken,
		SignedToken: signedToken,
		Valid:       true,
	}, nil
}

// CreateToken creates an HMAC-SHA256 signed bearer token from a raw session or user identifier.
//
// Brief Explanation:
//
//	Appends an HMAC-SHA256 signature encoded with RawURLEncoding to the input token string
//	and publishes EventBearerTokenCreated.
//
// Arguments:
//   - ctx: Request cancellation context.
//   - params: CreateTokenParams containing Token string, optional Secret, and UserID.
//
// Returns:
//   - *CreateTokenResult: Signed token, Authorization header value, and output header name.
//   - error: ErrTokenEmpty or ErrSecretRequired.
//
// Example:
//
//	res, err := bearerPlugin.CreateToken(ctx, bearer.CreateTokenParams{
//		Token:  "session_token_123",
//		UserID: "user_456",
//	})
//	if err != nil {
//		log.Fatalf("Token creation failed: %v", err)
//	}
//	fmt.Println("Header value:", res.HeaderValue)
func (p *Plugin) CreateToken(ctx context.Context, params CreateTokenParams) (*CreateTokenResult, error) {
	token := strings.TrimSpace(params.Token)
	if token == "" {
		return nil, ErrTokenEmpty
	}

	secret := p.config.Secret
	if params.Secret != "" {
		secret = params.Secret
	}
	if secret == "" {
		return nil, ErrSecretRequired
	}

	signed := SignToken(token, secret)

	p.publishEvent(EventBearerTokenCreated, ctx, &BearerTokenCreatedEventPayload{
		RawToken:    token,
		SignedToken: signed,
		UserID:      params.UserID,
	})

	return &CreateTokenResult{
		RawToken:        token,
		SignedToken:     signed,
		HeaderValue:     p.FormatHeader(signed),
		AuthTokenHeader: p.config.AuthTokenHeader,
	}, nil
}

// ResolveSession extracts the bearer token from an Authorization header or string, verifies its signature,
// and retrieves the corresponding non-expired Session entity from storage.
//
// Brief Explanation:
//
//	Performs header extraction, signature verification, repository lookup, expiry check, and context caching.
//
// Arguments:
//   - ctx: Request cancellation context.
//   - params: ResolveSessionParams containing Header or Token.
//
// Returns:
//   - *ResolveSessionResult: Session entity, verified raw token, and signed token.
//   - error: ErrTokenEmpty, ErrInvalidHeader, ErrInvalidSignature, ErrSessionNotFound, or ErrSessionExpired.
//
// Example:
//
//	res, err := bearerPlugin.ResolveSession(ctx, bearer.ResolveSessionParams{
//		Header: "Bearer " + signedToken,
//	})
//	if err != nil {
//		log.Fatalf("Failed to resolve session: %v", err)
//	}
//	fmt.Println("Session user ID:", res.Session.UserID)
func (p *Plugin) ResolveSession(ctx context.Context, params ResolveSessionParams) (*ResolveSessionResult, error) {
	var tokenStr string
	if params.Header != "" {
		extracted, err := p.ExtractToken(params.Header)
		if err != nil {
			return nil, err
		}
		tokenStr = extracted
	} else if params.Token != "" {
		tokenStr = params.Token
	} else {
		return nil, ErrTokenEmpty
	}

	verifyRes, err := p.Verify(ctx, VerifyParams{
		Token:  tokenStr,
		Secret: params.Secret,
	})
	if err != nil {
		return nil, err
	}

	if p.repo == nil {
		return &ResolveSessionResult{
			RawToken:    verifyRes.RawToken,
			SignedToken: verifyRes.SignedToken,
		}, nil
	}

	sess, err := p.repo.GetSessionByToken(ctx, verifyRes.RawToken)
	if err != nil {
		return nil, err
	}

	if !sess.ExpiresAt.IsZero() && time.Now().After(sess.ExpiresAt) {
		return nil, ErrSessionExpired
	}

	if p.ctx != nil {
		p.ctx.Set(plugin.ContextKeySession, sess)
	}

	return &ResolveSessionResult{
		Session:     sess,
		RawToken:    verifyRes.RawToken,
		SignedToken: verifyRes.SignedToken,
	}, nil
}

// ExtractToken extracts the bearer token from an HTTP Authorization header string according to RFC 7235.
func (p *Plugin) ExtractToken(headerValue string) (string, error) {
	trimmed := strings.TrimSpace(headerValue)
	if trimmed == "" {
		return "", ErrTokenEmpty
	}

	if strings.EqualFold(trimmed, "bearer") {
		return "", ErrTokenEmpty
	}

	if len(trimmed) < len(BearerSchemePrefix) ||
		strings.ToLower(trimmed[:len(BearerSchemePrefix)]) != BearerSchemePrefix {
		return "", ErrInvalidHeader
	}

	token := strings.TrimSpace(trimmed[len(BearerSchemePrefix):])
	if token == "" {
		return "", ErrTokenEmpty
	}

	return token, nil
}

// FormatHeader formats a signed token string as a standard HTTP Authorization header ("Bearer <token>").
func (p *Plugin) FormatHeader(token string) string {
	return "Bearer " + token
}

// FormatAuthTokenHeader returns the configured response header name and value for client consumption.
func (p *Plugin) FormatAuthTokenHeader(token string) (headerName, headerValue string) {
	return p.config.AuthTokenHeader, token
}

// ExposedHeaders returns the comma-separated header names to expose in CORS Access-Control-Expose-Headers.
func (p *Plugin) ExposedHeaders() string {
	return p.config.AuthTokenHeader
}

// publishEvent dispatches a typed event payload through the shared EventBus if initialized.
func (p *Plugin) publishEvent(topic string, ctx context.Context, payload any) {
	if p.ctx != nil && p.ctx.Events() != nil {
		p.ctx.Events().Publish(topic, ctx, payload)
	}
}
