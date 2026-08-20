package bearer

import (
	"github.com/BladiCreator/go-modular-auth/domain/entity"
	"github.com/BladiCreator/go-modular-auth/plugin"
)

// Parameter and Result Structs
type (
	// VerifyParams defines parameters required to verify an incoming Bearer token.
	VerifyParams struct {
		// Token is the raw or signed token string or extracted authorization header (required).
		Token string `json:"token"`

		// Secret optionally overrides the default secret key configured on the plugin.
		Secret string `json:"secret,omitempty"`

		plugin.ExtraContainer
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

		plugin.ExtraContainer
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

		plugin.ExtraContainer
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
