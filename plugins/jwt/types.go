package jwt

import (
	"time"

	"github.com/BladiCreator/go-modular-auth/domain/entity"
	"github.com/BladiCreator/go-modular-auth/plugin"
)

// Parameter and Result Structs
type (
	// SignParams defines parameters required to construct and sign a JSON Web Token.
	SignParams struct {
		// Payload contains custom application claims to include in the token (optional).
		Payload map[string]any `json:"payload,omitempty"`

		// Subject sets the "sub" claim value (optional, overrides default).
		Subject string `json:"subject,omitempty"`

		// Issuer overrides the default configured "iss" claim value (optional).
		Issuer string `json:"issuer,omitempty"`

		// Audience overrides the default configured "aud" claim list (optional).
		Audience []string `json:"audience,omitempty"`

		// ExpiresIn overrides the default validity duration for this specific token (optional).
		ExpiresIn time.Duration `json:"expires_in,omitempty"`

		// NotBefore optionally sets the "nbf" claim timestamp (optional).
		NotBefore *time.Time `json:"not_before,omitempty"`

		// KeyID explicitly specifies which persisted key to use for signing (optional; uses active key if empty).
		KeyID string `json:"key_id,omitempty"`

		plugin.ExtraContainer
	}

	// SignResult contains the signed compact JWT string and associated metadata.
	SignResult struct {
		// Token is the serialized RFC 7519 compact JWT string.
		Token string `json:"token"`

		// KeyID is the ID of the key that signed the token.
		KeyID string `json:"key_id"`

		// Algorithm is the cryptographic signature algorithm used.
		Algorithm Algorithm `json:"alg"`

		// ExpiresAt is the calculated expiration timestamp.
		ExpiresAt time.Time `json:"expires_at"`

		// HeaderValue is the formatted Authorization header string ("Bearer <token>").
		HeaderValue string `json:"header_value"`

		// AuthJWTHeader is the standard response header name ("set-auth-jwt").
		AuthJWTHeader string `json:"auth_jwt_header"`
	}

	// VerifyParams defines parameters required to verify an incoming JWT string.
	VerifyParams struct {
		// Token is the compact JWT string or authorization header value (required).
		Token string `json:"token"`

		// Issuer optionally enforces an expected "iss" claim match during verification.
		Issuer string `json:"issuer,omitempty"`

		// Audience optionally enforces expected "aud" claim recipients.
		Audience []string `json:"audience,omitempty"`

		// Leeway overrides the clock skew tolerance window for exp/nbf validation (optional).
		Leeway time.Duration `json:"leeway,omitempty"`

		plugin.ExtraContainer
	}

	// VerifyResult contains the outcome of a successful JWT verification.
	VerifyResult struct {
		// Valid indicates whether the signature and standard claims are valid.
		Valid bool `json:"valid"`

		// Subject is the "sub" claim extracted from the payload.
		Subject string `json:"subject,omitempty"`

		// Claims contains all claims present in the token payload.
		Claims map[string]any `json:"claims"`

		// KeyID is the "kid" identifier of the key used to verify the signature.
		KeyID string `json:"key_id"`

		// Algorithm is the cryptographic algorithm specified in the JWS header.
		Algorithm Algorithm `json:"alg"`

		// ExpiresAt is the expiration time parsed from the "exp" claim (if present).
		ExpiresAt *time.Time `json:"expires_at,omitempty"`

		// IssuedAt is the timestamp parsed from the "iat" claim (if present).
		IssuedAt *time.Time `json:"issued_at,omitempty"`

		// NotBefore is the timestamp parsed from the "nbf" claim (if present).
		NotBefore *time.Time `json:"not_before,omitempty"`
	}

	// GetTokenParams defines parameters to generate a signed JWT for an active session and user.
	GetTokenParams struct {
		// Session is the active authenticated session (required).
		Session *entity.Session `json:"session"`

		// User is the authenticated user entity (optional, provides email/name for custom claims).
		User *entity.User `json:"user,omitempty"`

		// ExpiresIn overrides the default validity duration for this session token (optional).
		ExpiresIn time.Duration `json:"expires_in,omitempty"`

		plugin.ExtraContainer
	}

	// GetTokenResult contains the generated session JWT and HTTP header representations.
	GetTokenResult struct {
		// Token is the issued compact JWT string.
		Token string `json:"token"`

		// KeyID is the key identifier used for the signature.
		KeyID string `json:"key_id"`

		// Algorithm is the cryptographic signature algorithm used.
		Algorithm Algorithm `json:"alg"`

		// ExpiresAt is the token expiration timestamp.
		ExpiresAt time.Time `json:"expires_at"`

		// HeaderValue is the formatted Authorization header string ("Bearer <token>").
		HeaderValue string `json:"header_value"`

		// AuthJWTHeader is the standard response header name ("set-auth-jwt").
		AuthJWTHeader string `json:"auth_jwt_header"`
	}

	// GetJWKSParams defines parameters to retrieve the public JSON Web Key Set.
	GetJWKSParams struct {
		// IncludeExpired specifies whether to include keys older than the grace period (default: false).
		IncludeExpired bool `json:"include_expired,omitempty"`

		plugin.ExtraContainer
	}

	// GetJWKSResult contains the public JWKS collection and metadata.
	GetJWKSResult struct {
		// JWKS is the RFC 7517 JSON Web Key Set containing active and grace-period public keys.
		JWKS *JWKS `json:"jwks"`

		// KeysCount is the number of public keys included.
		KeysCount int `json:"keys_count"`
	}

	// RotateKeysParams defines parameters to trigger an immediate key rotation.
	RotateKeysParams struct {
		// Algorithm optionally specifies a different algorithm for the new key (optional).
		Algorithm Algorithm `json:"alg,omitempty"`

		// RSABits optionally specifies the RSA bit length if rotating to an RSA key (optional).
		RSABits int `json:"rsa_bits,omitempty"`

		// ExpiresIn optionally sets an expiration date for the old active key (optional).
		ExpiresIn time.Duration `json:"expires_in,omitempty"`

		plugin.ExtraContainer
	}

	// RotateKeysResult contains details of the newly created and active key pair.
	RotateKeysResult struct {
		// NewKey is the persisted record of the new active key pair.
		NewKey *JWKRecord `json:"new_key"`

		// JWK is the public JWK representation of the new key.
		JWK *JWK `json:"jwk"`

		// OldKeyID is the Key ID of the rotated previous key (if one was active).
		OldKeyID string `json:"old_key_id,omitempty"`
	}
)
