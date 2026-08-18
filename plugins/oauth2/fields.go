package oauth2

// AccessTokenType defines the format of the issued Access Token.
type AccessTokenType string

const (
	// AccessTokenTypeJWT issues structured and signed JSON Web Tokens per RFC 9068.
	AccessTokenTypeJWT AccessTokenType = "jwt"

	// AccessTokenTypeOpaque issues cryptographically random opaque tokens persisted in storage.
	AccessTokenTypeOpaque AccessTokenType = "opaque"
)

// GrantType represents the authorization grant types defined in OAuth 2.1.
type GrantType string

const (
	// GrantTypeAuthorizationCode represents the authorization code grant type (RFC 6749 / OAuth 2.1).
	GrantTypeAuthorizationCode GrantType = "authorization_code"

	// GrantTypeClientCredentials represents machine-to-machine client credentials grant type.
	GrantTypeClientCredentials GrantType = "client_credentials"

	// GrantTypeRefreshToken represents the refresh token grant type with mandatory rotation.
	GrantTypeRefreshToken GrantType = "refresh_token"
)

// ResponseType represents the authorization endpoint response type.
type ResponseType string

const (
	// ResponseTypeCode represents the authorization code response type ("code").
	ResponseTypeCode ResponseType = "code"
)

// ClientType defines the category of OAuth client.
type ClientType string

const (
	// ClientTypeConfidential represents confidential clients capable of securely storing credentials (e.g. backend servers).
	ClientTypeConfidential ClientType = "confidential"

	// ClientTypePublic represents public clients unable to securely store secrets (e.g. SPAs, mobile apps).
	ClientTypePublic ClientType = "public"
)

// TokenEndpointAuthMethod specifies client authentication methods at the token endpoint.
type TokenEndpointAuthMethod string

const (
	// AuthMethodClientSecretBasic authenticates via HTTP Basic Authorization header.
	AuthMethodClientSecretBasic TokenEndpointAuthMethod = "client_secret_basic"

	// AuthMethodClientSecretPost authenticates via POST body parameters (client_id & client_secret).
	AuthMethodClientSecretPost TokenEndpointAuthMethod = "client_secret_post"

	// AuthMethodNone indicates no client authentication (public clients with PKCE).
	AuthMethodNone TokenEndpointAuthMethod = "none"
)

// SubjectType defines how the subject identifier (sub claim) is generated in OpenID Connect.
type SubjectType string

const (
	// SubjectTypePublic issues the exact same sub identifier across all clients.
	SubjectTypePublic SubjectType = "public"

	// SubjectTypePairwise issues client-specific pseudonymous sub identifiers.
	SubjectTypePairwise SubjectType = "pairwise"
)

// StoreMode defines how secrets, authorization codes, and tokens are stored in the database.
type StoreMode string

const (
	// StoreModePlain stores tokens and secrets in plain text (suitable for local dev/testing).
	StoreModePlain StoreMode = "plain"

	// StoreModeHashed stores tokens and secrets hashed via SHA-256.
	StoreModeHashed StoreMode = "hashed"

	// StoreModeEncrypted stores tokens and secrets encrypted via AES-256-GCM.
	StoreModeEncrypted StoreMode = "encrypted"
)

// Standard OpenID Connect (OIDC Core 1.0) and OAuth 2.1 Scope Constants.
const (
	// ScopeOpenID requests an OpenID Connect ID Token and enables identity workflows.
	ScopeOpenID = "openid"

	// ScopeProfile grants access to the End-User's default Profile Claims (name, picture, etc.).
	ScopeProfile = "profile"

	// ScopeEmail grants access to the email and email_verified claims.
	ScopeEmail = "email"

	// ScopeOffline requests issuance of an OAuth 2.1 Refresh Token (offline_access).
	ScopeOffline = "offline_access"

	// ScopePhone grants access to phone_number and phone_number_verified claims.
	ScopePhone = "phone"

	// ScopeAddress grants access to the address claim.
	ScopeAddress = "address"
)

// Prompt types for OpenID Connect authorization requests.
const (
	// PromptNone instructs the server not to display any authentication or consent UI.
	PromptNone = "none"

	// PromptLogin forces the server to prompt the user for re-authentication.
	PromptLogin = "login"

	// PromptConsent forces the server to prompt the user for consent.
	PromptConsent = "consent"

	// PromptSelectAccount prompts the user to select a user account.
	PromptSelectAccount = "select_account"
)

// CodeChallengeMethod constants for PKCE (RFC 7636).
const (
	// CodeChallengeMethodS256 represents SHA-256 hashed code challenge (mandatory in OAuth 2.1).
	CodeChallengeMethodS256 = "S256"

	// CodeChallengeMethodPlain represents plain text challenge (deprecated and forbidden in OAuth 2.1).
	CodeChallengeMethodPlain = "plain"
)

// Dynamic metadata keys used across Extra map bags and event payloads.
const (
	ExtraKeyClientID         = "oauth2:client_id"
	ExtraKeyClientSecret     = "oauth2:client_secret"
	ExtraKeyUserID           = "oauth2:user_id"
	ExtraKeySessionID        = "oauth2:session_id"
	ExtraKeyScopes           = "oauth2:scopes"
	ExtraKeyRedirectURI      = "oauth2:redirect_uri"
	ExtraKeyCodeChallenge    = "oauth2:code_challenge"
	ExtraKeyNonce            = "oauth2:nonce"
	ExtraKeyResource         = "oauth2:resource"
	ExtraKeyClaims           = "oauth2:claims"
	ExtraKeyAccessToken      = "oauth2:access_token"
	ExtraKeyRefreshToken     = "oauth2:refresh_token"
	ExtraKeyIDToken          = "oauth2:id_token"
	ExtraKeyAuthTime         = "oauth2:auth_time"
	ExtraKeyTokenType        = "oauth2:token_type"
	ExtraKeyFamilyID         = "oauth2:family_id"
	ExtraKeyInteractiveQuery = "oauth2:interactive_query"
)

// ContextKey constants for storing and retrieving OAuth 2.1 objects in plugin.Context.
const (
	ContextKeyOAuthClient       = "oauth2:current_client"
	ContextKeyOAuthToken        = "oauth2:current_token"
	ContextKeyOAuthUser         = "oauth2:current_user"
	ContextKeyOAuthAuthCode     = "oauth2:current_auth_code"
	ContextKeyOAuthRefreshToken = "oauth2:current_refresh_token"
)
