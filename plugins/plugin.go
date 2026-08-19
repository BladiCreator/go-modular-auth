// Package plugins provides convenient factory constructors for instantiating officially supported authentication plugins,
// such as EmailPassword (credential-based sign-in/sign-up) and TwoFactor (RFC 6238 TOTP, backup codes, challenge OTP).
package plugins

import (
	"github.com/BladiCreator/go-modular-auth/plugins/access"
	"github.com/BladiCreator/go-modular-auth/plugins/admin"
	"github.com/BladiCreator/go-modular-auth/plugins/bearer"
	"github.com/BladiCreator/go-modular-auth/plugins/emailotp"
	"github.com/BladiCreator/go-modular-auth/plugins/emailpassword"
	"github.com/BladiCreator/go-modular-auth/plugins/jwt"
	"github.com/BladiCreator/go-modular-auth/plugins/oauth2"
	"github.com/BladiCreator/go-modular-auth/plugins/organization"
	"github.com/BladiCreator/go-modular-auth/plugins/passkey"
	"github.com/BladiCreator/go-modular-auth/plugins/phonenumber"
	"github.com/BladiCreator/go-modular-auth/plugins/twofactor"
)

// EmailPassword instantiates a new EmailPassword authentication plugin configured with the given repository and options.
//
// The EmailPassword plugin handles traditional user registration (sign-up), login authentication (sign-in),
// password changes, forgot/reset password flows, email verification, active password verification, and lifecycle event hooks.
//
// # Configuration Options
//
// You can pass functional options to customize the plugin:
//
//   - emailpassword.WithMinPasswordLength(minLen int): Minimum password length required during registration (default: 8).
//   - emailpassword.WithMaxPasswordLength(maxLen int): Maximum allowed password length (default: 128).
//   - emailpassword.WithRequireEmailVerification(require bool): Require email verification before sign-in (default: false).
//   - emailpassword.WithSendVerificationOnSignUp(send bool): Automatically dispatch verification email on sign-up (default: false).
//   - emailpassword.WithResetTokenExpiry(duration time.Duration): Expiry duration for reset tokens (default: 15 minutes).
//   - emailpassword.WithVerificationTokenExpiry(duration time.Duration): Expiry duration for verification tokens (default: 24 hours).
//   - emailpassword.WithSendResetPasswordEmail(fn SendEmailFunc): Transactional email callback for reset links.
//   - emailpassword.WithSendVerificationEmail(fn SendEmailFunc): Transactional email callback for verification links.
//
// Example:
//
//	epPlugin := plugins.EmailPassword(
//		myRepository,
//		emailpassword.WithMinPasswordLength(10),
//		emailpassword.WithResetTokenExpiry(30 * time.Minute),
//		emailpassword.WithRequireEmailVerification(true),
//	)
func EmailPassword(repo emailpassword.Repository, opts ...emailpassword.Option) *emailpassword.Plugin {
	return emailpassword.New(repo, opts...)
}

// TwoFactor instantiates a new TwoFactor authentication plugin configured with the given repository and options.
//
// The TwoFactor plugin provides Time-based One-Time Password (TOTP / RFC 6238) multi-factor authentication,
// generating secure Base32 secrets, creating otpauth:// URIs for authenticator apps (Google Authenticator, Authy, 1Password),
// verifying 6- or 8-digit TOTP codes, managing single-use backup recovery codes, issuing sign-in challenge tokens,
// authorizing trusted client devices, and dispatching SMS/Email OTP challenges.
//
// # Configuration Options
//
// You can pass functional options to customize the plugin:
//
//   - twofactor.WithIssuer(issuer string): Issuer name shown in authenticator apps (default: "GoModularAuth").
//   - twofactor.WithAlgorithm(alg twofactor.TOTPAlgorithm): Hashing algorithm (SHA1, SHA256, SHA512).
//   - twofactor.WithTOTPOptions(digits int, period int): Number of digits and duration period (default: 6 digits, 30s).
//   - twofactor.WithBackupCodeOptions(amount, length int): Number and length of backup codes (default: 10 codes, 10 chars).
//   - twofactor.WithLockoutProtection(maxAttempts int, duration time.Duration): Rate-limiting brute-force protection.
//   - twofactor.WithTrustDevice(secret string, maxAge time.Duration): Configure authorized trusted devices.
//   - twofactor.WithChallengeExpiry(d time.Duration): Duration for sign-in 2FA challenge tokens (default: 10m).
//   - twofactor.WithSendOTP(fn twofactor.SendOTPFunc): Delivery callback for SMS/Email OTP challenges.
//
// Example:
//
//	tfPlugin := plugins.TwoFactor(
//		myRepository,
//		twofactor.WithIssuer("My Application"),
//		twofactor.WithTOTPOptions(6, 30),
//		twofactor.WithBackupCodeOptions(10, 10),
//		twofactor.WithTrustDevice("my-device-secret", 30*24*time.Hour),
//	)
func TwoFactor(repo twofactor.Repository, opts ...twofactor.Option) *twofactor.Plugin {
	return twofactor.New(repo, opts...)
}

// Bearer instantiates a new Bearer authentication plugin configured with an optional session repository and functional options.
//
// The Bearer plugin handles RFC 7235 compliant Bearer token extraction, HMAC-SHA256 cryptographic signing and verification
// with constant-time comparison, CORS header exposition, and seamless session resolution for API and mobile clients.
//
// # Configuration Options
//
// You can pass functional options to customize the plugin:
//
//   - bearer.WithSecret(secret string): Cryptographic HMAC secret key used for signing and verifying tokens.
//   - bearer.WithRequireSignature(require bool): Enforce that incoming tokens must already have a valid HMAC signature.
//   - bearer.WithTokenHeader(header string): Customize incoming authorization header name (default: "Authorization").
//   - bearer.WithAuthTokenHeader(header string): Customize outgoing token header name (default: "set-auth-token").
//   - bearer.WithExposeHeaders(expose bool): Enable CORS Access-Control-Expose-Headers propagation.
//
// Example:
//
//	bearerPlugin := plugins.Bearer(
//		myRepository,
//		bearer.WithSecret("my-cryptographic-secret-key"),
//		bearer.WithRequireSignature(false),
//	)
func Bearer(repo bearer.Repository, opts ...bearer.Option) *bearer.Plugin {
	return bearer.New(repo, opts...)
}

// JWT instantiates a new JSON Web Token authentication plugin configured with a key repository and functional options.
//
// The JWT plugin provides RFC 7519 JSON Web Token issuance and RFC 7517 JSON Web Key Set (JWKS) key management,
// supporting modern asymmetric cryptographic algorithms (Ed25519/EdDSA, ECDSA ES256/ES512, RSA RS256/PS256),
// AES-256-GCM authenticated encryption for private keys in persistent storage, and automatic key rotation with grace periods.
//
// # Configuration Options
//
// You can pass functional options to customize the plugin:
//
//   - jwt.WithIssuer(issuer string): Issuer identifier ("iss" claim) in generated tokens (default: "GoModularAuth").
//   - jwt.WithAudience(aud ...string): Audience identifiers ("aud" claim) in generated tokens.
//   - jwt.WithExpiration(duration time.Duration): Expiration duration ("exp" claim) for tokens (default: 15 minutes).
//   - jwt.WithAlgorithm(alg jwt.Algorithm): Asymmetric signing algorithm (default: jwt.AlgEdDSA / Ed25519).
//   - jwt.WithSecret(secret string): Symmetric encryption secret used to protect private keys via AES-256-GCM.
//   - jwt.WithGracePeriod(grace time.Duration): Grace period for keeping expired keys in public JWKS (default: 30 days).
//   - jwt.WithDefinePayload(fn jwt.PayloadFunc): Callback to inject custom claims based on session and user.
//   - jwt.WithGetSubject(fn jwt.SubjectFunc): Callback to resolve the subject ("sub") claim.
//
// Example:
//
//	jwtPlugin := plugins.JWT(
//		myJWKRepository,
//		jwt.WithIssuer("https://auth.example.com"),
//		jwt.WithSecret("my-aes-encryption-secret-32b"),
//		jwt.WithAlgorithm(jwt.AlgEdDSA),
//		jwt.WithExpiration(30 * time.Minute),
//	)
func JWT(repo jwt.Repository, opts ...jwt.Option) *jwt.Plugin {
	return jwt.New(repo, opts...)
}

// Organization instantiates a new Organization multi-tenancy plugin configured with a repository and options.
//
// The Organization plugin provides multi-tenancy, organization lifecycle management, member and role management,
// static and dynamic Role-Based Access Control (RBAC), team hierarchies (Teams), and full invitation workflows.
//
// # Configuration Options
//
// You can pass functional options to customize the plugin:
//
//   - organization.WithCreatorRole(role string): Role assigned to the organization creator (default: "owner").
//   - organization.WithInvitationExpiresIn(duration time.Duration): Duration for invitation expiry (default: 48h).
//   - organization.WithMembershipLimit(limit int): Max members per organization.
//   - organization.WithOrganizationLimit(limit int): Max organizations created per user.
//   - organization.WithTeams(enabled, defaultTeam, allowRemovingAll bool): Configure teams sub-module.
//   - organization.WithDynamicAccessControl(enabled bool): Enable database-persisted dynamic roles.
//   - organization.WithCustomRoles(roles map[string]Permissions): Define custom static roles.
//   - organization.WithSendInvitationEmail(fn SendInvitationEmailFunc): Email delivery callback.
//
// Example:
//
//	orgPlugin := plugins.Organization(
//		myOrgRepository,
//		organization.WithTeams(true, true, false),
//		organization.WithDynamicAccessControl(true),
//		organization.WithInvitationExpiresIn(72 * time.Hour),
//	)
func Organization(repo organization.Repository, opts ...organization.Option) *organization.Plugin {
	return organization.New(repo, opts...)
}

// Admin instantiates a new Admin governance plugin configured with a repository and options.
//
// The Admin plugin provides role-based access control (RBAC), user moderation (ban/unban with automatic expiry),
// CRUD operations on users, password administration, active session management and revocation, and user impersonation.
//
// # Configuration Options
//
// You can pass functional options to customize the plugin:
//
//   - admin.WithDefaultRole(role string): Default role for new users (default: "user").
//   - admin.WithAdminRoles(roles ...string): Roles recognized with administrator privileges (default: ["admin"]).
//   - admin.WithAdminUserIDs(userIDs ...string): Explicit user IDs granted unrestricted administrator access.
//   - admin.WithDefaultBanReason(reason string): Fallback reason for account suspensions.
//   - admin.WithDefaultBanExpiresIn(duration time.Duration): Default duration for temporary account suspensions (0 = permanent).
//   - admin.WithImpersonationSessionDuration(duration time.Duration): Duration for masquerade sessions (default: 1h).
//   - admin.WithBannedUserMessage(msg string): User-facing error message for suspended users.
//   - admin.WithAllowImpersonatingAdmins(allow bool): Allow administrators to masquerade as other administrators.
//   - admin.WithPasswordLength(min, max int): Minimum and maximum allowed password lengths for administrative updates.
//   - admin.WithCustomRoles(roles map[string]admin.Role): Configure custom static RBAC roles and statements.
//   - admin.WithRole(role admin.Role): Register or override an individual role definition.
//
// Example:
//
//	adminPlugin := plugins.Admin(
//		myAdminRepository,
//		admin.WithAdminRoles("admin", "superadmin"),
//		admin.WithImpersonationSessionDuration(2 * time.Hour),
//		admin.WithPasswordLength(8, 64),
//	)
func Admin(repo admin.Repository, opts ...admin.Option) *admin.Plugin {
	return admin.New(repo, opts...)
}

// Passkey instantiates a new Passkey (WebAuthn / FIDO2 / Passwordless) authentication plugin configured with a repository and options.
//
// The Passkey plugin provides biometric and security key passwordless authentication, resident keys (discoverable credentials / conditional UI),
// AAGUID authenticator metadata lookup, replay and cloning protection via monotonic signature counters, and full lifecycle event dispatching.
//
// # Configuration Options
//
// You can pass functional options to customize the plugin:
//
//   - passkey.WithRPDisplayName(name string): Relying Party human-readable name (default: "GoModularAuth").
//   - passkey.WithRPID(rpID string): Relying Party domain identifier (default: "localhost").
//   - passkey.WithRPOrigins(origins ...string): Allowed origin URLs (e.g. "http://localhost:3000").
//   - passkey.WithChallengeTimeout(d time.Duration): Expiry duration for ephemeral challenges (default: 5m).
//   - passkey.WithRequireSessionOnRegistration(require bool): Enforce active user session during registration (default: true).
//   - passkey.WithUserVerification(uv protocol.UserVerificationRequirement): Verification requirement (discouraged, preferred, required).
//   - passkey.WithResidentKey(rk protocol.ResidentKeyRequirement): Resident key requirement (discouraged, preferred, required).
//   - passkey.WithAttestation(att protocol.ConveyancePreference): Attestation conveyance (none, indirect, direct, enterprise).
//   - passkey.WithAuthenticatorAttachment(att protocol.AuthenticatorAttachment): Restrict attachment (platform, cross-platform).
//   - passkey.WithSessionDuration(d time.Duration): Duration for created user sessions (default: 7 days).
//   - passkey.WithResolveUser(fn passkey.ResolveUserFunc): User resolution callback when registration occurs without an active session.
//   - passkey.WithAfterRegistration(hook passkey.AfterRegistrationHook): Lifecycle callback executed after successful registration.
//   - passkey.WithAfterAuthentication(hook passkey.AfterAuthenticationHook): Lifecycle callback executed after successful authentication.
//
// Example:
//
//	passkeyPlugin := plugins.Passkey(
//		myPasskeyRepository,
//		passkey.WithRPDisplayName("Acme Corp"),
//		passkey.WithRPID("auth.acme.com"),
//		passkey.WithRPOrigins("https://auth.acme.com", "https://app.acme.com"),
//	)
func Passkey(repo passkey.Repository, opts ...passkey.Option) *passkey.Plugin {
	return passkey.New(repo, opts...)
}

// EmailOTP instantiates a new Email OTP authentication plugin configured with a repository and functional options.
//
// The EmailOTP plugin handles passwordless authentication (sign-in and automatic sign-up), email address verification,
// secure password reset flows, and verified email change requests via cryptographically secure one-time numeric passwords.
//
// # Configuration Options
//
// You can pass functional options to customize the plugin:
//
//   - emailotp.WithSendVerificationOTP(fn SendVerificationOTPFunc): Required delivery callback to send emails.
//   - emailotp.WithOTPLength(length int): Number of numeric digits for generated OTPs (default: 6).
//   - emailotp.WithExpiresIn(d time.Duration): Expiration lifetime of generated OTPs (default: 5m).
//   - emailotp.WithAllowedAttempts(attempts int): Max incorrect verification attempts before invalidation (default: 3).
//   - emailotp.WithStoreOTP(mode StoreOTPMode, secretKey ...string): Storage mode ("plain", "hashed", "encrypted").
//   - emailotp.WithResendStrategy(strategy ResendStrategy): Resend policy ("rotate" or "reuse", default: "rotate").
//   - emailotp.WithDisableSignUp(disable bool): Prevent auto-creating new users on sign-in (default: false).
//   - emailotp.WithAutoSignInAfterVerification(auto bool): Automatically create session upon email verification (default: true).
//   - emailotp.WithRevokeSessionsOnPasswordReset(revoke bool): Invalidate all active sessions on password reset (default: true).
//   - emailotp.WithChangeEmail(enabled, verifyCurrent bool): Configure email change flow parameters.
//
// Example:
//
//	otpPlugin := plugins.EmailOTP(
//		myRepository,
//		emailotp.WithSendVerificationOTP(func(ctx context.Context, data emailotp.SendEmailData) error {
//			return mailer.Send(data.Email, "Your OTP Code", data.OTP)
//		}),
//		emailotp.WithStoreOTP(emailotp.StoreOTPHashed),
//		emailotp.WithAllowedAttempts(3),
//	)
func EmailOTP(repo emailotp.Repository, opts ...emailotp.Option) *emailotp.Plugin {
	return emailotp.New(repo, opts...)
}

// PhoneNumber instantiates a new Phone Number (SMS OTP) authentication plugin configured with a repository and options.
//
// The PhoneNumber plugin handles passwordless SMS OTP authentication, phone number verification and updates,
// credentialed phone + password sign-in, secure password resets via SMS, attempt budgeting, and anti-replay protection.
//
// # Configuration Options
//
// You can pass functional options to customize the plugin:
//
//   - phonenumber.WithSendOTP(fn SendOTPFunc): Required delivery callback to dispatch SMS messages.
//   - phonenumber.WithVerifyOTP(fn VerifyOTPFunc): Optional delegated verification callback (e.g. Twilio Verify).
//   - phonenumber.WithSendPasswordResetOTP(fn SendOTPFunc): Optional dedicated callback for password reset SMS OTPs.
//   - phonenumber.WithOTPLength(length int): Number of numeric digits for generated OTPs (default: 6).
//   - phonenumber.WithExpiresIn(d time.Duration): Expiration lifetime of generated OTPs (default: 5m).
//   - phonenumber.WithAllowedAttempts(attempts int): Max incorrect verification attempts before invalidation (default: 3).
//   - phonenumber.WithStoreOTP(mode StoreOTPMode, secretKey ...string): Storage mode ("plain", "hashed", "encrypted").
//   - phonenumber.WithResendStrategy(strategy ResendStrategy): Resend policy ("rotate" or "reuse", default: "rotate").
//   - phonenumber.WithRequireVerification(require bool): Enforce verified phone before password login (default: false).
//   - phonenumber.WithDisableSignUp(disable bool): Prevent auto-creating new users on verification (default: false).
//   - phonenumber.WithRevokeSessionsOnPasswordReset(revoke bool): Invalidate all active sessions on password reset (default: true).
//   - phonenumber.WithPhoneNumberValidator(fn PhoneNumberValidatorFunc): Custom validator for phone number formats (e.g. E.164).
//   - phonenumber.WithSignUpOnVerification(cfg SignUpOnVerificationConfig): Custom temporary email/name generators for auto-signup.
//   - phonenumber.WithCallbackOnVerification(fn CallbackOnVerificationFunc): Hook executed after phone verification.
//   - phonenumber.WithOnPasswordReset(fn OnPasswordResetFunc): Hook executed after password reset confirmation.
//
// Example:
//
//	phonePlugin := plugins.PhoneNumber(
//		myRepository,
//		phonenumber.WithSendOTP(func(ctx context.Context, data phonenumber.SendOTPData) error {
//			return smsClient.SendSMS(data.PhoneNumber, "Your code is: " + data.Code)
//		}),
//		phonenumber.WithStoreOTP(phonenumber.StoreOTPHashed),
//		phonenumber.WithAllowedAttempts(3),
//	)
func PhoneNumber(repo phonenumber.Repository, opts ...phonenumber.Option) *phonenumber.Plugin {
	return phonenumber.New(repo, opts...)
}

// OAuth2 instantiates a new OAuth 2.1 & OpenID Connect Provider authentication plugin.
//
// The OAuth2 plugin provides full compliance with OAuth 2.1 (mandatory PKCE S256, single-use atomic code exchange,
// RFC 9207 issuer identification, refresh token rotation with family revocation) and OpenID Connect Core 1.0
// (ID Token issuance with at_hash/c_hash, UserInfo endpoint, RP-Initiated Logout, Dynamic Client Registration,
// and Discovery Metadata).
//
// # Configuration Options
//
// You can pass functional options to customize the plugin:
//
//   - oauth2.WithIssuer(issuer string): Authorization server base URL ("iss" claim).
//   - oauth2.WithAccessTokenType(t oauth2.AccessTokenType): Issue RFC 9068 JWT or opaque access tokens.
//   - oauth2.WithJWTSigner(signer oauth2.JWTSigner): Custom JWT signer (compatible with plugins/jwt or RSA/EdDSA).
//   - oauth2.WithPages(loginPage, consentPage string): Interactive UI redirect paths.
//   - oauth2.WithScopes(scopes ...string): Supported OAuth/OIDC scopes.
//   - oauth2.WithGrantTypes(types ...oauth2.GrantType): Enabled grant types.
//   - oauth2.WithTokenExpirations(code, access, refresh, idToken time.Duration): Token validity lifetimes.
//   - oauth2.WithStoreModes(secretMode, tokenMode oauth2.StoreMode, secretKey string): Persistence security modes.
//   - oauth2.WithPairwiseSecret(secret string): Secret salt for pairwise pseudonymous sub derivation.
//   - oauth2.WithDynamicClientRegistration(allow, allowUnauthenticated bool): RFC 7591 client registration.
//   - oauth2.WithCustomAccessTokenClaims(fn oauth2.CustomClaimsFunc): Application-specific JWT access token claims.
//   - oauth2.WithCustomIDTokenClaims(fn oauth2.CustomClaimsFunc): Application-specific OIDC ID token claims.
//   - oauth2.WithCustomUserInfoClaims(fn oauth2.CustomClaimsFunc): Application-specific UserInfo claims.
//
// Example:
//
//	oauthPlugin := plugins.OAuth2(
//		myOAuthRepository,
//		oauth2.WithIssuer("https://auth.example.com"),
//		oauth2.WithAccessTokenType(oauth2.AccessTokenTypeJWT),
//		oauth2.WithPages("/sign-in", "/consent"),
//	)
func OAuth2(repo oauth2.Repository, opts ...oauth2.Option) *oauth2.Plugin {
	return oauth2.New(repo, opts...)
}

// Access instantiates a new Access Control (Granular Permissions & RBAC/ABAC) plugin configured with master statements and options.
//
// The Access plugin provides sub-microsecond in-memory permission evaluation, boolean logic combinators (AND/OR),
// wildcard matching ('*'), multi-role subject aggregation, dynamic role inheritance (Extend/Merge), thread-safe runtime
// role registration, JSON persistence serialization, and execution guards for HTTP/gRPC middlewares.
//
// # Configuration Options
//
// You can pass functional options to customize the plugin:
//
//   - access.WithMasterStatements(stmts access.Statements): Define the global master schema of valid resources and permitted actions.
//   - access.WithInitialRoles(roles map[string]access.Statements): Pre-register initial static or dynamic roles on startup.
//   - access.WithAllowWildcards(allow bool): Enable or disable wildcard ('*') matching for resources and actions (default: true).
//   - access.WithStrictResources(strict bool): Enforce that registered roles must strictly match MasterStatements (default: false).
//
// Example:
//
//	statement := access.Statements{
//		"project": {"create", "read", "update", "delete"},
//		"user":    {"create", "read", "update", "delete"},
//	}
//
//	accessPlugin := plugins.Access(
//		statement,
//		access.WithInitialRoles(map[string]access.Statements{
//			"admin": {"*": {"*"}},
//			"user":  {"project": {"read"}, "user": {"read"}},
//		}),
//	)
func Access(masterStatements access.Statements, opts ...access.Option) *access.Plugin {
	return access.New(masterStatements, opts...)
}


