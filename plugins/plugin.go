// Package plugins provides convenient factory constructors for instantiating officially supported authentication plugins,
// such as EmailPassword (credential-based sign-in/sign-up) and TwoFactor (RFC 6238 TOTP, backup codes, challenge OTP).
package plugins

import (
	"github.com/BladiCreator/go-modular-auth/plugins/access"
	"github.com/BladiCreator/go-modular-auth/plugins/admin"
	"github.com/BladiCreator/go-modular-auth/plugins/anonymous"
	"github.com/BladiCreator/go-modular-auth/plugins/apikey"
	"github.com/BladiCreator/go-modular-auth/plugins/bearer"
	"github.com/BladiCreator/go-modular-auth/plugins/captcha"
	"github.com/BladiCreator/go-modular-auth/plugins/deviceauth"
	"github.com/BladiCreator/go-modular-auth/plugins/emailotp"
	"github.com/BladiCreator/go-modular-auth/plugins/emailpassword"
	"github.com/BladiCreator/go-modular-auth/plugins/genericoauth"
	"github.com/BladiCreator/go-modular-auth/plugins/jwt"
	"github.com/BladiCreator/go-modular-auth/plugins/lastloginmethod"
	"github.com/BladiCreator/go-modular-auth/plugins/magiclink"
	"github.com/BladiCreator/go-modular-auth/plugins/multisession"
	"github.com/BladiCreator/go-modular-auth/plugins/oauth2"
	"github.com/BladiCreator/go-modular-auth/plugins/oauthproxy"
	"github.com/BladiCreator/go-modular-auth/plugins/oidcprovider"
	"github.com/BladiCreator/go-modular-auth/plugins/organization"
	"github.com/BladiCreator/go-modular-auth/plugins/ott"
	"github.com/BladiCreator/go-modular-auth/plugins/passkey"
	"github.com/BladiCreator/go-modular-auth/plugins/phonenumber"
	"github.com/BladiCreator/go-modular-auth/plugins/polar"
	"github.com/BladiCreator/go-modular-auth/plugins/stripe"
	"github.com/BladiCreator/go-modular-auth/plugins/twofactor"
	"github.com/BladiCreator/go-modular-auth/plugins/username"
)

// EmailPassword instantiates a new EmailPassword authentication plugin configured with the given repository and options.
//
// The EmailPassword plugin handles traditional user registration (sign-up), login authentication (sign-in),
// password changes, forgot/reset password flows, email verification, active password verification, and lifecycle event hooks.
//
// # Available Methods
//
//   - SignUp(ctx context.Context, input dto.SignUpParams) (*entity.User, error): Register a new user with email and password.
//   - SignIn(ctx context.Context, input dto.SignInParams) (*entity.User, error): Authenticate an existing user with email and password credentials.
//   - ChangePassword(ctx context.Context, input dto.ChangePasswordParams) error: Update the password for an authenticated user.
//   - ForgotPassword(ctx context.Context, input dto.ForgotPasswordParams) (*entity.VerificationToken, error): Generate a secure password reset token and dispatch email.
//   - ResetPassword(ctx context.Context, input dto.ResetPasswordParams) error: Reset a user password using a valid reset token.
//   - SendVerificationEmail(ctx context.Context, input dto.SendVerificationEmailParams) (*entity.VerificationToken, error): Issue and send an email verification token.
//   - VerifyEmail(ctx context.Context, input dto.VerifyEmailParams) (*entity.User, error): Confirm user email address using a verification token.
//   - VerifyPassword(ctx context.Context, input dto.VerifyPasswordParams) (bool, error): Verify if a given plaintext password matches user hash.
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
//	ctx := context.Background()
//	storage := memory.New()
//	app, err := auth.New(
//		config.WithPlugins(
//			plugins.EmailPassword(storage, emailpassword.WithMinPasswordLength(8)),
//		),
//	)
//	if err != nil {
//		panic(err)
//	}
//
//	user, err := auth.Plugin[emailpassword.Plugin](app).SignUp(ctx, dto.SignUpParams{
//		Name:     "Gopher Go",
//		Email:    "gopher@golang.org",
//		Password: "SecurePassword123!",
//	})
//	if err != nil {
//		panic(err)
//	}
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
// # Available Methods
//
//   - Enable(ctx context.Context, params EnableParams) (*EnableResult, error): Initialize 2FA enrollment, generating secret, TOTP URI, and backup codes.
//   - Disable(ctx context.Context, params DisableParams) error: Deactivate two-factor authentication for a user.
//   - GetTOTPURI(ctx context.Context, params GetTOTPURIParams) (string, error): Retrieve otpauth:// URI for an enrolled user.
//   - VerifyTOTP(ctx context.Context, params VerifyTOTPParams) (*VerifyResult, error): Validate a time-based 6-digit TOTP code.
//   - VerifyBackupCode(ctx context.Context, params VerifyBackupCodeParams) (*VerifyResult, error): Consume and validate a single-use backup recovery code.
//   - GenerateBackupCodes(ctx context.Context, params GenerateBackupCodesParams) (*BackupCodesResult, error): Regenerate a fresh set of recovery backup codes.
//   - ViewBackupCodes(ctx context.Context, params ViewBackupCodesParams) (*BackupCodesResult, error): View active unconsumed backup codes.
//   - SendOTP(ctx context.Context, params SendOTPParams) (*SendOTPResult, error): Dispatch SMS/Email OTP code for 2FA verification.
//   - VerifyOTP(ctx context.Context, params VerifyOTPParams) (*VerifyResult, error): Verify an SMS/Email OTP challenge code.
//   - CreateChallenge(ctx context.Context, params CreateChallengeParams) (*ChallengeResult, error): Create a temporary sign-in challenge token.
//   - VerifyChallenge(ctx context.Context, params VerifyChallengeParams) (*VerifyResult, error): Complete authentication by verifying challenge token and 2FA code.
//   - TrustDevice(ctx context.Context, params TrustDeviceParams) (*TrustDeviceResult, error): Authorize and issue a trusted client device cookie/token.
//   - VerifyTrustDevice(ctx context.Context, params VerifyTrustDeviceParams) (bool, error): Check if a client device token is valid and trusted.
//   - RevokeTrustedDevice(ctx context.Context, params RevokeTrustedDeviceParams) error: Revoke authorization for a specific trusted device.
//   - RevokeAllTrustedDevices(ctx context.Context, userID string) error: Invalidate all trusted devices for a user.
//   - GenerateTOTPSecret(ctx context.Context, userID string) (string, error): Generate a raw Base32 TOTP secret.
//   - VerifyCode(ctx context.Context, userID, code string) (bool, error): Simple validation helper for TOTP or backup codes.
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
//	ctx := context.Background()
//	storage := memory.New()
//	app, err := auth.New(
//		config.WithPlugins(
//			plugins.TwoFactor(
//				storage,
//				twofactor.WithIssuer("GoModularAuth"),
//				twofactor.WithTOTPOptions(6, 30),
//			),
//		),
//	)
//	if err != nil {
//		panic(err)
//	}
//
//	res, err := auth.Plugin[twofactor.Plugin](app).Enable(ctx, twofactor.EnableParams{
//		UserID: "usr_123",
//	})
//	if err != nil {
//		panic(err)
//	}
func TwoFactor(repo twofactor.Repository, opts ...twofactor.Option) *twofactor.Plugin {
	return twofactor.New(repo, opts...)
}

// Bearer instantiates a new Bearer authentication plugin configured with an optional session repository and functional options.
//
// The Bearer plugin handles RFC 7235 compliant Bearer token extraction, HMAC-SHA256 cryptographic signing and verification
// with constant-time comparison, CORS header exposition, and seamless session resolution for API and mobile clients.
//
// # Available Methods
//
//   - Verify(ctx context.Context, params VerifyParams) (*VerifyResult, error): Cryptographically verify and parse an incoming Bearer token.
//   - CreateToken(ctx context.Context, params CreateTokenParams) (*CreateTokenResult, error): Generate and sign an HMAC-SHA256 authenticated Bearer token.
//   - ResolveSession(ctx context.Context, params ResolveSessionParams) (*ResolveSessionResult, error): Extract token, verify HMAC signature, and retrieve database session.
//   - ExtractToken(headerValue string) (string, error): Parse raw token from an HTTP Authorization header ("Bearer <token>").
//   - FormatHeader(token string) string: Format a token into standard "Bearer <token>" header value.
//   - FormatAuthTokenHeader(token string) (headerName, headerValue string): Generate "set-auth-token" response header.
//   - ExposedHeaders() string: Return CORS headers to expose to browsers ("set-auth-token").
//   - Authenticate() func(next http.Handler) http.Handler: Net/HTTP middleware for authenticating Bearer token request headers.
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
//	ctx := context.Background()
//	storage := memory.New()
//	app, err := auth.New(
//		config.WithPlugins(
//			plugins.Bearer(
//				storage,
//				bearer.WithSecret("my-cryptographic-secret-key"),
//			),
//		),
//	)
//	if err != nil {
//		panic(err)
//	}
//
//	tokenRes, err := auth.Plugin[bearer.Plugin](app).CreateToken(ctx, bearer.CreateTokenParams{
//		Token:  "session_token_xyz",
//		UserID: "usr_123",
//	})
//	if err != nil {
//		panic(err)
//	}
func Bearer(repo bearer.Repository, opts ...bearer.Option) *bearer.Plugin {
	return bearer.New(repo, opts...)
}

// JWT instantiates a new JSON Web Token authentication plugin configured with a key repository and functional options.
//
// The JWT plugin provides RFC 7519 JSON Web Token issuance and RFC 7517 JSON Web Key Set (JWKS) key management,
// supporting modern asymmetric cryptographic algorithms (Ed25519/EdDSA, ECDSA ES256/ES512, RSA RS256/PS256),
// AES-256-GCM authenticated encryption for private keys in persistent storage, and automatic key rotation with grace periods.
//
// # Available Methods
//
//   - Sign(ctx context.Context, params SignParams) (*SignResult, error): Construct and sign an RFC 7519 compact JWT token with active signing key.
//   - Verify(ctx context.Context, params VerifyParams) (*VerifyResult, error): Verify cryptographic signature and claims (iss, aud, exp, nbf) of a JWT.
//   - GetJWKS(ctx context.Context, params GetJWKSParams) (*GetJWKSResult, error): Serve RFC 7517 JSON Web Key Set containing active and valid grace-period public keys.
//   - GetToken(ctx context.Context, params GetTokenParams) (*GetTokenResult, error): Issue a signed JWT for an authenticated user session.
//   - RotateKeys(ctx context.Context, params RotateKeysParams) (*RotateKeysResult, error): Perform on-demand cryptographic key rotation, generating new active key pair.
//   - Authenticate() func(next http.Handler) http.Handler: Net/HTTP middleware for authenticating JWT tokens from incoming Authorization headers.
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
//	ctx := context.Background()
//	storage := memory.New()
//	app, err := auth.New(
//		config.WithPlugins(
//			plugins.JWT(
//				storage,
//				jwt.WithIssuer("https://auth.example.com"),
//				jwt.WithSecret("my-aes-encryption-secret-32b"),
//			),
//		),
//	)
//	if err != nil {
//		panic(err)
//	}
//
//	jwtRes, err := auth.Plugin[jwt.Plugin](app).Sign(ctx, jwt.SignParams{
//		Subject: "usr_123",
//		Payload: map[string]any{"role": "admin"},
//	})
//	if err != nil {
//		panic(err)
//	}
func JWT(repo jwt.Repository, opts ...jwt.Option) *jwt.Plugin {
	return jwt.New(repo, opts...)
}

// Organization instantiates a new Organization multi-tenancy plugin configured with a repository and options.
//
// The Organization plugin provides multi-tenancy, organization lifecycle management, member and role management,
// static and dynamic Role-Based Access Control (RBAC), team hierarchies (Teams), and full invitation workflows.
//
// # Available Methods
//
//   - Organization Lifecycle:
//     - CreateOrganization(ctx context.Context, params CreateOrganizationParams) (*CreateOrganizationResult, error): Create a new organization entity and assign creator role.
//     - GetOrganization(ctx context.Context, params GetOrganizationParams) (*GetOrganizationResult, error): Retrieve organization details by ID.
//     - GetOrganizationBySlug(ctx context.Context, params GetOrganizationBySlugParams) (*GetOrganizationBySlugResult, error): Retrieve organization details by URL slug.
//     - GetFullOrganization(ctx context.Context, params GetFullOrganizationParams) (*GetFullOrganizationResult, error): Fetch organization alongside its members, teams, and invitations.
//     - UpdateOrganization(ctx context.Context, params UpdateOrganizationParams) (*UpdateOrganizationResult, error): Update organization metadata (name, slug, logo, metadata).
//     - DeleteOrganization(ctx context.Context, params DeleteOrganizationParams) (*DeleteOrganizationResult, error): Permanently delete an organization and cascade delete child records.
//     - ListOrganizations(ctx context.Context, params ListOrganizationsParams) (*ListOrganizationsResult, error): List all organizations where a user is an active member.
//     - CheckSlug(ctx context.Context, params CheckSlugParams) (*CheckSlugResult, error): Validate slug availability and format.
//     - SetActiveOrganization(ctx context.Context, params SetActiveOrganizationParams) (*SetActiveOrganizationResult, error): Switch the active organization context on a session.
//     - GetActiveOrganization(ctx context.Context, params GetActiveOrganizationParams) (*GetActiveOrganizationResult, error): Retrieve the currently active organization for a session.
//
//   - Member Management:
//     - AddMember(ctx context.Context, params AddMemberParams) (*AddMemberResult, error): Directly add a user to an organization with a specific role.
//     - GetMember(ctx context.Context, params GetMemberParams) (*GetMemberResult, error): Retrieve membership record for a user in an organization.
//     - GetActiveMember(ctx context.Context, params GetActiveMemberParams) (*GetActiveMemberResult, error): Retrieve active membership details from the current session.
//     - GetActiveMemberRole(ctx context.Context, params GetActiveMemberRoleParams) (*GetActiveMemberRoleResult, error): Retrieve active member's assigned role.
//     - UpdateMemberRole(ctx context.Context, params UpdateMemberRoleParams) (*UpdateMemberRoleResult, error): Modify a member's role within an organization.
//     - RemoveMember(ctx context.Context, params RemoveMemberParams) (*RemoveMemberResult, error): Remove a user from an organization.
//     - LeaveOrganization(ctx context.Context, params LeaveOrganizationParams) (*LeaveOrganizationResult, error): Allow a member to voluntarily depart an organization.
//     - ListMembers(ctx context.Context, params ListMembersParams) (*ListMembersResult, error): List all members with pagination.
//
//   - Invitation Workflows:
//     - CreateInvitation(ctx context.Context, params CreateInvitationParams) (*CreateInvitationResult, error): Issue an email invitation with secure token.
//     - GetInvitation(ctx context.Context, params GetInvitationParams) (*GetInvitationResult, error): Retrieve invitation details by ID or token.
//     - AcceptInvitation(ctx context.Context, params AcceptInvitationParams) (*AcceptInvitationResult, error): Accept an invitation and join organization.
//     - RejectInvitation(ctx context.Context, params RejectInvitationParams) (*RejectInvitationResult, error): Decline an incoming organization invitation.
//     - CancelInvitation(ctx context.Context, params CancelInvitationParams) (*CancelInvitationResult, error): Revoke a pending invitation.
//     - ListInvitations(ctx context.Context, params ListInvitationsParams) (*ListInvitationsResult, error): List pending invitations for an organization.
//     - ListUserInvitations(ctx context.Context, params ListUserInvitationsParams) (*ListUserInvitationsResult, error): List all pending invitations addressed to a user.
//
//   - Teams:
//     - CreateTeam(ctx context.Context, params CreateTeamParams) (*CreateTeamResult, error): Create a team sub-unit within an organization.
//     - GetTeam(ctx context.Context, params GetTeamParams) (*GetTeamResult, error): Retrieve team details.
//     - UpdateTeam(ctx context.Context, params UpdateTeamParams) (*UpdateTeamResult, error): Modify team name or metadata.
//     - DeleteTeam(ctx context.Context, params DeleteTeamParams) (*DeleteTeamResult, error): Delete a team.
//     - ListTeams(ctx context.Context, params ListTeamsParams) (*ListTeamsResult, error): List all teams in an organization.
//     - AddTeamMember(ctx context.Context, params AddTeamMemberParams) (*AddTeamMemberResult, error): Assign an organization member to a team.
//     - RemoveTeamMember(ctx context.Context, params RemoveTeamMemberParams) (*RemoveTeamMemberResult, error): Remove a member from a team.
//     - ListTeamMembers(ctx context.Context, params ListTeamMembersParams) (*ListTeamMembersResult, error): List all members assigned to a team.
//     - SetActiveTeam(ctx context.Context, params SetActiveTeamParams) (*SetActiveTeamResult, error): Set active team on session.
//     - GetActiveTeam(ctx context.Context, params GetActiveTeamParams) (*GetActiveTeamResult, error): Get active team from session.
//
//   - Dynamic Roles & RBAC:
//     - CreateRole(ctx context.Context, params CreateRoleParams) (*CreateRoleResult, error): Provision a dynamic database-persisted custom role.
//     - GetRole(ctx context.Context, params GetRoleParams) (*GetRoleResult, error): Retrieve dynamic role permissions.
//     - UpdateRole(ctx context.Context, params UpdateRoleParams) (*UpdateRoleResult, error): Modify dynamic role permissions.
//     - DeleteRole(ctx context.Context, params DeleteRoleParams) (*DeleteRoleResult, error): Delete a dynamic role.
//     - ListRoles(ctx context.Context, params ListRolesParams) (*ListRolesResult, error): List all dynamic and static roles for an organization.
//     - HasPermission(ctx context.Context, params HasPermissionParams) (*HasPermissionResult, error): Check if a role satisfies specific permissions.
//     - CheckPermission(ctx context.Context, orgID, userRole string, required Permissions) (bool, error): Evaluate RBAC permissions.
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
//	ctx := context.Background()
//	storage := memory.New()
//	app, err := auth.New(
//		config.WithPlugins(
//			plugins.Organization(
//				storage,
//				organization.WithCreatorRole("owner"),
//			),
//		),
//	)
//	if err != nil {
//		panic(err)
//	}
//
//	orgRes, err := auth.Plugin[organization.Plugin](app).CreateOrganization(ctx, organization.CreateOrganizationParams{
//		Name:   "Acme Corp",
//		Slug:   "acme",
//		UserID: "usr_123",
//	})
//	if err != nil {
//		panic(err)
//	}
func Organization(repo organization.Repository, opts ...organization.Option) *organization.Plugin {
	return organization.New(repo, opts...)
}

// Admin instantiates a new Admin governance plugin configured with a repository and options.
//
// The Admin plugin provides role-based access control (RBAC), user moderation (ban/unban with automatic expiry),
// CRUD operations on users, password administration, active session management and revocation, and user impersonation.
//
// # Available Methods
//
//   - User Administration:
//     - CreateUser(ctx context.Context, params CreateUserParams) (*entity.User, error): Provision a new user account with assigned role and credentials.
//     - GetUser(ctx context.Context, params GetUserParams) (*entity.User, error): Retrieve comprehensive user profile details.
//     - ListUsers(ctx context.Context, params ListUsersParams) (*ListUsersResult, error): Paginated search and filtering of users by role, ban status, email, or creation date.
//     - UpdateUser(ctx context.Context, params UpdateUserParams) (*entity.User, error): Update user profile, email, name, image, or metadata.
//     - RemoveUser(ctx context.Context, params RemoveUserParams) error: Permanently delete a user account and associated credentials.
//     - SetRole(ctx context.Context, params SetRoleParams) (*entity.User, error): Update administrative RBAC role assigned to a user.
//     - SetUserPassword(ctx context.Context, params SetUserPasswordParams) error: Directly set/override a user's password.
//
//   - Moderation & Ban:
//     - BanUser(ctx context.Context, params BanUserParams) (*entity.User, error): Suspend a user account with optional reason and expiry duration.
//     - UnbanUser(ctx context.Context, params UnbanUserParams) (*entity.User, error): Reinstate a suspended user account.
//     - CheckUserBanStatus(ctx context.Context, user *entity.User) error: Validate if user account is currently banned or expired.
//
//   - Impersonation:
//     - ImpersonateUser(ctx context.Context, params ImpersonateUserParams) (*ImpersonateResult, error): Issue a masquerade session to act on behalf of another user.
//     - StopImpersonating(ctx context.Context, params StopImpersonatingParams) (*StopImpersonatingResult, error): Terminate masquerade session and restore original admin session.
//
//   - Session Governance:
//     - ListUserSessions(ctx context.Context, params ListUserSessionsParams) ([]*entity.Session, error): Retrieve all active sessions for a user.
//     - RevokeUserSession(ctx context.Context, params RevokeUserSessionParams) error: Terminate a specific user session.
//     - RevokeUserSessions(ctx context.Context, params RevokeUserSessionsParams) error: Invalidate all active sessions for a user.
//
//   - RBAC Evaluation:
//     - CheckPermission(ctx context.Context, params CheckPermissionParams) (bool, error): Evaluate whether caller role possesses required administrative permissions.
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
//	ctx := context.Background()
//	storage := memory.New()
//	app, err := auth.New(
//		config.WithPlugins(
//			plugins.Admin(
//				storage,
//				admin.WithAdminRoles("admin", "superadmin"),
//			),
//		),
//	)
//	if err != nil {
//		panic(err)
//	}
//
//	userRes, err := auth.Plugin[admin.Plugin](app).CreateUser(ctx, admin.CreateUserParams{
//		Caller:   admin.CallerContext{Role: "admin"},
//		Name:     "Jane Doe",
//		Email:    "jane@example.com",
//		Password: "SecurePassword123!",
//		Role:     "user",
//	})
//	if err != nil {
//		panic(err)
//	}
func Admin(repo admin.Repository, opts ...admin.Option) *admin.Plugin {
	return admin.New(repo, opts...)
}

// Passkey instantiates a new Passkey (WebAuthn / FIDO2 / Passwordless) authentication plugin configured with a repository and options.
//
// The Passkey plugin provides biometric and security key passwordless authentication, resident keys (discoverable credentials / conditional UI),
// AAGUID authenticator metadata lookup, replay and cloning protection via monotonic signature counters, and full lifecycle event dispatching.
//
// # Available Methods
//
//   - GenerateRegistrationOptions(ctx context.Context, params *GenerateRegistrationOptionsParams) (*RegistrationOptionsResult, error): Generate WebAuthn creation ceremony options and challenge.
//   - VerifyRegistration(ctx context.Context, params *VerifyRegistrationParams) (*entity.Passkey, error): Verify navigator.credentials.create() response and persist public key credential.
//   - GenerateAuthenticationOptions(ctx context.Context, params *GenerateAuthenticationOptionsParams) (*AuthenticationOptionsResult, error): Generate WebAuthn assertion ceremony options (supports discoverable keys/autofill).
//   - VerifyAuthentication(ctx context.Context, params *VerifyAuthenticationParams) (*VerifyAuthenticationResult, error): Verify navigator.credentials.get() assertion response and establish authenticated session.
//   - ListPasskeys(ctx context.Context, params *ListPasskeysParams) ([]*entity.Passkey, error): List all registered passkeys for an authenticated user.
//   - GetPasskey(ctx context.Context, id string) (*entity.Passkey, error): Retrieve specific passkey credential details by ID.
//   - UpdatePasskey(ctx context.Context, params *UpdatePasskeyParams) (*entity.Passkey, error): Rename or update friendly label of a registered passkey.
//   - DeletePasskey(ctx context.Context, params *DeletePasskeyParams) error: Remove a passkey credential from user account.
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
//	ctx := context.Background()
//	storage := memory.New()
//	app, err := auth.New(
//		config.WithPlugins(
//			plugins.Passkey(
//				storage,
//				passkey.WithRPDisplayName("Acme Corp"),
//				passkey.WithRPID("auth.acme.com"),
//				passkey.WithRPOrigins("https://auth.acme.com"),
//			),
//		),
//	)
//	if err != nil {
//		panic(err)
//	}
//
//	regOpts, err := auth.Plugin[passkey.Plugin](app).GenerateRegistrationOptions(ctx, passkey.GenerateRegistrationOptionsParams{
//		UserID:          "usr_123",
//		UserName:        "gopher@golang.org",
//		UserDisplayName: "Gopher Go",
//	})
//	if err != nil {
//		panic(err)
//	}
func Passkey(repo passkey.Repository, opts ...passkey.Option) *passkey.Plugin {
	return passkey.New(repo, opts...)
}

// EmailOTP instantiates a new Email OTP authentication plugin configured with a repository and functional options.
//
// The EmailOTP plugin handles passwordless authentication (sign-in and automatic sign-up), email address verification,
// secure password reset flows, and verified email change requests via cryptographically secure one-time numeric passwords.
//
// # Available Methods
//
//   - SendVerificationOTP(ctx context.Context, params *SendVerificationOTPParams) (*SendVerificationOTPResult, error): Generate and dispatch an OTP code via transactional email.
//   - CreateVerificationOTP(ctx context.Context, params *CreateVerificationOTPParams) (string, error): Server-side generation of an OTP code without sending email.
//   - GetVerificationOTP(ctx context.Context, params *GetVerificationOTPParams) (*GetVerificationOTPResult, error): Retrieve active OTP details for testing or inspection.
//   - CheckVerificationOTP(ctx context.Context, params *CheckVerificationOTPParams) (*CheckVerificationOTPResult, error): Non-destructive validation check of an OTP code without consuming it.
//   - VerifyEmailOTP(ctx context.Context, params *VerifyEmailOTPParams) (*VerifyEmailOTPResult, error): Verify OTP for email address confirmation.
//   - SignInEmailOTP(ctx context.Context, params *SignInEmailOTPParams) (*SignInEmailOTPResult, error): Passwordless authentication (sign-in/sign-up) using verified OTP code.
//   - RequestPasswordResetEmailOTP(ctx context.Context, params *RequestPasswordResetParams) (*RequestPasswordResetResult, error): Initiate password reset workflow via email OTP.
//   - ResetPasswordEmailOTP(ctx context.Context, params *ResetPasswordParams) (*ResetPasswordResult, error): Reset user password upon submitting valid OTP code.
//   - RequestEmailChangeEmailOTP(ctx context.Context, params *RequestEmailChangeParams) (*RequestEmailChangeResult, error): Initiate email address change workflow with OTP validation.
//   - ChangeEmailEmailOTP(ctx context.Context, params *ChangeEmailParams) (*ChangeEmailResult, error): Finalize email address update using verified OTP code.
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
//	ctx := context.Background()
//	storage := memory.New()
//	app, err := auth.New(
//		config.WithPlugins(
//			plugins.EmailOTP(
//				storage,
//				emailotp.WithSendVerificationOTP(func(ctx context.Context, data emailotp.SendEmailData) error {
//					return mailer.Send(data.Email, "Your OTP Code", data.OTP)
//				}),
//			),
//		),
//	)
//	if err != nil {
//		panic(err)
//	}
//
//	otpRes, err := auth.Plugin[emailotp.Plugin](app).SendVerificationOTP(ctx, emailotp.SendVerificationOTPParams{
//		Email: "gopher@golang.org",
//		Type:  emailotp.OTPTypeSignIn,
//	})
//	if err != nil {
//		panic(err)
//	}
func EmailOTP(repo emailotp.Repository, opts ...emailotp.Option) *emailotp.Plugin {
	return emailotp.New(repo, opts...)
}

// PhoneNumber instantiates a new Phone Number (SMS OTP) authentication plugin configured with a repository and options.
//
// The PhoneNumber plugin handles passwordless SMS OTP authentication, phone number verification and updates,
// credentialed phone + password sign-in, secure password resets via SMS, attempt budgeting, and anti-replay protection.
//
// # Available Methods
//
//   - SendOTP(ctx context.Context, params SendOTPParams) (*SendOTPResult, error): Generate and dispatch a numeric OTP code via SMS callback.
//   - Verify(ctx context.Context, params VerifyParams) (*VerifyResult, error): Verify an SMS OTP code for passwordless sign-in, registration, or phone update.
//   - SignIn(ctx context.Context, params SignInParams) (*SignInResult, error): Authenticate an existing user using verified phone number and password credentials.
//   - RequestPasswordReset(ctx context.Context, params RequestPasswordResetParams) (*RequestPasswordResetResult, error): Initiate password reset flow via SMS OTP code.
//   - ResetPassword(ctx context.Context, params ResetPasswordParams) (*ResetPasswordResult, error): Finalize password reset using verified SMS OTP code.
//   - UnlinkPhoneNumber(ctx context.Context, userID string) (*entity.User, error): Remove associated phone number from user account.
//   - CreateVerificationOTP(ctx context.Context, params CreateVerificationOTPParams) (*CreateVerificationOTPResult, error): Server-side generation of phone OTP code.
//   - GetVerificationOTP(ctx context.Context, params GetVerificationOTPParams) (*GetVerificationOTPResult, error): Inspect active phone OTP code record.
//   - CheckVerificationOTP(ctx context.Context, params CheckVerificationOTPParams) (*CheckVerificationOTPResult, error): Non-destructive validation check of phone OTP code.
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
//	ctx := context.Background()
//	storage := memory.New()
//	app, err := auth.New(
//		config.WithPlugins(
//			plugins.PhoneNumber(
//				storage,
//				phonenumber.WithSendOTP(func(ctx context.Context, data phonenumber.SendOTPData) error {
//					return smsClient.SendSMS(data.PhoneNumber, "Your code is: " + data.Code)
//				}),
//			),
//		),
//	)
//	if err != nil {
//		panic(err)
//	}
//
//	otpRes, err := auth.Plugin[phonenumber.Plugin](app).SendOTP(ctx, phonenumber.SendOTPParams{
//		PhoneNumber: "+15551234567",
//	})
//	if err != nil {
//		panic(err)
//	}
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
// # Available Methods
//
//   - Authorization Flow:
//     - Authorize(ctx context.Context, params AuthorizeParams) (*AuthorizeResult, error): Initiate OAuth 2.1 authorization request with PKCE and scope negotiation.
//     - ContinueAuthorize(ctx context.Context, params ContinueAuthorizeParams) (*AuthorizeResult, error): Resume authorization after user login and scope consent approval.
//
//   - Token Exchange & Management:
//     - Token(ctx context.Context, params TokenParams) (*TokenResult, error): Exchange authorization code or refresh token for Access Token and OIDC ID Token.
//     - Introspect(ctx context.Context, params IntrospectParams) (*IntrospectResult, error): RFC 7662 token introspection to query token status and claims.
//     - Revoke(ctx context.Context, params RevokeParams) (*RevokeResult, error): RFC 7009 token revocation for access and refresh tokens.
//
//   - OIDC UserInfo & Session Termination:
//     - UserInfo(ctx context.Context, params UserInfoParams) (*UserInfoResult, error): Serve OIDC UserInfo endpoint returning verified subject claims.
//     - EndSession(ctx context.Context, params EndSessionParams) (*EndSessionResult, error): RP-Initiated Logout to terminate user sessions.
//
//   - Client Registration (RFC 7591):
//     - RegisterClient(ctx context.Context, params RegisterClientParams) (*RegisterClientResult, error): Dynamically register an OAuth 2.1 client application.
//     - GetClient(ctx context.Context, params GetClientParams) (*GetClientResult, error): Retrieve registered client details.
//     - UpdateClient(ctx context.Context, params UpdateClientParams) (*UpdateClientResult, error): Modify client configuration (redirect URIs, scopes, grant types).
//     - DeleteClient(ctx context.Context, params DeleteClientParams) (*DeleteClientResult, error): Delete a registered client application.
//     - RotateClientSecret(ctx context.Context, params RotateClientSecretParams) (*RotateClientSecretResult, error): Rotate client secret credentials.
//
//   - User Consent Management:
//     - Consent(ctx context.Context, params ConsentParams) (*ConsentResult, error): Record user consent for authorized client scopes.
//     - RevokeConsent(ctx context.Context, params RevokeConsentParams) (*RevokeConsentResult, error): Revoke client access to user data.
//     - ListConsents(ctx context.Context, params ListConsentsParams) (*ListConsentsResult, error): List all active third-party application authorizations for a user.
//
//   - Discovery & Metadata:
//     - GetOpenIDConfiguration(ctx context.Context, params OpenIDConfigurationParams) (*OpenIDConfigurationResult, error): Serve .well-known/openid-configuration metadata.
//     - GetOAuthAuthorizationServerMetadata(ctx context.Context, params OAuthMetadataParams) (*OAuthMetadataResult, error): Serve RFC 8414 OAuth 2.0 authorization server metadata.
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
//	ctx := context.Background()
//	storage := memory.New()
//	app, err := auth.New(
//		config.WithPlugins(
//			plugins.OAuth2(
//				storage,
//				oauth2.WithIssuer("https://auth.example.com"),
//				oauth2.WithAccessTokenType(oauth2.AccessTokenTypeJWT),
//			),
//		),
//	)
//	if err != nil {
//		panic(err)
//	}
//
//	authRes, err := auth.Plugin[oauth2.Plugin](app).Authorize(ctx, oauth2.AuthorizeParams{
//		ClientID:            "client_123",
//		RedirectURI:         "https://app.example.com/callback",
//		ResponseType:        "code",
//		CodeChallenge:       "E9Melhoa2OwvFrGMTJguCH5rtx64EH_vu9-D64PJstU",
//		CodeChallengeMethod: "S256",
//		Scope:               "openid profile email",
//		State:               "state_xyz",
//	})
//	if err != nil {
//		panic(err)
//	}
func OAuth2(repo oauth2.Repository, opts ...oauth2.Option) *oauth2.Plugin {
	return oauth2.New(repo, opts...)
}

// GenericOAuth instantiates a new Generic OAuth & OIDC social authentication plugin configured with an optional repository and options.
//
// The GenericOAuth plugin enables dynamic integration with any OAuth 2.0 or OpenID Connect (OIDC) identity provider,
// supporting automatic OIDC discovery (/.well-known/openid-configuration), PKCE (S256) code challenge security,
// state token verification, user lookup/auto-creation, account linking to existing user profiles, session issuance,
// and preset provider builders (Auth0, Okta, Keycloak, Microsoft Entra ID, Slack, HubSpot, Line, Patreon, etc.).
//
// # Available Methods
//
//   - SignIn(ctx context.Context, providerID string, callbackURL string) (*SignInData, error): Initiate an OAuth authorization flow for the specified provider.
//   - Callback(ctx context.Context, providerID string, code string, state string, codeVerifier string) (*entity.User, *entity.Session, *Tokens, error): Process authorization code exchange, user lookup/registration, account linking, and session creation.
//   - LinkAccount(ctx context.Context, userID string, providerID string, code string, codeVerifier string) (*entity.Account, error): Explicitly bind a social provider profile to an existing authenticated user account.
//   - GetProvider(providerID string) (*ProviderConfig, error): Retrieve registered configuration for a specific provider.
//   - Config() Config: Retrieve the active configuration of the Generic OAuth plugin.
//
// # Configuration Options
//
// You can pass functional options to customize the plugin:
//
//   - genericoauth.WithProvider(cfg *genericoauth.ProviderConfig): Register an OAuth/OIDC provider configuration.
//   - genericoauth.WithHTTPClient(client *http.Client): Override the HTTP client used for discovery, token exchange, and UserInfo calls.
//   - genericoauth.WithCookieConfig(cfg genericoauth.CookieConfig): Customize cookie settings for state and PKCE tracking.
//   - genericoauth.WithStateTTL(ttl time.Duration): Set maximum expiration duration for OAuth state and PKCE verifier tokens (default: 10 minutes).
//
// Example:
//
//	ctx := context.Background()
//	storage := memory.New()
//	app, err := auth.New(
//		config.WithPlugins(
//			plugins.GenericOAuth(
//				storage,
//				genericoauth.WithProvider(&genericoauth.ProviderConfig{
//					ProviderID:   "github",
//					ClientID:     "my-client-id",
//					ClientSecret: "my-client-secret",
//					AuthURL:      "https://github.com/login/oauth/authorize",
//					TokenURL:     "https://github.com/login/oauth/access_token",
//					UserInfoURL:  "https://api.github.com/user",
//					Scopes:       []string{"read:user", "user:email"},
//				}),
//			),
//		),
//	)
//	if err != nil {
//		panic(err)
//	}
//
//	signInData, err := auth.Plugin[genericoauth.Plugin](app).SignIn(ctx, "github", "https://myapp.com/callback/github")
//	if err != nil {
//		panic(err)
//	}
//	_ = signInData.URL
func GenericOAuth(repo genericoauth.Repository, opts ...genericoauth.Option) *genericoauth.Plugin {
	return genericoauth.New(repo, opts...)
}

// Access instantiates a new Access Control (Granular Permissions & RBAC/ABAC) plugin configured with master statements and options.
//
// The Access plugin provides sub-microsecond in-memory permission evaluation, boolean logic combinators (AND/OR),
// wildcard matching ('*'), multi-role subject aggregation, dynamic role inheritance (Extend/Merge), thread-safe runtime
// role registration, JSON persistence serialization, and execution guards for HTTP/gRPC middlewares.
//
// # Available Methods
//
//   - Plugin Methods:
//     - AccessControl() *AccessControl: Returns the underlying central AccessControl manager instance.
//     - PublishAuthorized(roles []string, req AuthorizeRequest, extra map[string]any): Dispatch access:authorized security event.
//     - PublishDenied(roles []string, req AuthorizeRequest, reason string, extra map[string]any): Dispatch access:denied security event.
//     - PublishRoleCreated(role *Role): Dispatch access:role:created lifecycle event.
//     - PublishRoleDeleted(roleName string): Dispatch access:role:deleted lifecycle event.
//
//   - AccessControl Manager Methods (via plugin.AccessControl()):
//     - NewRole(name string, roleStatements Statements) (*Role, error): Create and register a named role in the registry.
//     - MustNewRole(name string, roleStatements Statements) *Role: Create a role, panicking on validation error.
//     - NewAnonymousRole(roleStatements Statements) (*Role, error): Instantiate an unregistered ephemeral role.
//     - GetRole(name string) (*Role, bool): Retrieve a registered role by identifier.
//     - GetAllRoles() map[string]*Role: Return snapshot of all registered roles.
//     - DeleteRole(name string) bool: Remove a role from the registry.
//     - AuthorizeRoles(roleNames []string, request AuthorizeRequest, connector ...Connector) AuthorizeResult: Atomic multi-role evaluation combining statements with union semantics.
//     - AuthorizeRoleString(roleString string, request AuthorizeRequest, connector ...Connector) AuthorizeResult: Evaluate comma-separated role string ("admin,editor").
//     - MergeRoles(roleNames ...string) (*Role, error): Consolidate multiple registered roles into a combined Role instance.
//     - MasterStatements() Statements: Retrieve schema master statements.
//
//   - Role Instance Methods (via role):
//     - Authorize(request AuthorizeRequest, connector ...Connector) AuthorizeResult: Evaluate granular permission request with short-circuit evaluation.
//     - HasPermission(resource string, action string) bool: Check single resource and action permission in sub-microsecond time.
//     - Extend(newName string, additionalStatements Statements) *Role: Derive a new role inheriting base statements without mutating parent.
//     - Clone(newName ...string) *Role: Create a deep copy of the role.
//     - Statements() Statements: Return copy of role permission statements.
//     - Name() string: Return role name.
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
//	ctx := context.Background()
//	statements := access.Statements{
//		"project": {"create", "read", "update", "delete"},
//		"user":    {"create", "read", "update", "delete"},
//	}
//
//	app, err := auth.New(
//		config.WithPlugins(
//			plugins.Access(
//				statements,
//				access.WithInitialRoles(map[string]access.Statements{
//					"admin": {"*": {"*"}},
//					"user":  {"project": {"read"}, "user": {"read"}},
//				}),
//			),
//		),
//	)
//	if err != nil {
//		panic(err)
//	}
//
//	ac := auth.Plugin[access.Plugin](app).AccessControl()
//	res := ac.AuthorizeRoles([]string{"user"}, access.Req("project", "read"))
//	if !res.Success {
//		panic(res.Error)
//	}
func Access(masterStatements access.Statements, opts ...access.Option) *access.Plugin {
	return access.New(masterStatements, opts...)
}

// MagicLink instantiates a new MagicLink authentication plugin configured with the given repository and options.
//
// The MagicLink plugin provides passwordless user authentication and auto-registration via transactional email verification links.
// It features atomic single-use token consumption (protecting against race conditions and replay attacks), flexible token
// storage modes (plain text, SHA-256 constant-time hashing, and AES-256-GCM symmetric encryption), customizable redirect URLs
// for new vs existing users, HTTP handlers for direct router integration, and lifecycle event bus hooks.
//
// # Available Methods
//
//   - SignInMagicLink(ctx context.Context, params magiclink.SignInMagicLinkParams) (*magiclink.SignInMagicLinkResult, error): Issue a secure verification token and dispatch the magic link email.
//   - VerifyMagicLink(ctx context.Context, params magiclink.VerifyMagicLinkParams) (*magiclink.VerifyMagicLinkResult, error): Atomically consume token, authenticate/register user, and issue active session.
//   - HandleSignInMagicLink(w http.ResponseWriter, r *http.Request): HTTP POST endpoint handler for /sign-in/magic-link.
//   - HandleVerifyMagicLink(w http.ResponseWriter, r *http.Request): HTTP GET/POST endpoint handler for /magic-link/verify with JSON or browser redirect output.
//
// # Configuration Options
//
// You can pass functional options to customize the plugin:
//
//   - magiclink.WithSendMagicLink(fn magiclink.SendMagicLinkFunc): Transactional email delivery callback for dispatching magic links (Required).
//   - magiclink.WithExpiresIn(duration time.Duration): Expiry duration for verification tokens (default: 5 minutes).
//   - magiclink.WithDisableSignUp(disable bool): Prevent auto-registration of unknown email addresses (default: false).
//   - magiclink.WithDefaultCallbackURL(url string): Default fallback redirect URL after successful login (default: "/").
//   - magiclink.WithStoreTokenMode(mode magiclink.StoreTokenMode): Security storage mode ("plain", "hashed", "encrypted", default: "plain").
//   - magiclink.WithSecretKey(key string): Secret key used for AES-256-GCM encrypted token storage.
//   - magiclink.WithCustomHasher(h magiclink.Hasher): Custom token hasher implementation for hashed mode.
//   - magiclink.WithCustomCipher(c magiclink.Cipher): Custom token cipher implementation for encrypted mode.
//   - magiclink.WithGenerateToken(fn magiclink.TokenGeneratorFunc): Custom token generator function.
//   - magiclink.WithRateLimit(window time.Duration, max int): Request throttling configuration (default: 5 requests per 60 seconds).
//
// Example:
//
//	ctx := context.Background()
//	storage := memory.New()
//	app, err := auth.New(
//		config.WithPlugins(
//			plugins.MagicLink(
//				storage,
//				magiclink.WithSendMagicLink(func(ctx context.Context, data magiclink.SendMagicLinkData) error {
//					fmt.Printf("Send magic link to %s: %s\n", data.Email, data.URL)
//					return nil
//				}),
//				magiclink.WithExpiresIn(10 * time.Minute),
//				magiclink.WithDefaultCallbackURL("/dashboard"),
//			),
//		),
//	)
//	if err != nil {
//		panic(err)
//	}
//
//	res, err := auth.Plugin[magiclink.Plugin](app).SignInMagicLink(ctx, magiclink.SignInMagicLinkParams{
//		Email: "gopher@golang.org",
//		Name:  "Gopher Go",
//	})
//	if err != nil {
//		panic(err)
//	}
func MagicLink(repo magiclink.Repository, opts ...magiclink.Option) *magiclink.Plugin {
	return magiclink.New(repo, opts...)
}

// Username instantiates a new Username authentication plugin configured with the given repository and options.
//
// The Username plugin enables username-based sign-in, username availability validation,
// character normalization (lowercasing by default), display username support, and timing attack mitigation.
//
// # Available Methods
//
//   - SignIn(ctx context.Context, params SignInUsernameParams) (*SignInUsernameResult, error): Authenticate a user with username and password credentials.
//   - IsAvailable(ctx context.Context, username string) (*IsUsernameAvailableResult, error): Check if a username is available for registration.
//   - UpdateUsername(ctx context.Context, params UpdateUsernameParams) (*UpdateUsernameResult, error): Update a user's username and display name.
//   - ProcessSignUpUsername(ctx context.Context, username, displayUsername string) (normalized, finalDisplay string, err error): Validate and normalize credentials for user registration.
//   - ValidateUsername(ctx context.Context, username string) error: Validate username length, format, and custom constraints.
//
// # Configuration Options
//
//   - username.WithMinLength(minLen int): Minimum allowed username length (default: 3).
//   - username.WithMaxLength(maxLen int): Maximum allowed username length (default: 30).
//   - username.WithUsernameValidator(pattern string): Custom regular expression format pattern.
//   - username.WithCustomValidator(fn username.CustomValidatorFunc): Asynchronous custom validator callback.
//   - username.WithNormalization(enable bool): Enable or disable username normalization (default: true).
//   - username.WithNormalizationFunc(fn username.NormalizationFunc): Custom normalization routine (default: strings.ToLower).
//   - username.WithRequireEmailVerification(require bool): Require verified email before sign-in (default: false).
//
// Example:
//
//	ctx := context.Background()
//	storage := memory.New()
//	app, err := auth.New(
//		config.WithPlugins(
//			plugins.Username(
//				storage,
//				username.WithMinLength(4),
//				username.WithRequireEmailVerification(true),
//			),
//		),
//	)
//	if err != nil {
//		panic(err)
//	}
//
//	res, err := auth.Plugin[username.Plugin](app).SignIn(ctx, username.SignInUsernameParams{
//		Username: "gopher_coder",
//		Password: "SecurePassword123!",
//	})
//	if err != nil {
//		panic(err)
//	}
func Username(repo username.Repository, opts ...username.Option) *username.Plugin {
	return username.New(repo, opts...)
}

// DeviceAuth instantiates a new Device Authorization Flow (RFC 8628) plugin configured with the given repository and options.
//
// The DeviceAuth plugin enables OAuth 2.0 Device Authorization Grant workflow for input-constrained
// or browserless devices (Smart TVs, CLI tools, IoT hardware), issuing short verification codes for end-user approval
// on a secondary browser and exchanging approved grants for active user sessions.
//
// # Available Methods
//
//   - RequestDeviceCode(ctx context.Context, params RequestDeviceCodeParams) (*DeviceCodeResponse, error): Initiate a new device authorization grant request.
//   - ExchangeDeviceToken(ctx context.Context, params ExchangeDeviceTokenParams) (*TokenResponse, error): Poll for authorization and exchange an approved device code for a session token.
//   - GetVerificationState(ctx context.Context, rawUserCode string) (*DeviceCode, error): Retrieve device authorization status by user verification code.
//   - ApproveDeviceCode(ctx context.Context, params ApproveDeviceCodeParams) error: Authorize a pending device code request for an authenticated user.
//   - DenyDeviceCode(ctx context.Context, params DenyDeviceCodeParams) error: Reject a pending device code authorization request.
//
// # Configuration Options
//
//   - deviceauth.WithExpiresIn(d time.Duration): Expiration lifetime duration of issued device code grants (default: 30 minutes).
//   - deviceauth.WithInterval(d time.Duration): Minimum polling interval requirement between token requests (default: 5 seconds).
//   - deviceauth.WithDeviceCodeLength(length int): Character length of generated device codes (default: 40).
//   - deviceauth.WithUserCodeLength(length int): Character length of generated user codes (default: 8).
//   - deviceauth.WithVerificationURI(uri string): Base verification path returned in responses (default: "/device").
//   - deviceauth.WithCustomURI(uri string): Custom domain base URI for complete verification URLs.
//   - deviceauth.WithSessionExpiry(d time.Duration): Duration of sessions generated upon token exchange (default: 24 hours).
//   - deviceauth.WithGenerateDeviceCode(fn func(int) (string, error)): Custom device code generator callback.
//   - deviceauth.WithGenerateUserCode(fn func(int) (string, error)): Custom user code generator callback.
//   - deviceauth.WithValidateClient(fn func(context.Context, string) (bool, error)): Callback to validate client_id during requests.
//   - deviceauth.WithOnDeviceAuthRequest(fn func(context.Context, string, *string) error): Callback hook executed on device code requests.
//
// Example:
//
//	ctx := context.Background()
//	storage := repo // custom deviceauth.Repository implementation
//	app, err := auth.New(
//		config.WithPlugins(
//			plugins.DeviceAuth(
//				storage,
//				deviceauth.WithExpiresIn(15*time.Minute),
//				deviceauth.WithInterval(5*time.Second),
//			),
//		),
//	)
//	if err != nil {
//		panic(err)
//	}
//
//	devPlugin := auth.Plugin[deviceauth.Plugin](app)
//	resp, err := devPlugin.RequestDeviceCode(ctx, deviceauth.RequestDeviceCodeParams{
//		ClientID: "cli_app",
//	})
//	if err != nil {
//		panic(err)
//	}
func DeviceAuth(repo deviceauth.Repository, opts ...deviceauth.Option) *deviceauth.Plugin {
	return deviceauth.New(repo, opts...)
}

// OIDCProvider instantiates a new OIDC Provider (OpenID Connect 1.0 / OAuth 2.0) plugin configured with the given repository and options.
//
// The OIDCProvider plugin converts your application into an OAuth 2.0 Authorization Server and OpenID Connect Provider (OP),
// handling client registration, Authorization Code Flow with PKCE (RFC 7636), user consent management, Access/Refresh/ID Token issuance,
// UserInfo claims endpoint, RP-Initiated Logout, OpenID Connect Discovery metadata (/.well-known/openid-configuration), and public JWKS export.
//
// # Available Methods
//
//   - RegisterClient(ctx context.Context, params RegisterClientParams) (*OAuthClient, error): Register a new OAuth 2.0 / OIDC client application.
//   - GetClient(ctx context.Context, clientID string) (*OAuthClient, error): Retrieve a registered client application by client_id.
//   - Authorize(ctx context.Context, params AuthorizeParams) (*AuthorizeResponse, error): Process an authorization request and issue an authorization code.
//   - GrantConsent(ctx context.Context, params GrantConsentParams) (*AuthorizeResponse, error): Record explicit user scope consent for a client.
//   - ExchangeToken(ctx context.Context, params ExchangeTokenParams) (*TokenResponse, error): Exchange an authorization code or refresh token for token pairs.
//   - GetUserInfo(ctx context.Context, accessToken string) (UserInfoClaims, error): Retrieve standard OpenID Connect claims for a valid access_token.
//   - EndSession(ctx context.Context, idTokenHint string, postLogoutRedirectURI *string) (string, error): Perform RP-Initiated Logout.
//   - GetDiscoveryMetadata(ctx context.Context) (*DiscoveryMetadata, error): Generate OpenID Connect Discovery 1.0 JSON configuration.
//   - GetJWKS(ctx context.Context) (map[string]any, error): Export public keys in JWKS format.
//
// # Configuration Options
//
//   - oidcprovider.WithIssuer(issuer string): OIDC issuer identifier URL (default: "http://localhost:8080").
//   - oidcprovider.WithBaseURL(url string): Base URL for endpoint path construction.
//   - oidcprovider.WithTokenExpirations(access, refresh, code time.Duration): Expiration durations for tokens and codes.
//   - oidcprovider.WithSupportedScopes(scopes []string): List of supported OIDC scopes (default: openid, profile, email, offline_access).
//   - oidcprovider.WithRequirePKCE(require bool): Enforce PKCE for authorization code grant requests (default: true).
//   - oidcprovider.WithRSAKeys(privateKey *rsa.PrivateKey): RSA private key for RS256 ID Token signing and JWKS export.
//   - oidcprovider.WithSecretKey(secret []byte): Shared secret key for HS256 ID Token signing.
//   - oidcprovider.WithStoreClientSecretMode(mode SecretStoreMode): How client_secret values are stored and verified.
//   - oidcprovider.WithConsentPageURL(url string): Interactive consent UI page URL.
//   - oidcprovider.WithLoginPageURL(url string): Login redirect URL.
//   - oidcprovider.WithAdditionalClaims(fn AdditionalClaimsFunc): Custom callback to inject custom claims into UserInfo and ID Tokens.
//
// Example:
//
//	ctx := context.Background()
//	storage := repo // custom oidcprovider.Repository implementation
//	app, err := auth.New(
//		config.WithPlugins(
//			plugins.OIDCProvider(
//				storage,
//				oidcprovider.WithIssuer("https://auth.example.com"),
//				oidcprovider.WithSecretKey([]byte("my-super-secret-key-32-bytes")),
//			),
//		),
//	)
//	if err != nil {
//		panic(err)
//	}
//
//	op := auth.Plugin[oidcprovider.Plugin](app)
//	client, err := op.RegisterClient(ctx, oidcprovider.RegisterClientParams{
//		Name:         "My Web App",
//		Type:         oidcprovider.ClientTypeWeb,
//		RedirectURIs: []string{"https://app.example.com/callback"},
//	})
//	if err != nil {
//		panic(err)
//	}
func OIDCProvider(repo oidcprovider.Repository, opts ...oidcprovider.Option) *oidcprovider.Plugin {
	return oidcprovider.New(repo, opts...)
}

// ApiKey instantiates a new ApiKey authentication and rate-limiting plugin configured with the given repository and options.
//
// The ApiKey plugin allows applications to create, verify, list, update, and revoke API keys with SHA-256 base64url hashing,
// sliding window rate limiting, quota auto-refill, scope permission verification, custom JSON metadata, expiration,
// asynchronous background updates (DeferUpdates), and HTTP header middleware authentication.
//
// # Available Methods
//
//   - CreateKey(ctx context.Context, params CreateApiKeyParams) (*CreateApiKeyResult, error): Issue a new API key.
//   - VerifyKey(ctx context.Context, params VerifyApiKeyParams) (*VerifyApiKeyResult, error): Authenticate an incoming API key.
//   - GetKey(ctx context.Context, params GetApiKeyParams) (*ApiKey, error): Retrieve key details by ID.
//   - UpdateKey(ctx context.Context, params UpdateApiKeyParams) (*ApiKey, error): Update metadata, status, or quota parameters.
//   - DeleteKey(ctx context.Context, params DeleteApiKeyParams) error: Revoke and delete an API key.
//   - ListKeys(ctx context.Context, params ListApiKeysParams) (*ListApiKeysResult, error): List keys for a owner reference ID.
//   - DeleteAllExpiredKeys(ctx context.Context) (int64, error): Purge all expired keys from storage.
//   - HTTPMiddleware() func(next http.Handler) http.Handler: Net/HTTP middleware for authenticating API Key request headers.
//
// # Configuration Options
//
//   - apikey.WithHeaderNames(headers ...string): Request headers checked for API keys (default: "X-API-Key").
//   - apikey.WithDefaultKeyLength(length int): Key character length (default: 32).
//   - apikey.WithDefaultPrefix(prefix string): Key prefix attached to issued keys (e.g. "sk_live_").
//   - apikey.WithRateLimit(enabled bool, window time.Duration, maxReq int64): Configure sliding window rate limiting.
//   - apikey.WithExpiration(defaultExpiresIn *time.Duration): Configure default expiration duration.
//   - apikey.WithDisableKeyHashing(disable bool): Toggle storing raw plaintext keys instead of SHA-256 hashes.
//   - apikey.WithEnableSessionForAPIKeys(enable bool): Populate mock user identity during HTTP middleware verification.
//   - apikey.WithDeferUpdates(deferUpdates bool): Execute request counter and timestamp updates asynchronously.
//
// Example:
//
//	ctx := context.Background()
//	storage := repo // custom apikey.Repository implementation
//	app, err := auth.New(
//		config.WithPlugins(
//			plugins.ApiKey(
//				storage,
//				apikey.WithDefaultPrefix("sk_live_"),
//				apikey.WithDeferUpdates(true),
//			),
//		),
//	)
//	if err != nil {
//		panic(err)
//	}
//
//	ak := auth.Plugin[apikey.Plugin](app)
//	res, err := ak.CreateKey(ctx, apikey.CreateApiKeyParams{
//		ReferenceID: "user_123",
//		Name:        stringPtr("Production Access"),
//	})
//	if err != nil {
//		panic(err)
//	}
//	fmt.Println("Raw API Key (shown once):", res.RawKey)
func ApiKey(repo apikey.Repository, opts ...apikey.Option) *apikey.Plugin {
	return apikey.New(repo, opts...)
}

// OTT instantiates a new One-Time Token (OTT) authentication plugin configured with the given repository and options.
//
// The OTT plugin allows issuing single-use, time-bound tokens bound to active user sessions for cross-domain SSO,
// secure credential exchange, or automatic session header generation.
//
// # Available Methods
//
//   - GenerateToken(ctx context.Context, params GenerateTokenParams) (*GenerateTokenResponse, error): Issue a new single-use token bound to a session.
//   - VerifyToken(ctx context.Context, params VerifyTokenParams) (*VerifyTokenResponse, error): Validate and atomically consume an OTT token.
//   - AttachOttHeader(w http.ResponseWriter, sessionToken string) error: Generate an OTT and set the set-ott HTTP header.
//
// # Configuration Options
//
//   - ott.WithExpiresIn(d time.Duration): Lifetime duration for issued OTT tokens (default: 3 minutes).
//   - ott.WithDisableClientRequest(disable bool): Disable token generation requests originating directly from HTTP clients.
//   - ott.WithDisableSetSessionCookie(disable bool): Prevent setting session HTTP cookies on verification.
//   - ott.WithSetOttHeaderOnNewSession(enable bool): Automatically attach set-ott header on new session creation.
//   - ott.WithStoreTokenMode(mode ott.StoreTokenMode): Set token storage mode ("plain" or "hashed", default: "plain").
//   - ott.WithCustomHasher(fn ott.HasherFunc): Override default SHA-256 base64url token hasher.
//   - ott.WithCustomGenerator(fn ott.TokenGeneratorFunc): Override default crypto/rand random token generator.
//
// Example:
//
//	ctx := context.Background()
//	storage := repo // custom ott.Repository implementation
//	app, err := auth.New(
//		config.WithPlugins(
//			plugins.OTT(
//				storage,
//				ott.WithExpiresIn(5*time.Minute),
//				ott.WithStoreTokenMode(ott.StoreTokenHashed),
//			),
//		),
//	)
//	if err != nil {
//		panic(err)
//	}
//
//	ottPlugin := auth.Plugin[ott.Plugin](app)
//	resp, err := ottPlugin.GenerateToken(ctx, ott.GenerateTokenParams{
//		SessionToken: "sess_123456",
//	})
//	if err != nil {
//		panic(err)
//	}
//	_ = resp.Token
func OTT(repo ott.Repository, opts ...ott.Option) *ott.Plugin {
	return ott.New(repo, opts...)
}

// Captcha instantiates a new Captcha verification plugin configured with functional options.
//
// The Captcha plugin provides middleware and verifiers for intercepting authentication endpoints (such as /sign-up/email, /sign-in/email)
// and validating client tokens against Cloudflare Turnstile, Google reCAPTCHA v2/v3, hCaptcha, or CaptchaFox.
//
// # Available Methods
//
//   - VerifyToken(ctx context.Context, token string, remoteIP string) error: Manually validate a captcha response token against the configured provider.
//   - IsProtectedPath(path string) bool: Check if a given URI path is configured for captcha protection.
//   - HTTPMiddleware() func(next http.Handler) http.Handler: Return a net/http middleware handler to intercept and validate requests on protected endpoints.
//
// # Configuration Options
//
//   - captcha.WithProvider(p captcha.Provider): Set captcha provider (Turnstile, reCAPTCHA, hCaptcha, CaptchaFox).
//   - captcha.WithSecretKey(key string): Configure private secret key for provider verification API.
//   - captcha.WithSiteKey(key string): Configure public site key for providers requiring it.
//   - captcha.WithEndpoints(endpoints []string): Set protected request URI paths.
//   - captcha.WithExemptEndpoints(exempt []string): Set exempted request URI paths.
//   - captcha.WithSiteVerifyURLOverride(url string): Override default siteverify endpoint URL.
//   - captcha.WithMinScore(score float64): Minimum score for reCAPTCHA v3 verification (default: 0.5).
//   - captcha.WithExpectedAction(action string): Validate expected action string for Turnstile / reCAPTCHA.
//   - captcha.WithAllowedHostnames(hostnames []string): Restrict valid tokens to allowed hostnames.
//   - captcha.WithTimeout(d time.Duration): Maximum verification HTTP request timeout (default: 10s).
//   - captcha.WithIPExtractor(fn captcha.IPExtractorFunc): Configure custom client remote IP extractor function.
//
// Example:
//
//	app, err := auth.New(
//		config.WithPlugins(
//			plugins.Captcha(
//				captcha.WithProvider(captcha.ProviderCloudflareTurnstile),
//				captcha.WithSecretKey("0x4AAAAAAAxXxxxxXXxxXxx"),
//				captcha.WithEndpoints([]string{"/sign-up/email", "/sign-in/email"}),
//			),
//		),
//	)
//	if err != nil {
//		panic(err)
//	}
//
//	captchaPlugin := auth.Plugin[captcha.Plugin](app)
//	_ = captchaPlugin.HTTPMiddleware()
func Captcha(opts ...captcha.Option) *captcha.Plugin {
	return captcha.New(opts...)
}

// OAuthProxy instantiates a new OAuth Proxy authentication plugin configured with functional options.
//
// The OAuth Proxy plugin resolves OAuth 2.0 / OIDC authentication in preview or dynamic deployment environments
// (e.g. Vercel Preview Deployments, Netlify Previews, local dev) by securely proxying authentication through a Production server.
//
// # Available Methods
//
//   - ServeOAuthProxyCallback(w http.ResponseWriter, r *http.Request): HTTP handler to verify and proxy incoming OAuth callback payloads from preview environments to production.
//   - RedirectToProduction(w http.ResponseWriter, r *http.Request, targetURL string): Redirect authentication requests from preview instances back to the main production server.
//   - VerifyProxyPayload(r *http.Request) (*ProxyPayload, error): Cryptographically verify signed payload parameters from proxy requests using HMAC SHA-256.
//
// # Configuration Options
//
// You can pass functional options to customize the plugin:
//
//   - oauthproxy.WithProductionURL(url string): Set base URL of the primary production server (e.g. "https://myapp.com").
//   - oauthproxy.WithSecret(secret string): Set shared HMAC SHA-256 secret key for signing preview/production proxy state.
//   - oauthproxy.WithAllowedRedirectURLs(urls ...string): Restrict valid preview environment callback URLs.
//
// Example:
//
//	app, err := auth.New(
//		config.WithPlugins(
//			plugins.OAuthProxy(
//				oauthproxy.WithProductionURL("https://myapp.com"),
//				oauthproxy.WithSecret("shared-secret-key-123"),
//			),
//		),
//	)
//	if err != nil {
//		panic(err)
//	}
//
//	proxyPlugin := auth.Plugin[oauthproxy.Plugin](app)
//	_ = proxyPlugin.ServeOAuthProxyCallback
func OAuthProxy(opts ...oauthproxy.Option) *oauthproxy.Plugin {
	return oauthproxy.New(opts...)
}

// MultiSession instantiates a new MultiSession authentication plugin configured with the given repository and options.
//
// The MultiSession plugin enables users/devices to maintain multiple active sessions for different user accounts
// within the same browser, managing HMAC SHA-256 signed multi-session cookies, active session switching,
// session limit enforcement, and mass session revocation on sign-out.
//
// # Available Methods
//
//   - ListDeviceSessions(ctx context.Context, r *http.Request) (*ListDeviceSessionsResult, error): List all active sessions registered on the current client device.
//   - SetActiveSession(ctx context.Context, params SetActiveSessionParams) (*SetActiveSessionResult, error): Switch the active account/session on the current client device.
//   - RevokeDeviceSession(ctx context.Context, params RevokeDeviceSessionParams) (*RevokeDeviceSessionResult, error): Revoke a specific multi-session from the client device.
//   - AfterSessionCreated(ctx context.Context, w http.ResponseWriter, r *http.Request, newSession *entity.Session) error: Lifecycle hook to enforce session limits and emit multi-session cookies.
//   - AfterSignOut(ctx context.Context, w http.ResponseWriter, r *http.Request) error: Perform mass revocation of all multi-sessions registered on the client device.
//
// # Configuration Options
//
// You can pass functional options to customize the plugin:
//
//   - multisession.WithMaximumSessions(max int): Set maximum allowed concurrent active sessions per device (default: 5).
//   - multisession.WithCookiePrefix(prefix string): Set prefix for multi-session cookies (default: "modular-auth").
//   - multisession.WithSecret(secret string): Set HMAC SHA-256 secret key for signing multi-session cookies.
//   - multisession.WithOnSessionActivated(fn SessionActivatedCallback): Callback invoked when a device session is set active.
//   - multisession.WithOnSessionRevoked(fn SessionRevokedCallback): Callback invoked when a device session is revoked.
//
// Example:
//
//	ctx := context.Background()
//	storage := memory.New()
//	app, err := auth.New(
//		config.WithPlugins(
//			plugins.MultiSession(
//				storage,
//				multisession.WithMaximumSessions(5),
//				multisession.WithCookiePrefix("modular-auth"),
//				multisession.WithSecret("my-hmac-secret-key"),
//			),
//		),
//	)
//	if err != nil {
//		panic(err)
//	}
//
//	multiSessionPlugin := auth.Plugin[multisession.Plugin](app)
//	_ = multiSessionPlugin
func MultiSession(repo multisession.Repository, opts ...multisession.Option) *multisession.Plugin {
	return multisession.New(repo, opts...)
}

// LastLoginMethod instantiates a new LastLoginMethod authentication plugin configured with functional options.
//
// The LastLoginMethod plugin automatically tracks the authentication method used by a user (e.g., email, google, github, passkey, magic-link, siwe),
// storing it in a client-readable browser cookie ("modular-auth.last_used_login_method" with HttpOnly=false) and optionally persisting it in the User entity in database.
//
// # Available Methods
//
//   - SetLastLoginMethod(ctx context.Context, w http.ResponseWriter, r *http.Request, userID, method string) (string, error): Explicitly record a user's last login method.
//   - GetLastLoginMethod(ctx context.Context, r *http.Request, userID string) (string, error): Retrieve last used login method from HTTP request cookies or DB.
//   - ClearLastLoginMethod(ctx context.Context, w http.ResponseWriter): Expire the last login method cookie and emit event.
//   - Middleware() func(next http.Handler) http.Handler: Net/HTTP middleware to automatically intercept responses (2xx), resolve login method, and emit cookie/DB update.
//
// # Configuration Options
//
// You can pass functional options to customize the plugin:
//
//   - lastloginmethod.WithCookieName(name string): Customize cookie name (default: "modular-auth.last_used_login_method").
//   - lastloginmethod.WithMaxAge(duration time.Duration): Cookie expiration lifetime (default: 30 days).
//   - lastloginmethod.WithCookieAttributes(domain, path string, sameSite http.SameSite, secure bool): Configure cookie attributes.
//   - lastloginmethod.WithStoreInDatabase(store bool): Enable or disable persisting last_login_method in User DB record.
//   - lastloginmethod.WithRouteMapping(pathPattern, method string): Add or override a path-to-method mapping rule.
//   - lastloginmethod.WithRouteMappings(routes map[string]string): Bulk configure custom path-to-method mapping rules.
//   - lastloginmethod.WithDisableDefaultRoutes(disable bool): Disable built-in route heuristics.
//   - lastloginmethod.WithCustomResolver(fn ResolveMethodFunc): Custom function to resolve login method from HTTP request.
//   - lastloginmethod.WithBeforeStoreCookie(fn BeforeStoreCookieFunc): GDPR consent check callback before issuing cookie.
//
// Example:
//
//	ctx := context.Background()
//	app, err := auth.New(
//		config.WithPlugins(
//			plugins.LastLoginMethod(
//				lastloginmethod.WithCookieName("modular-auth.last_used_login_method"),
//				lastloginmethod.WithMaxAge(30 * 24 * time.Hour),
//				lastloginmethod.WithRouteMapping("/custom/login", "custom-sso"),
//			),
//		),
//	)
//	if err != nil {
//		panic(err)
//	}
//
//	lastLoginPlugin := auth.Plugin[lastloginmethod.Plugin](app)
//	_ = lastLoginPlugin
func LastLoginMethod(opts ...lastloginmethod.Option) *lastloginmethod.Plugin {
	return lastloginmethod.New(opts...)
}

// LastLoginMethodWithRepository instantiates a new LastLoginMethod authentication plugin configured with a persistence repository and options.
//
// The LastLoginMethodWithRepository plugin automatically tracks the authentication method used by a user (e.g., email, google, github, passkey, magic-link, siwe),
// storing it in a client-readable browser cookie ("modular-auth.last_used_login_method" with HttpOnly=false) and persisting it to the User entity in database storage via the provided Repository.
//
// # Available Methods
//
//   - SetLastLoginMethod(ctx context.Context, w http.ResponseWriter, r *http.Request, userID, method string) (string, error): Explicitly record a user's last login method and persist to database.
//   - GetLastLoginMethod(ctx context.Context, r *http.Request, userID string) (string, error): Retrieve last used login method from HTTP request cookies or fallback to database lookup.
//   - ClearLastLoginMethod(ctx context.Context, w http.ResponseWriter): Expire the last login method cookie and emit event.
//   - Middleware() func(next http.Handler) http.Handler: Net/HTTP middleware to automatically intercept responses (2xx), resolve login method, update cookie, and persist to database.
//
// # Configuration Options
//
// You can pass functional options to customize the plugin:
//
//   - lastloginmethod.WithCookieName(name string): Customize cookie name (default: "modular-auth.last_used_login_method").
//   - lastloginmethod.WithMaxAge(duration time.Duration): Cookie expiration lifetime (default: 30 days).
//   - lastloginmethod.WithCookieAttributes(domain, path string, sameSite http.SameSite, secure bool): Configure cookie attributes.
//   - lastloginmethod.WithStoreInDatabase(store bool): Enable or disable persisting last_login_method in User DB record (default: true when repository provided).
//   - lastloginmethod.WithRouteMapping(pathPattern, method string): Add or override a path-to-method mapping rule.
//   - lastloginmethod.WithRouteMappings(routes map[string]string): Bulk configure custom path-to-method mapping rules.
//   - lastloginmethod.WithDisableDefaultRoutes(disable bool): Disable built-in route heuristics.
//   - lastloginmethod.WithCustomResolver(fn ResolveMethodFunc): Custom function to resolve login method from HTTP request.
//   - lastloginmethod.WithBeforeStoreCookie(fn BeforeStoreCookieFunc): GDPR consent check callback before issuing cookie.
//
// Example:
//
//	ctx := context.Background()
//	storage := memory.New()
//	app, err := auth.New(
//		config.WithPlugins(
//			plugins.LastLoginMethodWithRepository(
//				storage,
//				lastloginmethod.WithStoreInDatabase(true),
//				lastloginmethod.WithCookieName("modular-auth.last_used_login_method"),
//			),
//		),
//	)
//	if err != nil {
//		panic(err)
//	}
//
//	lastLoginPlugin := auth.Plugin[lastloginmethod.Plugin](app)
//	_ = lastLoginPlugin
func LastLoginMethodWithRepository(repo lastloginmethod.Repository, opts ...lastloginmethod.Option) *lastloginmethod.Plugin {
	return lastloginmethod.NewWithRepository(repo, opts...)
}

// Stripe instantiates a new Stripe billing & subscription authentication plugin configured with a mandatory repository and options.
//
// The Stripe plugin manages customer billing, checkout sessions, subscription lifecycles, seat-based billing for organizations,
// cryptographic webhook event verification (including checkout, subscription, and invoice payment events), and net/http middlewares.
//
// # Available Methods
//
//   - CreateCheckoutSession(ctx context.Context, params stripe.CreateCheckoutParams) (string, error): Create a Stripe Checkout session URL.
//   - UpgradeSubscription(ctx context.Context, params stripe.UpgradeSubscriptionParams) (*stripe.Subscription, error): Upgrade or downgrade plan or seat count.
//   - CancelSubscription(ctx context.Context, params stripe.CancelSubscriptionParams) (*stripe.Subscription, error): Cancel subscription immediately or at period end.
//   - RestoreSubscription(ctx context.Context, subID string) (*stripe.Subscription, error): Revoke scheduled cancellation.
//   - CreateBillingPortalSession(ctx context.Context, params stripe.BillingPortalParams) (string, error): Generate customer portal URL.
//   - GetSubscription(ctx context.Context, subID string) (*stripe.Subscription, error): Fetch local subscription record.
//   - ListSubscriptions(ctx context.Context, referenceID string) ([]*stripe.Subscription, error): List all subscriptions for a referenceId.
//   - SyncSeats(ctx context.Context, referenceID string, seats int) error: Update seat quantity in Stripe.
//   - ProcessWebhook(ctx context.Context, payload []byte, signature string) error: Process & verify raw Stripe webhooks.
//   - HandleWebhook(w http.ResponseWriter, r *http.Request): Net/HTTP handler for Stripe webhooks.
//   - WebhookHandler() http.Handler: Net/HTTP Handler instance for webhook routing.
//   - RequireActiveSubscription(allowedPlans ...string) func(http.Handler) http.Handler: Middleware requiring active subscription.
//   - AuthorizeReference(action string) func(http.Handler) http.Handler: Middleware authorizing referenceId access.
//
// # Configuration Options
//
// You can pass functional options to customize the plugin:
//
//   - stripe.WithStripeAPIKey(key string): Stripe secret API key used for initializing Stripe client.
//   - stripe.WithWebhookSecret(secret string): Secret key used to verify Stripe-Signature HTTP headers.
//   - stripe.WithCreateCustomerOnSignUp(enable bool): Automatically create Stripe Customer record during sign-up (default: true).
//   - stripe.WithPlans(plans ...stripe.StripePlan): Define static subscription plans available in the application.
//   - stripe.WithPlansFunc(fn stripe.PlansFunc): Set dynamic callback for resolving available subscription plans.
//   - stripe.WithAuthorizeReference(fn stripe.AuthorizeReferenceFunc): Configure callback to authorize referenceId access.
//   - stripe.WithOnSubscriptionCreated(fn stripe.SubscriptionCallbackFunc): Callback triggered when a subscription is created.
//   - stripe.WithOnSubscriptionUpdated(fn stripe.SubscriptionCallbackFunc): Callback triggered when a subscription state updates.
//   - stripe.WithOnSubscriptionDeleted(fn stripe.SubscriptionCallbackFunc): Callback triggered when a subscription is canceled or deleted.
//   - stripe.WithOnInvoicePaymentSucceeded(fn stripe.InvoiceCallbackFunc): Callback triggered when an invoice payment succeeds.
//   - stripe.WithOnInvoicePaymentFailed(fn stripe.InvoiceCallbackFunc): Callback triggered when an invoice payment fails.
//   - stripe.WithSeatPriceID(seatPriceID string): Configure organization seat-based billing with a specific Stripe Seat Price ID.
//
// Example:
//
//	ctx := context.Background()
//	storage := stripe.NewMemoryRepository()
//	app, err := auth.New(
//		config.WithPlugins(
//			plugins.Stripe(
//				storage,
//				stripe.WithStripeAPIKey("sk_test_..."),
//				stripe.WithWebhookSecret("whsec_..."),
//				stripe.WithPlans(stripe.StripePlan{
//					ID:      "pro_plan",
//					Name:    "Pro Plan",
//					PriceID: "price_12345",
//				}),
//			),
//		),
//	)
//	if err != nil {
//		panic(err)
//	}
//
//	stripePlugin := auth.Plugin[stripe.Plugin](app)
//	_ = stripePlugin
func Stripe(repo stripe.Repository, opts ...stripe.Option) (*stripe.Plugin, error) {
	return stripe.New(repo, opts...)
}

// Polar instantiates a new Polar billing, customer portal, usage metering, and webhook plugin configured with a mandatory repository and options.
//
// The Polar plugin manages customer billing, checkout sessions, customer portal sessions, subscription lifecycles,
// usage event ingestion, customer meter balances, benefit entitlements, cryptographic webhook event verification, and net/http middlewares.
//
// # Available Methods
//
//   - CreateCheckoutSession(ctx context.Context, params polar.CreateCheckoutParams) (string, error): Create a Polar Checkout session URL.
//   - CreateCustomerPortalSession(ctx context.Context, params polar.CustomerPortalParams) (string, error): Generate Customer Portal URL.
//   - GetCustomerState(ctx context.Context, referenceID string) (*polar.CustomerState, error): Retrieve customer billing and benefit state.
//   - ListSubscriptions(ctx context.Context, referenceID string) ([]*polar.Subscription, error): List subscriptions linked to a referenceId.
//   - GetSubscription(ctx context.Context, subID string) (*polar.Subscription, error): Fetch local subscription record.
//   - CancelSubscription(ctx context.Context, params polar.CancelSubscriptionParams) (*polar.Subscription, error): Cancel subscription.
//   - IngestEvent(ctx context.Context, params polar.IngestEventParams) (*polar.IngestEventResult, error): Ingest usage metrics event.
//   - ListMeters(ctx context.Context, referenceID string) ([]*polar.CustomerMeter, error): Fetch customer meter balances.
//   - SyncSeats(ctx context.Context, referenceID string, seats int) error: Update seat quantity for an active subscription.
//   - ProcessWebhook(ctx context.Context, payload []byte, signature string) error: Process & verify raw Polar webhooks.
//   - HandleWebhook(w http.ResponseWriter, r *http.Request): Net/HTTP handler for Polar webhooks.
//   - WebhookHandler() http.Handler: Net/HTTP Handler instance for webhook routing.
//   - RequireActiveSubscription(allowedPlans ...string) func(http.Handler) http.Handler: Middleware requiring active subscription.
//   - RequireBenefit(benefitID string) func(http.Handler) http.Handler: Middleware requiring granted benefit entitlement.
//   - AuthorizeReference(action string) func(http.Handler) http.Handler: Middleware authorizing referenceId access.
//
// # Configuration Options
//
// You can pass functional options to customize the plugin:
//
//   - polar.WithAccessToken(token string): Bearer access token for Polar API.
//   - polar.WithWebhookSecret(secret string): Secret key used to verify incoming webhook signatures.
//   - polar.WithServer(server string): Server environment ("production" or "sandbox").
//   - polar.WithCreateCustomerOnSignUp(enable bool): Automatically create Polar Customer record during sign-up (default: true).
//   - polar.WithPlans(plans ...polar.PolarPlan): Define static subscription plans available in the application.
//   - polar.WithPlansFunc(fn polar.PlansFunc): Set dynamic callback for resolving available subscription plans.
//   - polar.WithAuthorizeReference(fn polar.AuthorizeReferenceFunc): Configure callback to authorize referenceId access.
//   - polar.WithOnSubscriptionCreated(fn polar.SubscriptionCallbackFunc): Callback triggered when a subscription is created.
//   - polar.WithOnSubscriptionUpdated(fn polar.SubscriptionCallbackFunc): Callback triggered when a subscription state updates.
//   - polar.WithOnSubscriptionCanceled(fn polar.SubscriptionCallbackFunc): Callback triggered when a subscription is canceled.
//   - polar.WithOnCustomerStateChanged(fn polar.CustomerStateCallbackFunc): Callback triggered when customer state updates.
//   - polar.WithOnOrderPaid(fn polar.OrderCallbackFunc): Callback triggered when an order is paid.
//   - polar.WithOnBenefitGranted(fn polar.BenefitCallbackFunc): Callback triggered when a benefit is granted.
//   - polar.WithOnBenefitRevoked(fn polar.BenefitCallbackFunc): Callback triggered when a benefit is revoked.
//
// Example:
//
//	ctx := context.Background()
//	storage := polar.NewMemoryRepository()
//	app, err := auth.New(
//		config.WithPlugins(
//			plugins.Polar(
//				storage,
//				polar.WithAccessToken("polar_at_..."),
//				polar.WithWebhookSecret("whsec_..."),
//				polar.WithPlans(polar.PolarPlan{
//					ID:        "pro_plan",
//					Name:      "Pro Plan",
//					PriceID:   "price_12345",
//				}),
//			),
//		),
//	)
//	if err != nil {
//		panic(err)
//	}
//
//	polarPlugin := auth.Plugin[polar.Plugin](app)
//	_ = polarPlugin
func Polar(repo polar.Repository, opts ...polar.Option) (*polar.Plugin, error) {
	return polar.New(repo, opts...)
}

// Anonymous instantiates a new Anonymous (Guest Sessions) authentication plugin configured with optional Repository and functional options.
//
// The Anonymous plugin enables guest user workflows, allowing non-registered users to interact
// with the application under a temporary anonymous user profile (IsAnonymous = true). When the guest
// user eventually registers or signs in with a permanent account, the account linking hook (OnLinkAccount)
// is executed to transfer data (e.g. shopping carts, settings) before purging the temporary guest account.
//
// # Available Methods
//
//   - SignInAnonymous(ctx context.Context, currentSession *entity.Session, params SignInAnonymousParams) (*SignInAnonymousResult, error): Issue guest credentials and session.
//   - DeleteAnonymousUser(ctx context.Context, session *entity.Session) (*DeleteAnonymousUserResult, error): Purge guest user account and session data.
//   - LinkAccount(ctx context.Context, data *OnLinkAccountData) error: Execute custom linking callback and purge previous guest account if enabled.
//
// # Configuration Options
//
//   - anonymous.WithEmailDomainName(domain string): Custom domain suffix for temporary guest emails (default: "anonymous.local").
//   - anonymous.WithDisableDeleteAnonymousUser(disable bool): Toggle whether guest accounts should be retained after account linking.
//   - anonymous.WithOnLinkAccount(fn LinkAccountCallback): Callback triggered when linking a guest account to a permanent account.
//   - anonymous.WithGenerateName(fn GenerateNameCallback): Custom display name generator for guest users.
//   - anonymous.WithGenerateRandomEmail(fn GenerateEmailCallback): Custom email generator for guest users.
//
// Example:
//
//	ctx := context.Background()
//	storage := anonymous.NewMemoryRepository()
//	app, err := auth.New(
//		config.WithPlugins(
//			plugins.Anonymous(storage, anonymous.WithEmailDomainName("guest.myapp.com")),
//		),
//	)
//	if err != nil {
//		panic(err)
//	}
//
//	res, err := auth.Plugin[anonymous.Plugin](app).SignInAnonymous(ctx, nil, anonymous.SignInAnonymousParams{})
//	if err != nil {
//		panic(err)
//	}
//	_ = res
func Anonymous(repo anonymous.Repository, opts ...anonymous.Option) *anonymous.Plugin {
	return anonymous.NewWithRepository(repo, opts...)
}




