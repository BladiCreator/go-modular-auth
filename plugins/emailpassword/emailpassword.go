package emailpassword

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/mail"
	"strings"
	"time"

	"github.com/BladiCreator/go-modular-auth/domain/dto"
	"github.com/BladiCreator/go-modular-auth/domain/entity"
	"github.com/BladiCreator/go-modular-auth/domain/repository"
	"github.com/BladiCreator/go-modular-auth/plugin"
	"golang.org/x/crypto/bcrypt"
	"uuid"
)

// SessionOption represents a functional option for configuring session creation on SignIn.
type SessionOption = plugin.SessionOption

// Functional option constructors for configuring session creation.
var (
	WithDuration   = plugin.WithDuration
	WithRememberMe = plugin.WithRememberMe
	WithIPAddress  = plugin.WithIPAddress
	WithUserAgent  = plugin.WithUserAgent
	WithDeviceID   = plugin.WithDeviceID
	WithExtra      = plugin.WithExtra
	WithExtraMap   = plugin.WithExtraMap
)

// ErrSessionManagerRequired is returned when sign-in attempts to create a session without an active SessionManager in context.
var ErrSessionManagerRequired = plugin.ErrSessionManagerRequired

const (
	// PluginID is the unique string identifier for the EmailPassword plugin ("email-password").
	PluginID = "email-password"

	// CredentialProvider is the provider key used for password-based accounts ("credential").
	CredentialProvider = "credential"
)

// Plugin implements the modular authentication Plugin interface for credential-based email and password workflows.
type Plugin struct {
	repo   Repository
	config Config
	ctx    *plugin.Context
}

// New creates and initializes a new EmailPassword plugin instance with the specified repository and functional options.
//
// Arguments:
//   - repo: Implementation of the emailpassword.Repository storage interface.
//   - opts: Optional functional configuration options (WithMinPasswordLength, WithRequireEmailVerification, etc.).
//
// Returns:
//   - *Plugin: The configured EmailPassword plugin instance ready for registration in auth.New.
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

// ID returns the unique identifier for the plugin ("email-password").
func (p *Plugin) ID() string {
	return PluginID
}

// Init initializes the plugin within the global GoModularAuth runtime context.
func (p *Plugin) Init(ctx *plugin.Context) error {
	p.ctx = ctx
	return nil
}

// SignUp registers a new user with email and password credentials.
//
// Brief Explanation:
//
//	Validates email and password constraints, ensures email uniqueness, securely hashes the password,
//	publishes the EventSignUpBefore event (enabling listeners to mutate parameters or inject dynamic metadata),
//	persists both the user entity and credential account, optionally dispatches email verification, and publishes EventSignUpAfter.
//
// Function:
//
//	Primary entry point for user registration.
//
// Arguments:
//   - ctx: Request cancellation context.
//   - input: dto.SignUpParams containing:
//   - Name (string, required): Display name of the user.
//   - Email (string, required): User's primary email address.
//   - Password (string, required): Plaintext password to hash and validate.
//   - Extra (map[string]any, optional): Dynamic metadata (e.g. role, organization, phone).
//
// Returns:
//   - *entity.User: The persisted user entity containing generated ID and timestamps.
//   - error: ErrInvalidEmail, ErrPasswordTooShort, ErrPasswordTooLong, ErrUserAlreadyExists, or database error.
//
// Example:
//
//	user, err := epPlugin.SignUp(ctx, dto.SignUpParams{
//		Name:     "John Doe",
//		Email:    "john.doe@example.com",
//		Password: "SuperSecretPassword123!",
//	})
//	if err != nil {
//		log.Fatalf("Sign up failed: %v", err)
//	}
//	fmt.Printf("Created user with ID: %s\n", user.ID)
func (p *Plugin) SignUp(ctx context.Context, input dto.SignUpParams) (*entity.User, error) {
	email := strings.ToLower(strings.TrimSpace(input.Email))
	if !isValidEmail(email) {
		return nil, ErrInvalidEmail
	}

	if len(input.Password) < p.config.MinPasswordLength {
		return nil, ErrPasswordTooShort
	}
	if p.config.MaxPasswordLength > 0 && len(input.Password) > p.config.MaxPasswordLength {
		return nil, ErrPasswordTooLong
	}

	// 1. Run BeforeSignUp interceptors (can abort or mutate input.Extra/input fields)
	if p.ctx != nil && p.ctx.Pipeline() != nil {
		if err := p.ctx.Pipeline().ExecuteBeforeSignUp(ctx, &input); err != nil {
			return nil, err
		}
	}
	email = strings.ToLower(strings.TrimSpace(input.Email))

	existingUser, err := p.repo.GetUserByEmail(ctx, email)
	if err == nil && existingUser != nil {
		return nil, ErrUserAlreadyExists
	}

	hashedPassword, err := p.ctx.Crypto().HashPassword(input.Password)
	if err != nil {
		return nil, err
	}

	params := &dto.CreateUserParams{
		Email:           email,
		Name:            input.Name,
		PasswordHash:    hashedPassword,
		Role:            input.Role,
		Username:        input.Username,
		DisplayUsername: input.DisplayUsername,
		PhoneNumber:     input.PhoneNumber,
		Extra:           input.Extra,
	}

	if p.ctx != nil && p.ctx.Hooks() != nil {
		p.ctx.Hooks().Publish(EventSignUpBefore, ctx, &SignUpEventPayload{
			Params: params,
		})
	}

	newUser, err := p.repo.CreateUser(ctx, params)
	if err != nil {
		return nil, err
	}

	accountParams := &dto.CreateAccountParams{
		UserID:   newUser.ID,
		Provider: CredentialProvider,
		Password: hashedPassword,
	}

	if err := p.repo.CreateAccount(ctx, accountParams); err != nil {
		return nil, err
	}

	if p.config.SendVerificationOnSignUp {
		_, _ = p.SendVerificationEmail(ctx, dto.SendVerificationEmailParams{
			Email: newUser.Email,
		})
	}

	// 2. Run AfterSignUp interceptors
	if p.ctx != nil && p.ctx.Pipeline() != nil {
		if err := p.ctx.Pipeline().ExecuteAfterSignUp(ctx, newUser); err != nil {
			return nil, err
		}
	}

	// 3. Dispatch typed lifecycle hooks and EventSignUpAfter
	if p.ctx != nil && p.ctx.Hooks() != nil {
		p.ctx.Hooks().Publish(EventSignUpAfter, ctx, &SignUpEventPayload{
			Params: params,
			User:   newUser,
		})
		p.ctx.Hooks().DispatchUserSignedUp(ctx, newUser)
	}

	return newUser, nil
}

// VerifyCredentials validates user credentials by checking email existence and password hash
// without creating or emitting an active authentication session.
//
// Brief Explanation:
//
//	Verifies user identity for headless checks, re-authentication challenges, or step-up flows.
//	Mitigates timing attacks and user enumeration with constant-time password hashing if the user does not exist.
//
// Function:
//
//	Validates credentials without session side-effects.
//
// Arguments:
//   - ctx: Request cancellation context.
//   - email: User email address.
//   - password: User plaintext password to verify.
//
// Returns:
//   - *entity.User: The matching user entity if credentials are valid.
//   - error: ErrInvalidCredentials, ErrEmailNotVerified, or database error.
func (p *Plugin) VerifyCredentials(ctx context.Context, email, password string) (*entity.User, error) {
	normEmail := strings.ToLower(strings.TrimSpace(email))
	if normEmail == "" || password == "" {
		return nil, ErrInvalidCredentials
	}

	user, err := p.repo.GetUserByEmail(ctx, normEmail)
	if err != nil || user == nil {
		p.fakeHash(password)
		return nil, ErrInvalidCredentials
	}

	account, err := p.repo.GetAccountByUserIDAndProvider(ctx, user.ID, CredentialProvider)
	if err != nil || account == nil || account.Password == "" {
		p.fakeHash(password)
		return nil, ErrInvalidCredentials
	}

	if !p.comparePassword(account.Password, password) {
		return nil, ErrInvalidCredentials
	}

	if p.config.RequireEmailVerification && !user.EmailVerified {
		return nil, ErrEmailNotVerified
	}

	return user, nil
}

// SignIn authenticates user credentials, creates an active session via the central SessionManager, and returns SessionData.
//
// Brief Explanation:
//
//	Fetches the user and corresponding credentials account, securely verifies the password using constant-time
//	comparison, checks email verification prerequisites (if configured), emits a cryptographically secure session
//	through the core SessionManager, and publishes EventSignInBefore and EventSignInAfter.
//	Mitigates timing attacks and user enumeration by executing a constant-time fake password hash if the user does not exist.
//
// Function:
//
//	Primary entry point for user login authentication.
//
// Arguments:
//   - ctx: Request cancellation context.
//   - input: dto.SignInParams containing:
//   - Email (string, required): User email address.
//   - Password (string, required): Plaintext password to compare against stored hash.
//   - Extra (map[string]any, optional): Dynamic metadata passed through event interceptors.
//   - opts: Optional functional session options (WithRememberMe, WithIPAddress, WithUserAgent, WithDuration, etc.).
//
// Returns:
//   - *dto.AuthResult: Combined authenticated user profile and active session (or pending MFA challenge).
//   - error: ErrInvalidCredentials, ErrEmailNotVerified, ErrSessionManagerRequired, or database error.
//
// Example:
//
//	authRes, err := epPlugin.SignIn(ctx, dto.SignInParams{
//		Email:    "john.doe@example.com",
//		Password: "SuperSecretPassword123!",
//	})
//	if err != nil {
//		log.Fatalf("Authentication failed: %v", err)
//	}
//	if authRes.RequiresChallenge() {
//		fmt.Printf("MFA required: token=%s\n", authRes.Challenge().TempToken)
//	} else {
//		fmt.Printf("Authenticated as: %s (Session Token: %s)\n", authRes.User.Name, authRes.Session.Token)
//	}
func (p *Plugin) SignIn(ctx context.Context, input dto.SignInParams, opts ...plugin.SessionOption) (*dto.AuthResult, error) {
	email := strings.ToLower(strings.TrimSpace(input.Email))
	if email == "" || input.Password == "" {
		return nil, ErrInvalidCredentials
	}

	// 1. Extract per-call session options to pass interceptors to pipeline
	optsData := plugin.SessionOptions{}
	for _, opt := range opts {
		opt(&optsData)
	}

	// 2. Run BeforeSignIn interceptors BEFORE checking credentials or touching database!
	// This enables immediate abort for ErrUserBanned, ErrTenantInactive, rate limiting, etc.
	if p.ctx != nil && p.ctx.Pipeline() != nil {
		if err := p.ctx.Pipeline().ExecuteBeforeSignIn(ctx, &input, optsData.Interceptors...); err != nil {
			return nil, err // Abort immediately!
		}
	}
	email = strings.ToLower(strings.TrimSpace(input.Email))

	user, err := p.repo.GetUserByEmail(ctx, email)
	if err != nil || user == nil {
		// Timing attack mitigation: compute fake hash to maintain constant-time response
		p.fakeHash(input.Password)
		return nil, ErrInvalidCredentials
	}

	payload := &SignInEventPayload{
		User:  user,
		Extra: optsData.Extra,
	}

	if p.ctx != nil && p.ctx.Hooks() != nil {
		p.ctx.Hooks().Publish(EventSignInBefore, ctx, payload)
	}

	account, err := p.repo.GetAccountByUserIDAndProvider(ctx, user.ID, CredentialProvider)
	if err != nil || account == nil || account.Password == "" {
		p.fakeHash(input.Password)
		return nil, ErrInvalidCredentials
	}

	if !p.comparePassword(account.Password, input.Password) {
		return nil, ErrInvalidCredentials
	}

	if p.config.RequireEmailVerification && !user.EmailVerified {
		return nil, ErrEmailNotVerified
	}

	// 3. Step-Up / Multi-Factor Authentication (MFA) Check
	if p.ctx != nil && p.ctx.MFAProvider() != nil {
		mfa := p.ctx.MFAProvider()
		requiresMFA, err := mfa.RequiresMFA(ctx, user.ID, optsData.Extra)
		if err != nil {
			return nil, fmt.Errorf("emailpassword: failed to evaluate 2FA: %w", err)
		}
		if requiresMFA {
			challenge, err := mfa.CreateMFAChallenge(ctx, user.ID, "totp")
			if err != nil {
				return nil, fmt.Errorf("emailpassword: failed to create 2FA challenge: %w", err)
			}
			return dto.NewAuthResultChallenge(challenge), nil
		}
	}

	if p.ctx == nil || p.ctx.Session() == nil {
		return nil, ErrSessionManagerRequired
	}

	sess, err := p.ctx.Session().CreateSession(ctx, user.ID, opts...)
	if err != nil {
		return nil, fmt.Errorf("emailpassword: failed to create session: %w", err)
	}

	sessionData := &dto.SessionData{
		Session: sess,
		User:    user,
	}

	// 4. Run AfterSignIn interceptors (allows mutating sessionData.Session.Extra or aborting)
	if p.ctx != nil && p.ctx.Pipeline() != nil {
		if err := p.ctx.Pipeline().ExecuteAfterSignIn(ctx, sessionData, optsData.Interceptors...); err != nil {
			_ = p.ctx.Session().RevokeSession(ctx, sess.Token)
			return nil, err
		}
	}

	payload.Session = sess
	if p.ctx != nil && p.ctx.Hooks() != nil {
		p.ctx.Hooks().Publish(EventSignInAfter, ctx, payload)
		p.ctx.Hooks().DispatchUserSignedIn(ctx, sessionData)
	}

	return dto.NewAuthResultCompleted(sessionData), nil
}

// ChangePassword updates an existing authenticated user's password after verifying their current password.
//
// Brief Explanation:
//
//	Verifies the current password against stored credentials to prevent unauthorized modification,
//	enforces password length requirements, computes the new password hash, updates storage,
//	and emits EventPasswordChangeBefore and EventPasswordChangeAfter.
//
// Function:
//
//	User settings and self-service password update workflow.
//
// Arguments:
//   - ctx: Request cancellation context.
//   - input: dto.ChangePasswordParams containing:
//   - UserID (string, required): Authenticated user's unique identifier.
//   - CurrentPassword (string, required): Current password for authorization.
//   - NewPassword (string, required): New password to set.
//   - Extra (map[string]any, optional): Dynamic metadata.
//
// Returns:
//   - error: ErrPasswordTooShort, ErrPasswordTooLong, ErrAccountNotFound, ErrInvalidCurrentPass, or database error.
//
// Example:
//
//	err := epPlugin.ChangePassword(ctx, dto.ChangePasswordParams{
//		UserID:          "usr_12345",
//		CurrentPassword: "OldPassword123!",
//		NewPassword:     "NewBrandPassword456!",
//	})
//	if err != nil {
//		log.Fatalf("Password change failed: %v", err)
//	}
func (p *Plugin) ChangePassword(ctx context.Context, input dto.ChangePasswordParams) error {
	if input.UserID == "" {
		return ErrInvalidParameter
	}

	if len(input.NewPassword) < p.config.MinPasswordLength {
		return ErrPasswordTooShort
	}
	if p.config.MaxPasswordLength > 0 && len(input.NewPassword) > p.config.MaxPasswordLength {
		return ErrPasswordTooLong
	}

	account, err := p.repo.GetAccountByUserIDAndProvider(ctx, input.UserID, CredentialProvider)
	if err != nil || account == nil {
		return ErrAccountNotFound
	}

	if !p.ctx.Crypto().ComparePassword(account.Password, input.CurrentPassword) {
		return ErrInvalidCurrentPass
	}

	newHashedPassword, err := p.ctx.Crypto().HashPassword(input.NewPassword)
	if err != nil {
		return err
	}

	payload := &PasswordChangeEventPayload{
		UserID: input.UserID,
	}

	if p.ctx != nil && p.ctx.Hooks() != nil {
		p.ctx.Hooks().Publish(EventPasswordChangeBefore, ctx, payload)
	}

	if err := p.repo.UpdateAccountPassword(ctx, account.ID, newHashedPassword); err != nil {
		return err
	}

	if p.ctx != nil && p.ctx.Hooks() != nil {
		p.ctx.Hooks().Publish(EventPasswordChangeAfter, ctx, payload)
		user, _ := p.repo.GetUserByID(ctx, input.UserID)
		if user == nil {
			user = &entity.User{ID: input.UserID}
		}
		p.ctx.Hooks().DispatchPasswordChanged(ctx, user)
	}

	return nil
}

// ForgotPassword initiates a tokenized password recovery workflow for a user.
//
// Brief Explanation:
//
//	Finds the user by email, generates a 32-byte cryptographically secure random token, persists the token
//	with an expiration timestamp, invokes the SendResetPasswordEmail callback (if configured), and publishes EventPasswordResetRequested.
//
// Function:
//
//	Initial step of forgot-password and account recovery.
//
// Arguments:
//   - ctx: Request cancellation context.
//   - input: dto.ForgotPasswordParams containing:
//   - Email (string, required): User email address requesting reset.
//   - Extra (map[string]any, optional): Dynamic metadata.
//
// Returns:
//   - *entity.Verification: The generated verification entity (containing Identifier token string, Value email, and ExpiresAt).
//   - error: ErrInvalidEmail, ErrUserNotFound, or database error.
//
// Example:
//
//	token, err := epPlugin.ForgotPassword(ctx, dto.ForgotPasswordParams{
//		Email: "john.doe@example.com",
//	})
//	if err != nil {
//		log.Fatalf("Forgot password failed: %v", err)
//	}
//	fmt.Printf("Reset token generated: %s (expires at %v)\n", token.Identifier, token.ExpiresAt)
func (p *Plugin) ForgotPassword(ctx context.Context, input dto.ForgotPasswordParams) (*entity.Verification, error) {
	email := strings.ToLower(strings.TrimSpace(input.Email))
	if !isValidEmail(email) {
		return nil, ErrInvalidEmail
	}

	user, err := p.repo.GetUserByEmail(ctx, email)
	if err != nil || user == nil {
		return nil, ErrUserNotFound
	}

	tokenStr, err := p.ctx.Crypto().GenerateRandomToken(32)
	if err != nil {
		return nil, err
	}

	expiresAt := time.Now().Add(p.config.ResetTokenExpiry)
	verification := &entity.Verification{
		ID:         uuid.NewV7().String(),
		Identifier: tokenStr,
		Value:      user.Email,
		ExpiresAt:  expiresAt,
		CreatedAt:  time.Now(),
	}

	if err := p.repo.CreateVerification(ctx, verification); err != nil {
		return nil, err
	}

	if p.ctx != nil {
		p.ctx.Set(ResetTokenContextKey(tokenStr), user.ID)
	}

	if p.config.SendResetPasswordEmail != nil {
		extra := maps.Clone(input.Extra)
		if extra == nil && input.RedirectTo != "" {
			extra = make(map[string]any)
		}
		if input.RedirectTo != "" {
			extra["redirectTo"] = input.RedirectTo
		}
		_ = p.config.SendResetPasswordEmail(ctx, user.Email, tokenStr, expiresAt, extra)
	}

	if p.ctx != nil && p.ctx.Hooks() != nil {
		p.ctx.Hooks().Publish(EventPasswordResetRequested, ctx, &PasswordResetRequestedEventPayload{
			User:      user,
			Token:     tokenStr,
			ExpiresAt: expiresAt,
		})
		p.ctx.Hooks().DispatchPasswordResetRequested(ctx, user.Email, verification)
	}

	return verification, nil
}

// ResetPassword completes a password reset by consuming a single-use token and setting a new password.
//
// Brief Explanation:
//
//	Validates token existence and expiry, hashes the new password, updates the user's credential account,
//	atomically deletes the consumed token to guarantee single-use safety, and emits EventPasswordResetCompleted.
//
// Function:
//
//	Final step of forgot-password and recovery verification.
//
// Arguments:
//   - ctx: Request cancellation context.
//   - input: dto.ResetPasswordParams containing:
//   - Token (string, required): Single-use recovery token from email.
//   - NewPassword (string, required): New password to set.
//   - Extra (map[string]any, optional): Dynamic metadata.
//
// Returns:
//   - error: ErrInvalidParameter, ErrPasswordTooShort, ErrPasswordTooLong, ErrInvalidToken, ErrTokenExpired, ErrUserNotFound, or database error.
//
// Example:
//
//	err := epPlugin.ResetPassword(ctx, dto.ResetPasswordParams{
//		Token:       "9a8b7c6d5e4f3a2b1c0d",
//		NewPassword: "BrandNewSecurePassword123!",
//	})
//	if err != nil {
//		log.Fatalf("Password reset failed: %v", err)
//	}
func (p *Plugin) ResetPassword(ctx context.Context, input dto.ResetPasswordParams) error {
	if input.Token == "" {
		return ErrInvalidParameter
	}

	if len(input.NewPassword) < p.config.MinPasswordLength {
		return ErrPasswordTooShort
	}
	if p.config.MaxPasswordLength > 0 && len(input.NewPassword) > p.config.MaxPasswordLength {
		return ErrPasswordTooLong
	}

	verification, err := p.repo.ConsumeVerification(ctx, input.Token)
	if err != nil || verification == nil {
		if errors.Is(err, repository.ErrVerificationExpired) {
			return ErrTokenExpired
		}
		return ErrInvalidToken
	}

	if time.Now().After(verification.ExpiresAt) {
		return ErrTokenExpired
	}

	user, err := p.repo.GetUserByEmail(ctx, verification.Value)
	if err != nil || user == nil {
		return ErrUserNotFound
	}

	account, err := p.repo.GetAccountByUserIDAndProvider(ctx, user.ID, CredentialProvider)
	if err != nil || account == nil {
		return ErrAccountNotFound
	}

	newHashedPassword, err := p.ctx.Crypto().HashPassword(input.NewPassword)
	if err != nil {
		return err
	}

	if err := p.repo.UpdateAccountPassword(ctx, account.ID, newHashedPassword); err != nil {
		return err
	}

	if p.ctx != nil && p.ctx.Hooks() != nil {
		p.ctx.Hooks().Publish(EventPasswordResetCompleted, ctx, &PasswordResetCompletedEventPayload{
			UserID: user.ID,
		})
		p.ctx.Hooks().DispatchPasswordResetCompleted(ctx, user.ID)
	}

	return nil
}

// SendVerificationEmail generates and dispatches an email verification token to the user.
//
// Brief Explanation:
//
//	Looks up the user by email, generates a cryptographically secure verification token with expiration,
//	persists it in storage, executes the SendVerificationEmail callback (if registered), and emits EventEmailVerificationRequested.
//
// Function:
//
//	Initiates the email verification workflow.
//
// Arguments:
//   - ctx: Request cancellation context.
//   - input: dto.SendVerificationEmailParams containing:
//   - Email (string, required): Target user email address.
//   - Extra (map[string]any, optional): Dynamic metadata.
//
// Returns:
//   - *entity.Verification: The generated verification entity.
//   - error: ErrInvalidEmail, ErrUserNotFound, or database error.
//
// Example:
//
//	token, err := epPlugin.SendVerificationEmail(ctx, dto.SendVerificationEmailParams{
//		Email: "john.doe@example.com",
//	})
//	if err != nil {
//		log.Fatalf("Send verification failed: %v", err)
//	}
//	fmt.Printf("Verification token: %s\n", token.Identifier)
func (p *Plugin) SendVerificationEmail(ctx context.Context, input dto.SendVerificationEmailParams) (*entity.Verification, error) {
	email := strings.ToLower(strings.TrimSpace(input.Email))
	if !isValidEmail(email) {
		return nil, ErrInvalidEmail
	}

	user, err := p.repo.GetUserByEmail(ctx, email)
	if err != nil || user == nil {
		return nil, ErrUserNotFound
	}

	tokenStr, err := p.ctx.Crypto().GenerateRandomToken(32)
	if err != nil {
		return nil, err
	}

	expiresAt := time.Now().Add(p.config.VerificationTokenExpiry)
	verification := &entity.Verification{
		ID:         uuid.NewV7().String(),
		Identifier: tokenStr,
		Value:      user.Email,
		ExpiresAt:  expiresAt,
		CreatedAt:  time.Now(),
	}

	if err := p.repo.CreateVerification(ctx, verification); err != nil {
		return nil, err
	}

	if p.ctx != nil {
		p.ctx.Set(VerificationTokenContextKey(tokenStr), user.ID)
	}

	if p.config.SendVerificationEmail != nil {
		extra := maps.Clone(input.Extra)
		if extra == nil && input.CallbackURL != "" {
			extra = make(map[string]any)
		}
		if input.CallbackURL != "" {
			extra["callbackURL"] = input.CallbackURL
		}
		_ = p.config.SendVerificationEmail(ctx, user.Email, tokenStr, expiresAt, extra)
	}

	if p.ctx != nil && p.ctx.Hooks() != nil {
		p.ctx.Hooks().Publish(EventEmailVerificationRequested, ctx, &EmailVerificationRequestedEventPayload{
			User:      user,
			Token:     tokenStr,
			ExpiresAt: expiresAt,
		})
		p.ctx.Hooks().DispatchEmailVerificationRequested(ctx, user.Email, verification)
	}

	return verification, nil
}

// VerifyEmail completes the email confirmation process by consuming a valid verification token.
//
// Brief Explanation:
//
//	Validates token existence and expiry, marks user.EmailVerified as true in persistent storage,
//	deletes the consumed single-use token, and emits EventEmailVerified.
//
// Function:
//
//	Completes the email confirmation process.
//
// Arguments:
//   - ctx: Request cancellation context.
//   - input: dto.VerifyEmailParams containing:
//   - Token (string, required): Single-use verification token from email link.
//   - Extra (map[string]any, optional): Dynamic metadata.
//
// Returns:
//   - *entity.User: The updated user entity with EmailVerified set to true.
//   - error: ErrInvalidParameter, ErrInvalidToken, ErrTokenExpired, ErrUserNotFound, or database error.
//
// Example:
//
//	verifiedUser, err := epPlugin.VerifyEmail(ctx, dto.VerifyEmailParams{
//		Token: "abc123token456",
//	})
//	if err != nil {
//		log.Fatalf("Email verification failed: %v", err)
//	}
//	fmt.Printf("User %s email verified: %v\n", verifiedUser.Email, verifiedUser.EmailVerified)
func (p *Plugin) VerifyEmail(ctx context.Context, input dto.VerifyEmailParams) (*entity.User, error) {
	if input.Token == "" {
		return nil, ErrInvalidParameter
	}

	verification, err := p.repo.ConsumeVerification(ctx, input.Token)
	if err != nil || verification == nil {
		if errors.Is(err, repository.ErrVerificationExpired) {
			return nil, ErrTokenExpired
		}
		return nil, ErrInvalidToken
	}

	if time.Now().After(verification.ExpiresAt) {
		return nil, ErrTokenExpired
	}

	user, err := p.repo.GetUserByEmail(ctx, verification.Value)
	if err != nil || user == nil {
		return nil, ErrUserNotFound
	}

	user.EmailVerified = true
	if err := p.repo.UpdateUser(ctx, user); err != nil {
		return nil, err
	}

	if p.ctx != nil && p.ctx.Hooks() != nil {
		p.ctx.Hooks().Publish(EventEmailVerified, ctx, &EmailVerifiedEventPayload{
			User: user,
		})
		p.ctx.Hooks().DispatchEmailVerified(ctx, user)
	}

	return user, nil
}

// VerifyPassword validates whether the provided password matches the user's stored credential password.
//
// Brief Explanation:
//
//	Fetches the user's credential account and performs constant-time password comparison.
//	Useful for high-security operations (e.g. 2FA enrollment, modifying sensitive account settings).
//
// Function:
//
//	Credential verification and re-authentication check.
//
// Arguments:
//   - ctx: Request cancellation context.
//   - input: dto.VerifyPasswordParams containing:
//   - UserID (string, required): User ID to verify.
//   - Password (string, required): Plaintext password to check.
//   - Extra (map[string]any, optional): Dynamic metadata.
//
// Returns:
//   - bool: True if password matches, false otherwise.
//   - error: ErrInvalidParameter, ErrAccountNotFound, or database error.
//
// Example:
//
//	valid, err := epPlugin.VerifyPassword(ctx, dto.VerifyPasswordParams{
//		UserID:   "usr_12345",
//		Password: "CurrentPassword123!",
//	})
//	if err != nil || !valid {
//		log.Println("Password verification failed")
//	}
func (p *Plugin) VerifyPassword(ctx context.Context, input dto.VerifyPasswordParams) (bool, error) {
	if input.UserID == "" || input.Password == "" {
		return false, ErrInvalidParameter
	}

	account, err := p.repo.GetAccountByUserIDAndProvider(ctx, input.UserID, CredentialProvider)
	if err != nil || account == nil {
		return false, ErrAccountNotFound
	}

	valid := p.comparePassword(account.Password, input.Password)
	return valid, nil
}

// comparePassword securely verifies a password hash using context CryptoUtils or bcrypt fallback.
func (p *Plugin) comparePassword(hash, password string) bool {
	if p.ctx != nil && p.ctx.Crypto() != nil {
		return p.ctx.Crypto().ComparePassword(hash, password)
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

// fakeHash computes a dummy password hash to maintain constant response times against timing attacks.
func (p *Plugin) fakeHash(password string) {
	if p.ctx != nil && p.ctx.Crypto() != nil {
		_, _ = p.ctx.Crypto().HashPassword(password)
	} else {
		_, _ = bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	}
}

// isValidEmail checks whether the provided string is a valid email address.
func isValidEmail(email string) bool {
	if len(email) < 3 || len(email) > 254 {
		return false
	}
	_, err := mail.ParseAddress(email)
	return err == nil
}
