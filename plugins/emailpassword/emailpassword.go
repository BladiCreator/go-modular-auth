package emailpassword

import (
	"context"
	"errors"
	"time"

	"github.com/BladiCreator/go-modular-auth/domain/dto"
	"github.com/BladiCreator/go-modular-auth/domain/entity"
	"github.com/BladiCreator/go-modular-auth/plugin"
)

const (
	// PluginID is the unique string identifier for the EmailPassword plugin ("email-password").
	PluginID = "email-password"

	// CredentialProvider is the default provider key used for password-based accounts ("credential").
	CredentialProvider = "credential"
)

var (
	// ErrPasswordTooShort is returned when a password does not satisfy the configured minimum length requirement.
	ErrPasswordTooShort = errors.New("emailpassword: password does not meet the minimum length requirement")

	// ErrInvalidCredentials is returned when email or password verification fails during sign-in.
	ErrInvalidCredentials = errors.New("emailpassword: invalid credentials")

	// ErrEmailNotVerified is returned when sign-in is attempted by a user whose email has not been verified, and verification is required.
	ErrEmailNotVerified = errors.New("emailpassword: email address has not been verified")

	// ErrInvalidCurrentPass is returned during password change when the provided current password does not match stored credentials.
	ErrInvalidCurrentPass = errors.New("emailpassword: current password is incorrect")

	// ErrTokenExpired is returned when attempting to consume a verification or password reset token that has expired.
	ErrTokenExpired = errors.New("emailpassword: token has expired")
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
//   - repo: Implementation of emailpassword.Repository interface.
//   - opts: Optional functional configuration options (WithMinPasswordLength, WithRequireEmailVerification, WithResetTokenExpiry).
//
// Returns:
//   - *Plugin: The configured EmailPassword plugin instance ready for registration in auth.New.
func New(repo Repository, opts ...Option) *Plugin {
	cfg := defaultConfig()
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
//   Validates password constraints, ensures email uniqueness, securely hashes the password using bcrypt/argon2,
//   publishes the EventSignUpBefore event (enabling listeners to mutate parameters or inject dynamic metadata),
//   persists both the user entity and credential account, and finally publishes EventSignUpAfter.
//
// Function:
//   Primary entry point for user registration.
//
// Arguments:
//   - ctx: Request cancellation context.
//   - input: dto.SignUpParams containing:
//     - Email (string, required): User's primary email address.
//     - Password (string, required): Plaintext password to hash and validate.
//     - Name (string, optional): Display name of the user.
//     - Extra (map[string]any, optional): Dynamic metadata (e.g. role, organization, phone).
//
// Returns:
//   - *entity.User: The persisted user entity containing generated ID and timestamps.
//   - error: ErrPasswordTooShort, ErrUserAlreadyExists, or database error.
//
// Example:
//
//	user, err := epPlugin.SignUp(ctx, dto.SignUpParams{
//		Email:    "john.doe@example.com",
//		Password: "SuperSecretPassword123!",
//		Name:     "John Doe",
//	})
//	if err != nil {
//		log.Fatalf("Sign up failed: %v", err)
//	}
//	fmt.Printf("Created user with ID: %s\n", user.ID)
func (p *Plugin) SignUp(ctx context.Context, input dto.SignUpParams) (*entity.User, error) {
	if len(input.Password) < p.config.MinPasswordLength {
		return nil, ErrPasswordTooShort
	}

	existingUser, err := p.repo.GetUserByEmail(ctx, input.Email)
	if err == nil && existingUser != nil {
		return nil, ErrUserAlreadyExists
	}

	hashedPassword, err := p.ctx.Crypto().HashPassword(input.Password)
	if err != nil {
		return nil, err
	}

	params := &dto.CreateUserParams{
		Email:        input.Email,
		Name:         input.Name,
		PasswordHash: hashedPassword,
	}

	if p.ctx != nil && p.ctx.Events() != nil {
		p.ctx.Events().Publish(EventSignUpBefore, ctx, &SignUpEventPayload{Params: params})
	}

	newUser, err := p.repo.CreateUser(ctx, params)
	if err != nil {
		return nil, err
	}

	account := &entity.Account{
		UserID:   newUser.ID,
		Provider: CredentialProvider,
		Password: hashedPassword,
	}

	if err := p.repo.CreateAccount(ctx, account); err != nil {
		return nil, err
	}

	if p.ctx != nil && p.ctx.Events() != nil {
		p.ctx.Events().Publish(EventSignUpAfter, ctx, &SignUpEventPayload{Params: params, User: newUser})
	}
	return newUser, nil
}

// SignIn authenticates user credentials by verifying email existence and comparing the password hash.
//
// Brief Explanation:
//   Fetches the user and corresponding credentials account, securely verifies the password using constant-time
//   comparison, checks email verification prerequisites (if configured), and publishes EventSignInBefore and EventSignInAfter.
//
// Function:
//   Primary entry point for user login authentication.
//
// Arguments:
//   - ctx: Request cancellation context.
//   - input: dto.SignInParams containing:
//     - Email (string, required): User email address.
//     - Password (string, required): Plaintext password to compare against stored hash.
//
// Returns:
//   - *entity.User: The authenticated user profile.
//   - error: ErrInvalidCredentials, ErrEmailNotVerified, or database error.
//
// Example:
//
//	user, err := epPlugin.SignIn(ctx, dto.SignInParams{
//		Email:    "john.doe@example.com",
//		Password: "SuperSecretPassword123!",
//	})
//	if err != nil {
//		log.Fatalf("Authentication failed: %v", err)
//	}
func (p *Plugin) SignIn(ctx context.Context, input dto.SignInParams) (*entity.User, error) {
	user, err := p.repo.GetUserByEmail(ctx, input.Email)
	if err != nil || user == nil {
		return nil, ErrInvalidCredentials
	}

	account, err := p.repo.GetAccountByUserIDAndProvider(ctx, user.ID, CredentialProvider)
	if err != nil || account == nil {
		return nil, ErrInvalidCredentials
	}

	if !p.ctx.Crypto().ComparePassword(account.Password, input.Password) {
		return nil, ErrInvalidCredentials
	}

	if p.config.RequireEmailVerification && !user.EmailVerified {
		return nil, ErrEmailNotVerified
	}

	payload := &SignInEventPayload{User: user}
	if p.ctx != nil && p.ctx.Events() != nil {
		p.ctx.Events().Publish(EventSignInBefore, ctx, payload)
	}

	if p.ctx != nil && p.ctx.Events() != nil {
		p.ctx.Events().Publish(EventSignInAfter, ctx, payload)
	}
	return user, nil
}

// ChangePassword updates an existing authenticated user's password after verifying their current password.
//
// Brief Explanation:
//   Verifies the current password against stored credentials to prevent unauthorized modification,
//   enforces password length requirements, computes the new password hash, updates the database,
//   and emits EventPasswordChangeBefore and EventPasswordChangeAfter.
//
// Function:
//   User settings and self-service password update workflow.
//
// Arguments:
//   - ctx: Request cancellation context.
//   - input: dto.ChangePasswordParams containing:
//     - UserID (string, required): Authenticated user's unique identifier.
//     - CurrentPassword (string, required): Current password for authorization.
//     - NewPassword (string, required): New password to set.
//
// Returns:
//   - error: ErrPasswordTooShort, ErrAccountNotFound, ErrInvalidCurrentPass, or database error.
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
	if len(input.NewPassword) < p.config.MinPasswordLength {
		return ErrPasswordTooShort
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

	payload := &PasswordChangeEventPayload{UserID: input.UserID}
	if p.ctx != nil && p.ctx.Events() != nil {
		p.ctx.Events().Publish(EventPasswordChangeBefore, ctx, payload)
	}

	if err := p.repo.UpdateAccountPassword(ctx, account.ID, newHashedPassword); err != nil {
		return err
	}

	if p.ctx != nil && p.ctx.Events() != nil {
		p.ctx.Events().Publish(EventPasswordChangeAfter, ctx, payload)
	}
	return nil
}

// ForgotPassword initiates a tokenized password recovery workflow for a user.
//
// Brief Explanation:
//   Finds the user by email, generates a 32-byte cryptographically secure random token, persists the token
//   with an expiration timestamp, and publishes EventPasswordResetRequested so email/notification dispatchers
//   can send the recovery link to the user.
//
// Function:
//   Initial step of forgot-password and account recovery.
//
// Arguments:
//   - ctx: Request cancellation context.
//   - input: dto.ForgotPasswordParams containing:
//     - Email (string, required): User email address requesting reset.
//
// Returns:
//   - *entity.VerificationToken: The generated verification token entity (containing Token string and ExpiresAt).
//   - error: ErrUserNotFound or database error.
//
// Example:
//
//	token, err := epPlugin.ForgotPassword(ctx, dto.ForgotPasswordParams{
//		Email: "john.doe@example.com",
//	})
//	if err != nil {
//		log.Fatalf("Forgot password failed: %v", err)
//	}
//	fmt.Printf("Reset link token: %s (expires: %v)\n", token.Token, token.ExpiresAt)
func (p *Plugin) ForgotPassword(ctx context.Context, input dto.ForgotPasswordParams) (*entity.VerificationToken, error) {
	user, err := p.repo.GetUserByEmail(ctx, input.Email)
	if err != nil || user == nil {
		return nil, ErrUserNotFound
	}

	tokenStr, err := p.ctx.Crypto().GenerateRandomToken(32)
	if err != nil {
		return nil, err
	}

	expiresAt := time.Now().Add(p.config.ResetTokenExpiry)
	token := &entity.VerificationToken{
		Identifier: user.Email,
		Token:      tokenStr,
		ExpiresAt:  expiresAt,
	}

	if err := p.repo.CreateVerificationToken(ctx, token); err != nil {
		return nil, err
	}

	if p.ctx != nil && p.ctx.Events() != nil {
		p.ctx.Events().Publish(EventPasswordResetRequested, ctx, &PasswordResetRequestedEventPayload{
			User:      user,
			Token:     tokenStr,
			ExpiresAt: expiresAt,
		})
	}

	return token, nil
}

// ResetPassword completes a password reset by consuming a single-use token and setting a new password.
//
// Brief Explanation:
//   Validates token existence and expiry, hashes the new password, updates the user's credential account,
//   atomically deletes the consumed token to guarantee single-use safety, and emits EventPasswordResetCompleted.
//
// Function:
//   Final step of forgot-password and recovery verification.
//
// Arguments:
//   - ctx: Request cancellation context.
//   - input: dto.ResetPasswordParams containing:
//     - Token (string, required): Single-use recovery token from email.
//     - NewPassword (string, required): New password to set.
//
// Returns:
//   - error: ErrPasswordTooShort, ErrInvalidToken, ErrTokenExpired, ErrUserNotFound, or database error.
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
	if len(input.NewPassword) < p.config.MinPasswordLength {
		return ErrPasswordTooShort
	}

	tokenRecord, err := p.repo.GetVerificationToken(ctx, input.Token)
	if err != nil || tokenRecord == nil {
		return ErrInvalidToken
	}

	if time.Now().After(tokenRecord.ExpiresAt) {
		_ = p.repo.DeleteVerificationToken(ctx, input.Token)
		return ErrTokenExpired
	}

	user, err := p.repo.GetUserByEmail(ctx, tokenRecord.Identifier)
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

	_ = p.repo.DeleteVerificationToken(ctx, input.Token)

	if p.ctx != nil && p.ctx.Events() != nil {
		p.ctx.Events().Publish(EventPasswordResetCompleted, ctx, &PasswordResetCompletedEventPayload{
			UserID: user.ID,
		})
	}

	return nil
}
