package emailotp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/mail"
	"strings"
	"time"

	"github.com/BladiCreator/go-modular-auth/domain/dto"
	"github.com/BladiCreator/go-modular-auth/domain/entity"
	"github.com/BladiCreator/go-modular-auth/plugin"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// PluginID is the unique string identifier for the Email OTP plugin ("email-otp").
const PluginID = "email-otp"

// Parameter and Result Structs
type (
	// SendVerificationOTPParams defines parameters required to dispatch an OTP to a user's email.
	SendVerificationOTPParams struct {
		// Email is the destination recipient email address (required).
		Email string `json:"email"`

		// Type specifies the OTP workflow type ("email-verification", "sign-in", "forget-password", "change-email").
		Type OTPType `json:"type"`

		// Extra holds dynamic metadata passed through event interceptors (optional).
		Extra map[string]any `json:"extra,omitempty"`
	}

	// SendVerificationOTPResult contains the delivery status and expiry of the dispatched OTP.
	SendVerificationOTPResult struct {
		// Success indicates if the OTP was successfully generated and dispatched.
		Success bool `json:"success"`

		// ExpiresAt indicates when the dispatched OTP code will expire.
		ExpiresAt time.Time `json:"expires_at"`
	}

	// CreateVerificationOTPParams defines parameters for server-side OTP generation without email dispatch.
	CreateVerificationOTPParams struct {
		// Email is the target email address.
		Email string `json:"email"`

		// Type specifies the OTP workflow type.
		Type OTPType `json:"type"`

		// Extra holds optional dynamic metadata.
		Extra map[string]any `json:"extra,omitempty"`
	}

	// GetVerificationOTPParams defines parameters for server-side inspection of an active OTP code.
	GetVerificationOTPParams struct {
		// Email is the target email address.
		Email string `json:"email"`

		// Type specifies the OTP workflow type.
		Type OTPType `json:"type"`

		// Extra holds optional dynamic metadata.
		Extra map[string]any `json:"extra,omitempty"`
	}

	// GetVerificationOTPResult contains the plain text OTP code retrieved from storage.
	GetVerificationOTPResult struct {
		// OTP is the retrieved plain text code.
		OTP string `json:"otp"`
	}

	// CheckVerificationOTPParams defines parameters for validating an OTP without consuming it.
	CheckVerificationOTPParams struct {
		// Email is the target email address.
		Email string `json:"email"`

		// Type specifies the OTP workflow type.
		Type OTPType `json:"type"`

		// OTP is the code to check.
		OTP string `json:"otp"`

		// Extra holds optional dynamic metadata.
		Extra map[string]any `json:"extra,omitempty"`
	}

	// CheckVerificationOTPResult reports whether the tested OTP code is valid.
	CheckVerificationOTPResult struct {
		// Success indicates whether the OTP is currently valid.
		Success bool `json:"success"`
	}

	// VerifyEmailOTPParams defines parameters to verify email ownership via OTP.
	VerifyEmailOTPParams struct {
		// Email is the address being verified.
		Email string `json:"email"`

		// OTP is the verification code submitted by the user.
		OTP string `json:"otp"`

		// Extra holds optional dynamic metadata.
		Extra map[string]any `json:"extra,omitempty"`
	}

	// VerifyEmailOTPResult contains the updated user profile and optional auto-created session.
	VerifyEmailOTPResult struct {
		// Success indicates successful email verification.
		Success bool `json:"success"`

		// User is the updated user entity with EmailVerified set to true.
		User *entity.User `json:"user"`

		// SessionToken is the raw token string if AutoSignInAfterVerification is enabled.
		SessionToken string `json:"session_token,omitempty"`

		// Session is the active session entity if AutoSignInAfterVerification is enabled.
		Session *entity.Session `json:"session,omitempty"`
	}

	// SignInEmailOTPParams defines parameters for passwordless sign-in and auto-registration via OTP.
	SignInEmailOTPParams struct {
		// Email is the user's email address.
		Email string `json:"email"`

		// OTP is the one-time code submitted by the user.
		OTP string `json:"otp"`

		// Name is the optional display name assigned if a new user is created.
		Name string `json:"name,omitempty"`

		// Extra holds optional dynamic metadata.
		Extra map[string]any `json:"extra,omitempty"`
	}

	// SignInEmailOTPResult contains the authenticated user profile, session, and registration indicator.
	SignInEmailOTPResult struct {
		// User is the authenticated or newly provisioned user entity.
		User *entity.User `json:"user"`

		// SessionToken is the raw session token.
		SessionToken string `json:"session_token"`

		// Session is the persisted active session entity.
		Session *entity.Session `json:"session"`

		// IsNewUser indicates if this sign-in operation provisioned a new user account.
		IsNewUser bool `json:"is_new_user"`
	}

	// RequestPasswordResetParams defines parameters to request a password reset OTP.
	RequestPasswordResetParams struct {
		// Email is the account email requesting a password reset.
		Email string `json:"email"`

		// Extra holds optional dynamic metadata.
		Extra map[string]any `json:"extra,omitempty"`
	}

	// RequestPasswordResetResult reports the result of the password reset dispatch request.
	RequestPasswordResetResult struct {
		// Success indicates if the reset OTP was successfully dispatched.
		Success bool `json:"success"`
	}

	// ResetPasswordParams defines parameters for setting a new password using a verified OTP.
	ResetPasswordParams struct {
		// Email is the account email address.
		Email string `json:"email"`

		// OTP is the reset code submitted by the user.
		OTP string `json:"otp"`

		// NewPassword is the new password string to set.
		NewPassword string `json:"new_password"`

		// Extra holds optional dynamic metadata.
		Extra map[string]any `json:"extra,omitempty"`
	}

	// ResetPasswordResult reports whether the password was successfully updated.
	ResetPasswordResult struct {
		// Success indicates if the password was successfully reset.
		Success bool `json:"success"`
	}

	// RequestEmailChangeParams defines parameters to initiate an email change flow.
	RequestEmailChangeParams struct {
		// UserID is the ID of the authenticated user requesting the change.
		UserID string `json:"user_id"`

		// NewEmail is the new email address to bind to the account.
		NewEmail string `json:"new_email"`

		// OTP is the verification code for the current email if VerifyCurrentEmail is enabled.
		OTP string `json:"otp,omitempty"`

		// Extra holds optional dynamic metadata.
		Extra map[string]any `json:"extra,omitempty"`
	}

	// RequestEmailChangeResult reports whether the email change OTP was dispatched to the new email.
	RequestEmailChangeResult struct {
		// Success indicates if the OTP was successfully dispatched to the new email address.
		Success bool `json:"success"`
	}

	// ChangeEmailParams defines parameters to confirm an email change using the OTP sent to the new email.
	ChangeEmailParams struct {
		// UserID is the ID of the authenticated user.
		UserID string `json:"user_id"`

		// NewEmail is the new verified email address.
		NewEmail string `json:"new_email"`

		// OTP is the confirmation code delivered to the new email.
		OTP string `json:"otp"`

		// Extra holds optional dynamic metadata.
		Extra map[string]any `json:"extra,omitempty"`
	}

	// ChangeEmailResult reports the outcome of the email change confirmation.
	ChangeEmailResult struct {
		// Success indicates if the email was successfully changed.
		Success bool `json:"success"`

		// User is the updated user entity with the new email address.
		User *entity.User `json:"user"`
	}
)

// Helper methods for attaching/retrieving metadata on parameter structs.

func (p *SendVerificationOTPParams) Set(key string, val any) {
	if p.Extra == nil {
		p.Extra = make(map[string]any)
	}
	p.Extra[key] = val
}

func (p *SendVerificationOTPParams) Get(key string) (any, bool) {
	if p.Extra == nil {
		return nil, false
	}
	v, ok := p.Extra[key]
	return v, ok
}

func (p *VerifyEmailOTPParams) Set(key string, val any) {
	if p.Extra == nil {
		p.Extra = make(map[string]any)
	}
	p.Extra[key] = val
}

func (p *VerifyEmailOTPParams) Get(key string) (any, bool) {
	if p.Extra == nil {
		return nil, false
	}
	v, ok := p.Extra[key]
	return v, ok
}

func (p *SignInEmailOTPParams) Set(key string, val any) {
	if p.Extra == nil {
		p.Extra = make(map[string]any)
	}
	p.Extra[key] = val
}

func (p *SignInEmailOTPParams) Get(key string) (any, bool) {
	if p.Extra == nil {
		return nil, false
	}
	v, ok := p.Extra[key]
	return v, ok
}

func (p *ResetPasswordParams) Set(key string, val any) {
	if p.Extra == nil {
		p.Extra = make(map[string]any)
	}
	p.Extra[key] = val
}

func (p *ResetPasswordParams) Get(key string) (any, bool) {
	if p.Extra == nil {
		return nil, false
	}
	v, ok := p.Extra[key]
	return v, ok
}

// Plugin implements the Email OTP authentication plugin.
type Plugin struct {
	repo   Repository
	config Config
	ctx    *plugin.Context
	hasher Hasher
	cipher Cipher
}

// New instantiates a new Email OTP plugin configured with the given repository and options.
func New(repo Repository, opts ...Option) *Plugin {
	cfg := DefaultConfig()
	for _, opt := range opts {
		opt(&cfg)
	}

	p := &Plugin{
		repo:   repo,
		config: cfg,
		hasher: cfg.CustomHasher,
		cipher: cfg.CustomCipher,
	}

	if cfg.StoreOTPMode == StoreOTPEncrypted && p.cipher == nil && cfg.SecretKey != "" {
		p.cipher, _ = NewAESGCMCipher(cfg.SecretKey)
	}

	return p
}

// ID returns the unique string identifier for the Email OTP plugin ("email-otp").
func (p *Plugin) ID() string {
	return PluginID
}

// Init initializes the plugin within the global GoModularAuth runtime context.
func (p *Plugin) Init(ctx *plugin.Context) error {
	p.ctx = ctx
	return nil
}

// Config returns the active configuration settings of the Email OTP plugin.
func (p *Plugin) Config() Config {
	return p.config
}

// Repository returns the underlying storage repository instance.
func (p *Plugin) Repository() Repository {
	return p.repo
}

// publishEvent safely publishes an event to the EventBus if initialized.
func (p *Plugin) publishEvent(topic string, payload any) {
	if p.ctx != nil && p.ctx.Events() != nil {
		p.ctx.Events().Publish(topic, payload)
	}
}

// hashPassword securely hashes a password using CryptoUtils from context or fallback bcrypt.
func (p *Plugin) hashPassword(password string) (string, error) {
	if p.ctx != nil && p.ctx.Crypto() != nil {
		return p.ctx.Crypto().HashPassword(password)
	}
	b, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(b), err
}

// generateSessionToken generates a cryptographically secure hex session token string.
func (p *Plugin) generateSessionToken() (string, error) {
	if p.ctx != nil && p.ctx.Crypto() != nil {
		return p.ctx.Crypto().GenerateRandomToken(32)
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// normalizeEmail trims whitespace and normalizes email strings.
func (p *Plugin) normalizeEmail(email string) (string, error) {
	trimmed := strings.TrimSpace(email)
	if trimmed == "" {
		return "", ErrInvalidEmail
	}
	parsed, err := mail.ParseAddress(trimmed)
	if err != nil {
		return "", ErrInvalidEmail
	}
	return strings.ToLower(parsed.Address), nil
}

// validateOTPType ensures the provided OTPType is one of the supported types.
func (p *Plugin) validateOTPType(t OTPType) bool {
	switch t {
	case OTPTypeEmailVerification, OTPTypeSignIn, OTPTypeForgetPassword, OTPTypeChangeEmail:
		return true
	default:
		return false
	}
}

// SendVerificationOTP generates and dispatches a one-time password code to the recipient's email.
func (p *Plugin) SendVerificationOTP(ctx context.Context, params *SendVerificationOTPParams) (*SendVerificationOTPResult, error) {
	if params == nil {
		return nil, ErrInvalidParameter
	}

	email, err := p.normalizeEmail(params.Email)
	if err != nil {
		return nil, err
	}

	if !p.validateOTPType(params.Type) {
		return nil, ErrInvalidOTPType
	}

	if p.config.SendVerificationOTP == nil {
		return nil, ErrSendCallbackMissing
	}

	identifier := ToOTPIdentifier(params.Type, email)

	p.publishEvent(EventEmailOTPSendBefore, &SendOTPPendingPayload{
		Email:     email,
		Type:      params.Type,
		ExpiresAt: time.Now().Add(p.config.ExpiresIn),
		Extra:     params.Extra,
	})

	otp, expiresAt, err := p.resolveOTP(ctx, identifier, email, params.Type)
	if err != nil {
		return nil, err
	}

	if err := p.config.SendVerificationOTP(ctx, SendEmailData{
		Email: email,
		OTP:   otp,
		Type:  params.Type,
	}); err != nil {
		return nil, err
	}

	p.publishEvent(EventEmailOTPSent, &OTPSentPayload{
		Email:     email,
		Type:      params.Type,
		ExpiresAt: expiresAt,
		Extra:     params.Extra,
	})

	return &SendVerificationOTPResult{
		Success:   true,
		ExpiresAt: expiresAt,
	}, nil
}

// CreateVerificationOTP generates and stores an OTP code without triggering the email delivery callback (server API).
func (p *Plugin) CreateVerificationOTP(ctx context.Context, params *CreateVerificationOTPParams) (string, error) {
	if params == nil {
		return "", ErrInvalidParameter
	}

	email, err := p.normalizeEmail(params.Email)
	if err != nil {
		return "", err
	}

	if !p.validateOTPType(params.Type) {
		return "", ErrInvalidOTPType
	}

	identifier := ToOTPIdentifier(params.Type, email)
	otp, _, err := p.resolveOTP(ctx, identifier, email, params.Type)
	if err != nil {
		return "", err
	}

	return otp, nil
}

// GetVerificationOTP retrieves the plain text OTP code currently stored for an identifier (server API).
func (p *Plugin) GetVerificationOTP(ctx context.Context, params *GetVerificationOTPParams) (*GetVerificationOTPResult, error) {
	if params == nil {
		return nil, ErrInvalidParameter
	}

	email, err := p.normalizeEmail(params.Email)
	if err != nil {
		return nil, err
	}

	if !p.validateOTPType(params.Type) {
		return nil, ErrInvalidOTPType
	}

	if p.config.StoreOTPMode == StoreOTPHashed {
		return nil, ErrCannotRetrieveHashed
	}

	identifier := ToOTPIdentifier(params.Type, email)
	record, err := p.repo.FindVerificationValue(ctx, identifier)
	if err != nil || record == nil || record.ExpiresAt.Before(time.Now()) {
		return nil, ErrOTPExpired
	}

	storedValue, _ := SplitAtLastColon(record.Value)
	plainOtp, ok := p.retrievePlainOTP(storedValue)
	if !ok {
		return nil, ErrCannotRetrieveHashed
	}

	return &GetVerificationOTPResult{
		OTP: plainOtp,
	}, nil
}

// CheckVerificationOTP verifies whether a submitted OTP is valid without consuming it or changing attempt counts.
func (p *Plugin) CheckVerificationOTP(ctx context.Context, params *CheckVerificationOTPParams) (*CheckVerificationOTPResult, error) {
	if params == nil || strings.TrimSpace(params.OTP) == "" {
		return nil, ErrInvalidParameter
	}

	email, err := p.normalizeEmail(params.Email)
	if err != nil {
		return nil, err
	}

	if !p.validateOTPType(params.Type) {
		return nil, ErrInvalidOTPType
	}

	identifier := ToOTPIdentifier(params.Type, email)
	record, err := p.repo.FindVerificationValue(ctx, identifier)
	if err != nil || record == nil || record.ExpiresAt.Before(time.Now()) {
		return nil, ErrOTPExpired
	}

	storedValue, _ := SplitAtLastColon(record.Value)
	valid := p.verifyStoredOTP(storedValue, strings.TrimSpace(params.OTP))
	if !valid {
		return nil, ErrInvalidOTP
	}

	return &CheckVerificationOTPResult{
		Success: true,
	}, nil
}

// VerifyEmailOTP validates an OTP submitted for email verification and marks the user's email as verified.
func (p *Plugin) VerifyEmailOTP(ctx context.Context, params *VerifyEmailOTPParams) (*VerifyEmailOTPResult, error) {
	if params == nil || strings.TrimSpace(params.OTP) == "" {
		return nil, ErrInvalidParameter
	}

	email, err := p.normalizeEmail(params.Email)
	if err != nil {
		return nil, err
	}

	identifier := ToOTPIdentifier(OTPTypeEmailVerification, email)

	p.publishEvent(EventEmailOTPVerifyBefore, &VerifyBeforePayload{
		Email: email,
		Type:  OTPTypeEmailVerification,
		Extra: params.Extra,
	})

	if err := p.atomicVerifyOTP(ctx, identifier, strings.TrimSpace(params.OTP), OTPTypeEmailVerification, email, params.Extra); err != nil {
		return nil, err
	}

	user, err := p.repo.GetUserByEmail(ctx, email)
	if err != nil {
		return nil, ErrUserNotFound
	}

	user.EmailVerified = true
	user.UpdatedAt = time.Now()
	if err := p.repo.UpdateUser(ctx, user); err != nil {
		return nil, err
	}

	p.publishEvent(EventEmailOTPVerified, &OTPVerifiedPayload{
		UserID:    user.ID,
		Email:     email,
		Type:      OTPTypeEmailVerification,
		Timestamp: time.Now(),
		Extra:     params.Extra,
	})

	var sessionToken string
	var session *entity.Session
	if p.config.AutoSignInAfterVerification {
		token, err := p.generateSessionToken()
		if err != nil {
			return nil, err
		}

		sessParams := &dto.CreateSessionParams{
			UserID:    user.ID,
			Token:     token,
			ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
			CreatedAt: time.Now(),
			Extra:     params.Extra,
		}

		sess, err := p.repo.CreateSession(ctx, sessParams)
		if err != nil {
			return nil, err
		}
		sessionToken = token
		session = sess
	}

	return &VerifyEmailOTPResult{
		Success:      true,
		User:         user,
		SessionToken: sessionToken,
		Session:      session,
	}, nil
}

// SignInEmailOTP authenticates an existing user or automatically provisions a new user via OTP.
func (p *Plugin) SignInEmailOTP(ctx context.Context, params *SignInEmailOTPParams) (*SignInEmailOTPResult, error) {
	if params == nil || strings.TrimSpace(params.OTP) == "" {
		return nil, ErrInvalidParameter
	}

	email, err := p.normalizeEmail(params.Email)
	if err != nil {
		return nil, err
	}

	identifier := ToOTPIdentifier(OTPTypeSignIn, email)

	p.publishEvent(EventEmailOTPVerifyBefore, &VerifyBeforePayload{
		Email: email,
		Type:  OTPTypeSignIn,
		Extra: params.Extra,
	})

	if err := p.atomicVerifyOTP(ctx, identifier, strings.TrimSpace(params.OTP), OTPTypeSignIn, email, params.Extra); err != nil {
		return nil, err
	}

	user, err := p.repo.GetUserByEmail(ctx, email)
	isNewUser := false

	if err != nil || user == nil {
		if p.config.DisableSignUp {
			return nil, ErrUserNotFound
		}

		// Provision new user
		name := strings.TrimSpace(params.Name)
		if name == "" {
			if atIdx := strings.Index(email, "@"); atIdx != -1 {
				name = email[:atIdx]
			} else {
				name = email
			}
		}

		createUserParams := &dto.CreateUserParams{
			Email: email,
			Name:  name,
			Role:  "user",
			Extra: params.Extra,
		}

		newUser, createErr := p.repo.CreateUser(ctx, createUserParams)
		if createErr != nil {
			return nil, createErr
		}

		newUser.EmailVerified = true
		newUser.UpdatedAt = time.Now()
		_ = p.repo.UpdateUser(ctx, newUser)

		// Create credential account record
		_ = p.repo.CreateAccount(ctx, &entity.Account{
			ID:        "acc_" + uuid.NewString(),
			UserID:    newUser.ID,
			Provider:  "email-otp",
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		})

		user = newUser
		isNewUser = true
	} else {
		// Existing user: mark email verified if not verified
		if !user.EmailVerified {
			user.EmailVerified = true
			user.UpdatedAt = time.Now()
			_ = p.repo.UpdateUser(ctx, user)
		}
	}

	// Generate authenticated session
	token, err := p.generateSessionToken()
	if err != nil {
		return nil, err
	}

	sessParams := &dto.CreateSessionParams{
		UserID:    user.ID,
		Token:     token,
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
		CreatedAt: time.Now(),
		Extra:     params.Extra,
	}

	session, err := p.repo.CreateSession(ctx, sessParams)
	if err != nil {
		return nil, err
	}

	p.publishEvent(EventEmailOTPSignInSuccess, &SignInSuccessPayload{
		User:      user,
		Session:   session,
		IsNewUser: isNewUser,
		Extra:     params.Extra,
	})

	return &SignInEmailOTPResult{
		User:         user,
		SessionToken: token,
		Session:      session,
		IsNewUser:    isNewUser,
	}, nil
}

// RequestPasswordResetEmailOTP verifies account existence and dispatches a password recovery OTP.
func (p *Plugin) RequestPasswordResetEmailOTP(ctx context.Context, params *RequestPasswordResetParams) (*RequestPasswordResetResult, error) {
	if params == nil {
		return nil, ErrInvalidParameter
	}

	email, err := p.normalizeEmail(params.Email)
	if err != nil {
		return nil, err
	}

	if p.config.SendVerificationOTP == nil {
		return nil, ErrSendCallbackMissing
	}

	user, err := p.repo.GetUserByEmail(ctx, email)
	if err != nil || user == nil {
		return nil, ErrUserNotFound
	}

	identifier := ToOTPIdentifier(OTPTypeForgetPassword, email)

	p.publishEvent(EventEmailOTPSendBefore, &SendOTPPendingPayload{
		Email:     email,
		Type:      OTPTypeForgetPassword,
		ExpiresAt: time.Now().Add(p.config.ExpiresIn),
		Extra:     params.Extra,
	})

	otp, expiresAt, err := p.resolveOTP(ctx, identifier, email, OTPTypeForgetPassword)
	if err != nil {
		return nil, err
	}

	if err := p.config.SendVerificationOTP(ctx, SendEmailData{
		Email: email,
		OTP:   otp,
		Type:  OTPTypeForgetPassword,
	}); err != nil {
		return nil, err
	}

	p.publishEvent(EventEmailOTPSent, &OTPSentPayload{
		Email:     email,
		Type:      OTPTypeForgetPassword,
		ExpiresAt: expiresAt,
		Extra:     params.Extra,
	})

	return &RequestPasswordResetResult{
		Success: true,
	}, nil
}

// ResetPasswordEmailOTP validates a password reset OTP and updates the user's password hash.
func (p *Plugin) ResetPasswordEmailOTP(ctx context.Context, params *ResetPasswordParams) (*ResetPasswordResult, error) {
	if params == nil || strings.TrimSpace(params.OTP) == "" {
		return nil, ErrInvalidParameter
	}

	email, err := p.normalizeEmail(params.Email)
	if err != nil {
		return nil, err
	}

	// Validate password length constraints
	passLen := len(params.NewPassword)
	if passLen < p.config.MinPasswordLength {
		return nil, ErrPasswordTooShort
	}
	if passLen > p.config.MaxPasswordLength {
		return nil, ErrPasswordTooLong
	}

	identifier := ToOTPIdentifier(OTPTypeForgetPassword, email)

	p.publishEvent(EventEmailOTPVerifyBefore, &VerifyBeforePayload{
		Email: email,
		Type:  OTPTypeForgetPassword,
		Extra: params.Extra,
	})

	if err := p.atomicVerifyOTP(ctx, identifier, strings.TrimSpace(params.OTP), OTPTypeForgetPassword, email, params.Extra); err != nil {
		return nil, err
	}

	user, err := p.repo.GetUserByEmail(ctx, email)
	if err != nil || user == nil {
		return nil, ErrUserNotFound
	}

	hash, err := p.hashPassword(params.NewPassword)
	if err != nil {
		return nil, err
	}

	// Update or create credential account
	if err := p.repo.UpdateAccountPassword(ctx, user.ID, hash); err != nil {
		_ = p.repo.CreateAccount(ctx, &entity.Account{
			ID:        "acc_" + uuid.NewString(),
			UserID:    user.ID,
			Provider:  "credential",
			Password:  hash,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		})
	}

	// Ensure user is marked verified
	user.EmailVerified = true
	user.UpdatedAt = time.Now()
	_ = p.repo.UpdateUser(ctx, user)

	// Optionally revoke existing active sessions
	if p.config.RevokeSessionsOnPasswordReset {
		_ = p.repo.DeleteSessionsByUserID(ctx, user.ID)
	}

	p.publishEvent(EventEmailOTPPasswordReset, &PasswordResetPayload{
		UserID:    user.ID,
		Email:     email,
		Timestamp: time.Now(),
		Extra:     params.Extra,
	})

	return &ResetPasswordResult{
		Success: true,
	}, nil
}

// RequestEmailChangeEmailOTP initiates the email change procedure by dispatching an OTP to the new email address.
func (p *Plugin) RequestEmailChangeEmailOTP(ctx context.Context, params *RequestEmailChangeParams) (*RequestEmailChangeResult, error) {
	if params == nil {
		return nil, ErrInvalidParameter
	}

	if !p.config.ChangeEmail.Enabled {
		return nil, ErrChangeEmailDisabled
	}

	if strings.TrimSpace(params.UserID) == "" {
		return nil, ErrInvalidParameter
	}

	newEmail, err := p.normalizeEmail(params.NewEmail)
	if err != nil {
		return nil, err
	}

	if p.config.SendVerificationOTP == nil {
		return nil, ErrSendCallbackMissing
	}

	user, err := p.repo.GetUserByID(ctx, params.UserID)
	if err != nil || user == nil {
		return nil, ErrUserNotFound
	}

	if strings.EqualFold(user.Email, newEmail) {
		return nil, ErrSameEmail
	}

	// Check if new email is already claimed by another user
	if existingUser, _ := p.repo.GetUserByEmail(ctx, newEmail); existingUser != nil && existingUser.ID != user.ID {
		return nil, ErrEmailAlreadyInUse
	}

	// If verify current email is required, validate submitted OTP against current email
	if p.config.ChangeEmail.VerifyCurrentEmail {
		if strings.TrimSpace(params.OTP) == "" {
			return nil, ErrCurrentEmailNotVerified
		}

		currentIdentifier := ToOTPIdentifier(OTPTypeChangeEmail, user.Email)
		if err := p.atomicVerifyOTP(ctx, currentIdentifier, strings.TrimSpace(params.OTP), OTPTypeChangeEmail, user.Email, params.Extra); err != nil {
			return nil, err
		}
	}

	// Generate and dispatch OTP to new email
	changeIdentifier := ToChangeEmailOTPIdentifier(user.Email, newEmail)

	p.publishEvent(EventEmailOTPSendBefore, &SendOTPPendingPayload{
		Email:     newEmail,
		Type:      OTPTypeChangeEmail,
		ExpiresAt: time.Now().Add(p.config.ExpiresIn),
		Extra:     params.Extra,
	})

	otp, expiresAt, err := p.resolveOTP(ctx, changeIdentifier, newEmail, OTPTypeChangeEmail)
	if err != nil {
		return nil, err
	}

	if err := p.config.SendVerificationOTP(ctx, SendEmailData{
		Email: newEmail,
		OTP:   otp,
		Type:  OTPTypeChangeEmail,
	}); err != nil {
		return nil, err
	}

	p.publishEvent(EventEmailOTPSent, &OTPSentPayload{
		Email:     newEmail,
		Type:      OTPTypeChangeEmail,
		ExpiresAt: expiresAt,
		Extra:     params.Extra,
	})

	return &RequestEmailChangeResult{
		Success: true,
	}, nil
}

// ChangeEmailEmailOTP confirms changing the user's email address using the OTP delivered to the new email.
func (p *Plugin) ChangeEmailEmailOTP(ctx context.Context, params *ChangeEmailParams) (*ChangeEmailResult, error) {
	if params == nil || strings.TrimSpace(params.OTP) == "" {
		return nil, ErrInvalidParameter
	}

	if !p.config.ChangeEmail.Enabled {
		return nil, ErrChangeEmailDisabled
	}

	if strings.TrimSpace(params.UserID) == "" {
		return nil, ErrInvalidParameter
	}

	newEmail, err := p.normalizeEmail(params.NewEmail)
	if err != nil {
		return nil, err
	}

	user, err := p.repo.GetUserByID(ctx, params.UserID)
	if err != nil || user == nil {
		return nil, ErrUserNotFound
	}

	if strings.EqualFold(user.Email, newEmail) {
		return nil, ErrSameEmail
	}

	// Ensure new email is not claimed by another user
	if existingUser, _ := p.repo.GetUserByEmail(ctx, newEmail); existingUser != nil && existingUser.ID != user.ID {
		return nil, ErrEmailAlreadyInUse
	}

	changeIdentifier := ToChangeEmailOTPIdentifier(user.Email, newEmail)

	p.publishEvent(EventEmailOTPVerifyBefore, &VerifyBeforePayload{
		Email: newEmail,
		Type:  OTPTypeChangeEmail,
		Extra: params.Extra,
	})

	if err := p.atomicVerifyOTP(ctx, changeIdentifier, strings.TrimSpace(params.OTP), OTPTypeChangeEmail, newEmail, params.Extra); err != nil {
		return nil, err
	}

	oldEmail := user.Email
	user.Email = newEmail
	user.EmailVerified = true
	user.UpdatedAt = time.Now()

	if err := p.repo.UpdateUser(ctx, user); err != nil {
		return nil, err
	}

	p.publishEvent(EventEmailOTPChangeEmail, &EmailChangedPayload{
		UserID:    user.ID,
		OldEmail:  oldEmail,
		NewEmail:  newEmail,
		Timestamp: time.Now(),
		Extra:     params.Extra,
	})

	return &ChangeEmailResult{
		Success: true,
		User:    user,
	}, nil
}
