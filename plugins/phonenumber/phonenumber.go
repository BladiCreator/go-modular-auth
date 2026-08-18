package phonenumber

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"

	"github.com/BladiCreator/go-modular-auth/domain/dto"
	"github.com/BladiCreator/go-modular-auth/domain/entity"
	"github.com/BladiCreator/go-modular-auth/plugin"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// PluginID is the unique string identifier for the Phone Number plugin ("phone-number").
const PluginID = "phone-number"

// Parameter and Result Structs
type (
	// SendOTPParams defines parameters required to dispatch an OTP to a user's phone number.
	SendOTPParams struct {
		// PhoneNumber is the destination recipient phone number (required).
		PhoneNumber string `json:"phone_number"`

		// Extra holds dynamic metadata passed through event interceptors (optional).
		Extra map[string]any `json:"extra,omitempty"`
	}

	// SendOTPResult contains the delivery status and expiry of the dispatched OTP.
	SendOTPResult struct {
		// Success indicates if the OTP was successfully generated and dispatched.
		Success bool `json:"success"`

		// ExpiresAt indicates when the dispatched OTP code will expire.
		ExpiresAt time.Time `json:"expires_at"`
	}

	// VerifyParams defines parameters to verify a phone number OTP for login, registration, or profile update.
	VerifyParams struct {
		// PhoneNumber is the phone number being verified (required).
		PhoneNumber string `json:"phone_number"`

		// Code is the verification code submitted by the user (required).
		Code string `json:"code"`

		// UserID is the ID of the authenticated user (required if UpdatePhoneNumber is true).
		UserID string `json:"user_id,omitempty"`

		// UpdatePhoneNumber indicates whether to attach the verified phone number to an existing user session.
		UpdatePhoneNumber bool `json:"update_phone_number,omitempty"`

		// DisableSession prevents creating an active authentication session upon successful verification.
		DisableSession bool `json:"disable_session,omitempty"`

		// Extra holds optional dynamic metadata.
		Extra map[string]any `json:"extra,omitempty"`
	}

	// VerifyResult contains the updated user profile and optional created session.
	VerifyResult struct {
		// Success indicates successful phone verification.
		Success bool `json:"success"`

		// User is the authenticated, newly provisioned, or updated user entity.
		User *entity.User `json:"user"`

		// SessionToken is the raw session token if a session was created.
		SessionToken string `json:"session_token,omitempty"`

		// Session is the active session entity if created.
		Session *entity.Session `json:"session,omitempty"`
	}

	// SignInParams defines parameters for credential-based phone number + password login.
	SignInParams struct {
		// PhoneNumber is the registered user's phone number.
		PhoneNumber string `json:"phone_number"`

		// Password is the plain text password.
		Password string `json:"password"`

		// RememberMe extends session lifespan if set to true.
		RememberMe *bool `json:"remember_me,omitempty"`

		// Extra holds optional dynamic metadata.
		Extra map[string]any `json:"extra,omitempty"`
	}

	// SignInResult contains the authenticated user and active session.
	SignInResult struct {
		// User is the authenticated user entity.
		User *entity.User `json:"user"`

		// SessionToken is the raw session token.
		SessionToken string `json:"session_token"`

		// Session is the persisted active session entity.
		Session *entity.Session `json:"session"`
	}

	// RequestPasswordResetParams defines parameters to request a password reset OTP via SMS.
	RequestPasswordResetParams struct {
		// PhoneNumber is the account phone number requesting a password reset.
		PhoneNumber string `json:"phone_number"`

		// Extra holds optional dynamic metadata.
		Extra map[string]any `json:"extra,omitempty"`
	}

	// RequestPasswordResetResult reports the result of the password reset dispatch request.
	RequestPasswordResetResult struct {
		// Success indicates if the reset OTP was successfully dispatched.
		Success bool `json:"success"`
	}

	// ResetPasswordParams defines parameters for setting a new password using a verified SMS OTP.
	ResetPasswordParams struct {
		// PhoneNumber is the account phone number.
		PhoneNumber string `json:"phone_number"`

		// OTP is the reset code submitted by the user.
		OTP string `json:"otp"`

		// NewPassword is the new password string to set.
		NewPassword string `json:"new_password"`

		// Extra holds optional dynamic metadata.
		Extra map[string]any `json:"extra,omitempty"`
	}

	// ResetPasswordResult reports whether the password was successfully reset.
	ResetPasswordResult struct {
		// Success indicates if the password was successfully reset.
		Success bool `json:"success"`
	}

	// CreateVerificationOTPParams defines parameters for server-side OTP generation without SMS dispatch.
	CreateVerificationOTPParams struct {
		// PhoneNumber is the target phone number.
		PhoneNumber string `json:"phone_number"`

		// Type specifies the OTP workflow type.
		Type OTPType `json:"type"`

		// Extra holds optional dynamic metadata.
		Extra map[string]any `json:"extra,omitempty"`
	}

	// CreateVerificationOTPResult contains the status and expiry of the created OTP.
	CreateVerificationOTPResult struct {
		// Success indicates if the OTP record was created.
		Success bool `json:"success"`

		// ExpiresAt indicates when the created OTP will expire.
		ExpiresAt time.Time `json:"expires_at"`
	}

	// GetVerificationOTPParams defines parameters for server-side inspection of an active OTP code.
	GetVerificationOTPParams struct {
		// PhoneNumber is the target phone number.
		PhoneNumber string `json:"phone_number"`

		// Type specifies the OTP workflow type.
		Type OTPType `json:"type"`
	}

	// GetVerificationOTPResult contains the plain text OTP code retrieved from storage.
	GetVerificationOTPResult struct {
		// OTP is the retrieved plain text code.
		OTP string `json:"otp"`
	}

	// CheckVerificationOTPParams defines parameters for validating an OTP without consuming it.
	CheckVerificationOTPParams struct {
		// PhoneNumber is the target phone number.
		PhoneNumber string `json:"phone_number"`

		// Type specifies the OTP workflow type.
		Type OTPType `json:"type"`

		// OTP is the code to check.
		OTP string `json:"otp"`
	}

	// CheckVerificationOTPResult reports whether the tested OTP code is currently valid.
	CheckVerificationOTPResult struct {
		// Success indicates whether the OTP is currently valid.
		Success bool `json:"success"`
	}
)

// Helper methods for attaching/retrieving metadata on parameter structs.

func (p *SendOTPParams) Set(key string, val any) {
	if p.Extra == nil {
		p.Extra = make(map[string]any)
	}
	p.Extra[key] = val
}

func (p *SendOTPParams) Get(key string) (any, bool) {
	if p.Extra == nil {
		return nil, false
	}
	v, ok := p.Extra[key]
	return v, ok
}

func (p *VerifyParams) Set(key string, val any) {
	if p.Extra == nil {
		p.Extra = make(map[string]any)
	}
	p.Extra[key] = val
}

func (p *VerifyParams) Get(key string) (any, bool) {
	if p.Extra == nil {
		return nil, false
	}
	v, ok := p.Extra[key]
	return v, ok
}

func (p *SignInParams) Set(key string, val any) {
	if p.Extra == nil {
		p.Extra = make(map[string]any)
	}
	p.Extra[key] = val
}

func (p *SignInParams) Get(key string) (any, bool) {
	if p.Extra == nil {
		return nil, false
	}
	v, ok := p.Extra[key]
	return v, ok
}

func (p *RequestPasswordResetParams) Set(key string, val any) {
	if p.Extra == nil {
		p.Extra = make(map[string]any)
	}
	p.Extra[key] = val
}

func (p *RequestPasswordResetParams) Get(key string) (any, bool) {
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

func (p *CreateVerificationOTPParams) Set(key string, val any) {
	if p.Extra == nil {
		p.Extra = make(map[string]any)
	}
	p.Extra[key] = val
}

func (p *CreateVerificationOTPParams) Get(key string) (any, bool) {
	if p.Extra == nil {
		return nil, false
	}
	v, ok := p.Extra[key]
	return v, ok
}

// Plugin implements the Phone Number (SMS OTP) authentication plugin.
type Plugin struct {
	repo   Repository
	config Config
	ctx    *plugin.Context
	hasher Hasher
	cipher Cipher
}

// New instantiates a new Phone Number plugin configured with the given repository and options.
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

// ID returns the unique string identifier for the Phone Number plugin ("phone-number").
func (p *Plugin) ID() string {
	return PluginID
}

// Init initializes the plugin within the global GoModularAuth runtime context.
func (p *Plugin) Init(ctx *plugin.Context) error {
	p.ctx = ctx
	return nil
}

// Config returns the active configuration settings of the Phone Number plugin.
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

// comparePassword securely verifies a password against a hash using CryptoUtils or fallback bcrypt.
func (p *Plugin) comparePassword(hash, password string) bool {
	if p.ctx != nil && p.ctx.Crypto() != nil {
		return p.ctx.Crypto().ComparePassword(hash, password)
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

// generateSessionToken generates a 32-byte cryptographically secure hexadecimal session token.
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

// SendOTP generates and dispatches a numeric OTP via SMS to the specified recipient phone number.
func (p *Plugin) SendOTP(ctx context.Context, params SendOTPParams) (*SendOTPResult, error) {
	if p.config.SendOTP == nil {
		return nil, ErrSendOTPNotImplemented
	}
	if params.PhoneNumber == "" {
		return nil, ErrInvalidPhoneNumber
	}
	if p.config.PhoneNumberValidator != nil {
		valid, err := p.config.PhoneNumberValidator(ctx, params.PhoneNumber)
		if err != nil || !valid {
			return nil, ErrInvalidPhoneNumber
		}
	}

	identifier := ToOTPIdentifier(params.PhoneNumber)
	p.publishEvent(EventPhoneNumberOTPSendBefore, &OTPSentPayload{
		PhoneNumber: params.PhoneNumber,
		Type:        OTPTypeVerification,
		Extra:       params.Extra,
	})

	rawCode, expiresAt, err := p.resolveOTP(ctx, identifier, params.PhoneNumber, OTPTypeVerification)
	if err != nil {
		return nil, fmt.Errorf("phonenumber: failed to resolve otp: %w", err)
	}

	if err := p.config.SendOTP(ctx, SendOTPData{
		PhoneNumber: params.PhoneNumber,
		Code:        rawCode,
		Type:        OTPTypeVerification,
		Extra:       params.Extra,
	}); err != nil {
		return nil, fmt.Errorf("phonenumber: send otp callback failed: %w", err)
	}

	p.publishEvent(EventPhoneNumberOTPSent, &OTPSentPayload{
		PhoneNumber: params.PhoneNumber,
		Type:        OTPTypeVerification,
		ExpiresAt:   expiresAt,
		Extra:       params.Extra,
	})

	return &SendOTPResult{Success: true, ExpiresAt: expiresAt}, nil
}

// Verify validates a submitted OTP code and performs user login, auto-registration, or phone number update.
func (p *Plugin) Verify(ctx context.Context, params VerifyParams) (*VerifyResult, error) {
	if params.PhoneNumber == "" {
		return nil, ErrInvalidPhoneNumber
	}
	if params.Code == "" {
		return nil, ErrInvalidOTP
	}

	identifier := ToOTPIdentifier(params.PhoneNumber)

	p.publishEvent(EventPhoneNumberOTPVerifyBefore, &OTPSentPayload{
		PhoneNumber: params.PhoneNumber,
		Type:        OTPTypeVerification,
		Extra:       params.Extra,
	})

	if p.config.VerifyOTP != nil {
		valid, err := p.config.VerifyOTP(ctx, VerifyOTPData{
			PhoneNumber: params.PhoneNumber,
			Code:        params.Code,
			Extra:       params.Extra,
		})
		if err != nil || !valid {
			p.publishEvent(EventPhoneNumberOTPFailed, &OTPFailedPayload{
				PhoneNumber: params.PhoneNumber,
				Type:        OTPTypeVerification,
				Reason:      "custom_verify_failed",
				Extra:       params.Extra,
			})
			return nil, ErrInvalidOTP
		}
		_ = p.repo.DeleteVerificationValue(ctx, identifier)
	} else {
		if err := p.atomicVerifyOTP(ctx, identifier, params.Code, OTPTypeVerification, params.PhoneNumber, params.Extra); err != nil {
			return nil, err
		}
	}

	// Case A: Update phone number on an existing authenticated user
	if params.UpdatePhoneNumber {
		if params.UserID == "" {
			return nil, ErrUserNotFound
		}
		existing, _ := p.repo.GetUserByPhoneNumber(ctx, params.PhoneNumber)
		if existing != nil && existing.ID != params.UserID {
			return nil, ErrPhoneNumberAlreadyExists
		}

		user, err := p.repo.GetUserByID(ctx, params.UserID)
		if err != nil || user == nil {
			return nil, ErrUserNotFound
		}

		phone := params.PhoneNumber
		user.PhoneNumber = &phone
		user.PhoneNumberVerified = true
		user.UpdatedAt = time.Now()

		if err := p.repo.UpdateUser(ctx, user); err != nil {
			return nil, fmt.Errorf("phonenumber: failed to update user phone: %w", err)
		}

		if p.config.CallbackOnVerification != nil {
			_ = p.config.CallbackOnVerification(ctx, OnVerificationData{
				PhoneNumber: params.PhoneNumber,
				User:        user,
				Extra:       params.Extra,
			})
		}

		p.publishEvent(EventPhoneNumberOTPVerified, &OTPVerifiedPayload{
			UserID:      user.ID,
			PhoneNumber: params.PhoneNumber,
			Type:        OTPTypeVerification,
			Timestamp:   time.Now(),
			Extra:       params.Extra,
		})
		p.publishEvent(EventPhoneNumberUpdated, user)

		return &VerifyResult{Success: true, User: user}, nil
	}

	// Case B: Sign-in or Auto-Registration via OTP
	user, err := p.repo.GetUserByPhoneNumber(ctx, params.PhoneNumber)
	var isNewUser bool
	if err != nil || user == nil {
		if p.config.DisableSignUp {
			return nil, ErrPhoneNumberNotRegistered
		}

		var tempEmail, tempName string
		if p.config.SignUpOnVerification != nil {
			tempEmail = p.config.SignUpOnVerification.GetTempEmail(params.PhoneNumber)
			tempName = p.config.SignUpOnVerification.GetTempName(params.PhoneNumber)
		} else {
			tempEmail = fmt.Sprintf("%s@phone.local", params.PhoneNumber)
			tempName = params.PhoneNumber
		}

		phone := params.PhoneNumber
		createUserParams := &dto.CreateUserParams{
			Email: tempEmail,
			Name:  tempName,
			Extra: map[string]any{
				ExtraKeyPhoneNumber:         params.PhoneNumber,
				ExtraKeyPhoneNumberVerified: true,
			},
		}

		created, createErr := p.repo.CreateUser(ctx, createUserParams)
		if createErr != nil {
			return nil, fmt.Errorf("phonenumber: failed to create user on verification: %w", createErr)
		}
		user = created
		user.PhoneNumber = &phone
		user.PhoneNumberVerified = true
		_ = p.repo.UpdateUser(ctx, user)
		isNewUser = true
	} else {
		user.PhoneNumberVerified = true
		user.UpdatedAt = time.Now()
		_ = p.repo.UpdateUser(ctx, user)
	}

	if p.config.CallbackOnVerification != nil {
		_ = p.config.CallbackOnVerification(ctx, OnVerificationData{
			PhoneNumber: params.PhoneNumber,
			User:        user,
			Extra:       params.Extra,
		})
	}

	var session *entity.Session
	var sessionToken string
	if !params.DisableSession {
		token, tokenErr := p.generateSessionToken()
		if tokenErr != nil {
			return nil, fmt.Errorf("phonenumber: failed to generate session token: %w", tokenErr)
		}
		sess, sessErr := p.repo.CreateSession(ctx, &dto.CreateSessionParams{
			UserID:    user.ID,
			Token:     token,
			ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
			CreatedAt: time.Now(),
			Extra:     params.Extra,
		})
		if sessErr != nil {
			return nil, fmt.Errorf("phonenumber: failed to create session: %w", sessErr)
		}
		session = sess
		sessionToken = token
	}

	p.publishEvent(EventPhoneNumberOTPVerified, &OTPVerifiedPayload{
		UserID:      user.ID,
		PhoneNumber: params.PhoneNumber,
		Type:        OTPTypeVerification,
		Timestamp:   time.Now(),
		Extra:       params.Extra,
	})

	if isNewUser {
		p.publishEvent(EventPhoneNumberSignUpSuccess, &SignInSuccessPayload{
			User:      user,
			Session:   session,
			IsNewUser: true,
			Extra:     params.Extra,
		})
	} else {
		p.publishEvent(EventPhoneNumberSignInSuccess, &SignInSuccessPayload{
			User:      user,
			Session:   session,
			IsNewUser: false,
			Extra:     params.Extra,
		})
	}

	return &VerifyResult{
		Success:      true,
		User:         user,
		SessionToken: sessionToken,
		Session:      session,
	}, nil
}

// SignIn authenticates a user using their phone number and password.
func (p *Plugin) SignIn(ctx context.Context, params SignInParams) (*SignInResult, error) {
	if params.PhoneNumber == "" {
		return nil, ErrInvalidPhoneNumber
	}
	if p.config.PhoneNumberValidator != nil {
		valid, err := p.config.PhoneNumberValidator(ctx, params.PhoneNumber)
		if err != nil || !valid {
			return nil, ErrInvalidPhoneNumber
		}
	}

	user, err := p.repo.GetUserByPhoneNumber(ctx, params.PhoneNumber)
	if err != nil || user == nil {
		return nil, ErrInvalidPhoneNumberOrPassword
	}

	// Verification requirement protection
	if p.config.RequireVerification && !user.PhoneNumberVerified {
		_, _ = p.SendOTP(ctx, SendOTPParams{
			PhoneNumber: params.PhoneNumber,
			Extra:       params.Extra,
		})
		return nil, ErrPhoneNumberNotVerified
	}

	account, err := p.repo.GetAccountByUserIDAndProvider(ctx, user.ID, "credential")
	if err != nil || account == nil || account.Password == "" {
		return nil, ErrInvalidPhoneNumberOrPassword
	}

	if !p.comparePassword(account.Password, params.Password) {
		return nil, ErrInvalidPhoneNumberOrPassword
	}

	token, err := p.generateSessionToken()
	if err != nil {
		return nil, fmt.Errorf("phonenumber: failed to generate session token: %w", err)
	}

	sessionExpiry := 7 * 24 * time.Hour
	if params.RememberMe != nil && *params.RememberMe {
		sessionExpiry = 30 * 24 * time.Hour
	}

	sess, err := p.repo.CreateSession(ctx, &dto.CreateSessionParams{
		UserID:    user.ID,
		Token:     token,
		ExpiresAt: time.Now().Add(sessionExpiry),
		CreatedAt: time.Now(),
		Extra:     params.Extra,
	})
	if err != nil {
		return nil, fmt.Errorf("phonenumber: failed to create session: %w", err)
	}

	p.publishEvent(EventPhoneNumberSignInPasswordSuccess, &SignInSuccessPayload{
		User:      user,
		Session:   sess,
		IsNewUser: false,
		Extra:     params.Extra,
	})

	return &SignInResult{
		User:         user,
		SessionToken: token,
		Session:      sess,
	}, nil
}

// RequestPasswordReset dispatches a numeric OTP via SMS to enable password resetting.
func (p *Plugin) RequestPasswordReset(ctx context.Context, params RequestPasswordResetParams) (*RequestPasswordResetResult, error) {
	if params.PhoneNumber == "" {
		return nil, ErrInvalidPhoneNumber
	}

	user, _ := p.repo.GetUserByPhoneNumber(ctx, params.PhoneNumber)
	identifier := ToPasswordResetOTPIdentifier(params.PhoneNumber)

	rawCode, expiresAt, err := p.resolveOTP(ctx, identifier, params.PhoneNumber, OTPTypePasswordReset)
	if err != nil {
		return nil, fmt.Errorf("phonenumber: failed to resolve reset otp: %w", err)
	}

	// User enumeration mitigation: return success without sending SMS if user doesn't exist
	if user == nil {
		return &RequestPasswordResetResult{Success: true}, nil
	}

	sendCallback := p.config.SendPasswordResetOTP
	if sendCallback == nil {
		sendCallback = p.config.SendOTP
	}
	if sendCallback != nil {
		_ = sendCallback(ctx, SendOTPData{
			PhoneNumber: params.PhoneNumber,
			Code:        rawCode,
			Type:        OTPTypePasswordReset,
			Extra:       params.Extra,
		})
	}

	p.publishEvent(EventPhoneNumberPasswordResetRequested, &OTPSentPayload{
		PhoneNumber: params.PhoneNumber,
		Type:        OTPTypePasswordReset,
		ExpiresAt:   expiresAt,
		Extra:       params.Extra,
	})

	return &RequestPasswordResetResult{Success: true}, nil
}

// ResetPassword verifies the reset OTP and securely updates the user's password.
func (p *Plugin) ResetPassword(ctx context.Context, params ResetPasswordParams) (*ResetPasswordResult, error) {
	if params.PhoneNumber == "" {
		return nil, ErrInvalidPhoneNumber
	}
	if params.OTP == "" {
		return nil, ErrInvalidOTP
	}

	identifier := ToPasswordResetOTPIdentifier(params.PhoneNumber)
	if err := p.atomicVerifyOTP(ctx, identifier, params.OTP, OTPTypePasswordReset, params.PhoneNumber, params.Extra); err != nil {
		return nil, err
	}

	user, err := p.repo.GetUserByPhoneNumber(ctx, params.PhoneNumber)
	if err != nil || user == nil {
		return nil, ErrUserNotFound
	}

	if len(params.NewPassword) < p.config.MinPasswordLength {
		return nil, ErrPasswordTooShort
	}
	if len(params.NewPassword) > p.config.MaxPasswordLength {
		return nil, ErrPasswordTooLong
	}

	hashedPassword, err := p.hashPassword(params.NewPassword)
	if err != nil {
		return nil, fmt.Errorf("phonenumber: failed to hash password: %w", err)
	}

	account, _ := p.repo.GetAccountByUserIDAndProvider(ctx, user.ID, "credential")
	if account == nil {
		newAccount := &entity.Account{
			ID:        uuid.NewString(),
			UserID:    user.ID,
			Provider:  "credential",
			Password:  hashedPassword,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
		if err := p.repo.CreateAccount(ctx, newAccount); err != nil {
			return nil, fmt.Errorf("phonenumber: failed to create credential account: %w", err)
		}
	} else {
		if err := p.repo.UpdateAccountPassword(ctx, user.ID, hashedPassword); err != nil {
			return nil, fmt.Errorf("phonenumber: failed to update account password: %w", err)
		}
	}

	if p.config.OnPasswordReset != nil {
		_ = p.config.OnPasswordReset(ctx, user)
	}

	if p.config.RevokeSessionsOnPasswordReset {
		_ = p.repo.DeleteSessionsByUserID(ctx, user.ID)
	}

	p.publishEvent(EventPhoneNumberPasswordResetSuccess, &PasswordResetPayload{
		UserID:      user.ID,
		PhoneNumber: params.PhoneNumber,
		Timestamp:   time.Now(),
		Extra:       params.Extra,
	})

	return &ResetPasswordResult{Success: true}, nil
}

// UnlinkPhoneNumber removes the phone number from the user's profile and resets its verified status.
func (p *Plugin) UnlinkPhoneNumber(ctx context.Context, userID string) (*entity.User, error) {
	if userID == "" {
		return nil, ErrUserNotFound
	}

	user, err := p.repo.GetUserByID(ctx, userID)
	if err != nil || user == nil {
		return nil, ErrUserNotFound
	}

	user.PhoneNumber = nil
	user.PhoneNumberVerified = false
	user.UpdatedAt = time.Now()

	if err := p.repo.UpdateUser(ctx, user); err != nil {
		return nil, fmt.Errorf("phonenumber: failed to unlink phone number: %w", err)
	}

	p.publishEvent(EventPhoneNumberUnlinked, user)
	return user, nil
}

// CreateVerificationOTP generates and persists an OTP record in storage without sending SMS.
func (p *Plugin) CreateVerificationOTP(ctx context.Context, params CreateVerificationOTPParams) (*CreateVerificationOTPResult, error) {
	if params.PhoneNumber == "" {
		return nil, ErrInvalidPhoneNumber
	}

	identifier := ToOTPIdentifier(params.PhoneNumber)
	if params.Type == OTPTypePasswordReset {
		identifier = ToPasswordResetOTPIdentifier(params.PhoneNumber)
	}

	_, expiresAt, err := p.resolveOTP(ctx, identifier, params.PhoneNumber, params.Type)
	if err != nil {
		return nil, err
	}
	return &CreateVerificationOTPResult{Success: true, ExpiresAt: expiresAt}, nil
}

// GetVerificationOTP retrieves the active plain text OTP code (fails if stored in hashed mode).
func (p *Plugin) GetVerificationOTP(ctx context.Context, params GetVerificationOTPParams) (*GetVerificationOTPResult, error) {
	if params.PhoneNumber == "" {
		return nil, ErrInvalidPhoneNumber
	}

	identifier := ToOTPIdentifier(params.PhoneNumber)
	if params.Type == OTPTypePasswordReset {
		identifier = ToPasswordResetOTPIdentifier(params.PhoneNumber)
	}

	record, err := p.repo.FindVerificationValue(ctx, identifier)
	if err != nil || record == nil || record.ExpiresAt.Before(time.Now()) {
		return nil, ErrOTPNotFound
	}

	storedValue, _ := SplitAtLastColon(record.Value)
	plainOtp, ok := p.retrievePlainOTP(storedValue)
	if !ok {
		return nil, ErrCannotRetrieveHashed
	}

	return &GetVerificationOTPResult{OTP: plainOtp}, nil
}

// CheckVerificationOTP validates an OTP code against storage without consuming it or modifying attempt counters.
func (p *Plugin) CheckVerificationOTP(ctx context.Context, params CheckVerificationOTPParams) (*CheckVerificationOTPResult, error) {
	if params.PhoneNumber == "" || params.OTP == "" {
		return &CheckVerificationOTPResult{Success: false}, nil
	}

	identifier := ToOTPIdentifier(params.PhoneNumber)
	if params.Type == OTPTypePasswordReset {
		identifier = ToPasswordResetOTPIdentifier(params.PhoneNumber)
	}

	record, err := p.repo.FindVerificationValue(ctx, identifier)
	if err != nil || record == nil || record.ExpiresAt.Before(time.Now()) {
		return &CheckVerificationOTPResult{Success: false}, nil
	}

	storedValue, attemptsStr := SplitAtLastColon(record.Value)
	attempts, _ := strconv.Atoi(attemptsStr)
	if attempts >= p.config.AllowedAttempts {
		return &CheckVerificationOTPResult{Success: false}, nil
	}

	valid := p.verifyStoredOTP(storedValue, params.OTP)
	return &CheckVerificationOTPResult{Success: valid}, nil
}
