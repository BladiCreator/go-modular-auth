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
	PluginID           = "email-password"
	CredentialProvider = "credential"
)

var (
	ErrPasswordTooShort   = errors.New("emailpassword: la contraseña no cumple con la longitud mínima requerida")
	ErrInvalidCredentials = errors.New("emailpassword: credenciales inválidas")
	ErrEmailNotVerified   = errors.New("emailpassword: el correo electrónico no ha sido verificado")
	ErrInvalidCurrentPass = errors.New("emailpassword: la contraseña actual es incorrecta")
	ErrTokenExpired       = errors.New("emailpassword: el token ha expirado")
)

// Plugin implements plugin.Plugin interface for email/password authentication.
type Plugin struct {
	repo   Repository
	config Config
	ctx    *plugin.Context
}

// New creates a new EmailPassword plugin instance with the specified repository and functional options.
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

// Init initializes the plugin within the global GoModularAuth context.
func (p *Plugin) Init(ctx *plugin.Context) error {
	p.ctx = ctx
	return nil
}

// SignUp registers a new user with email and password credentials.
func (p *Plugin) SignUp(ctx context.Context, input dto.SignUpDTO) (*entity.User, error) {
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

	newUser := &entity.User{
		Email:         input.Email,
		Name:          input.Name,
		EmailVerified: false,
	}

	if p.ctx != nil && p.ctx.Events() != nil {
		p.ctx.Events().Publish(EventSignUpBefore, ctx, &SignUpEventPayload{User: newUser})
	}

	if err := p.repo.CreateUser(ctx, newUser); err != nil {
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
		p.ctx.Events().Publish(EventSignUpAfter, ctx, &SignUpEventPayload{User: newUser})
	}
	return newUser, nil
}

// SignIn authenticates user credentials.
func (p *Plugin) SignIn(ctx context.Context, input dto.SignInDTO) (*entity.User, error) {
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

// ChangePassword changes the password of an existing user after validating current password.
func (p *Plugin) ChangePassword(ctx context.Context, input dto.ChangePasswordDTO) error {
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

// ForgotPassword generates a secure reset token and publishes notification event.
func (p *Plugin) ForgotPassword(ctx context.Context, input dto.ForgotPasswordDTO) (*entity.VerificationToken, error) {
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

// ResetPassword validates the reset token and updates the user's password.
func (p *Plugin) ResetPassword(ctx context.Context, input dto.ResetPasswordDTO) error {
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
