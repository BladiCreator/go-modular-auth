package username

import (
	"context"
	"strings"
	"time"

	"github.com/BladiCreator/go-modular-auth/domain/dto"
	"github.com/BladiCreator/go-modular-auth/plugin"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// PluginID is the unique string identifier for the Username plugin ("username").
const PluginID = "username"

// CredentialProvider is the default account provider ID for password authentication ("credential").
const CredentialProvider = "credential"

// Pre-calculated valid bcrypt hash used to prevent timing attacks when querying nonexistent users.
// Hashed value of "DummyTimingAttackPassword123!" with cost 10.
const dummyBcryptHash = "$2a$10$7EqJtq98hPqEX7fNZaFWoO.8/3uO4hN5gG1p6Fk4L4N2XyZ1eW26W"

// Plugin implements the username authentication plugin for go-modular-auth.
type Plugin struct {
	repo   Repository
	config Config
	ctx    *plugin.Context
}

// New instantiates a new Username plugin configured with the given repository and options.
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

// ID returns the unique string identifier for the plugin ("username").
func (p *Plugin) ID() string {
	return PluginID
}

// Init initializes the plugin with the shared execution context.
func (p *Plugin) Init(ctx *plugin.Context) error {
	p.ctx = ctx
	return nil
}

// Config returns a copy of the active plugin configuration.
func (p *Plugin) Config() Config {
	return p.config
}

// Normalize applies the configured normalization routine to a username string (e.g. lowercasing).
func (p *Plugin) Normalize(username string) string {
	trimmed := strings.TrimSpace(username)
	if p.config.EnableNormalization && p.config.NormalizeFunc != nil {
		return p.config.NormalizeFunc(trimmed)
	}
	return trimmed
}

// ValidateUsername checks format, length, regex, and custom validation rules for a username.
func (p *Plugin) ValidateUsername(ctx context.Context, username string) error {
	normalized := p.Normalize(username)
	if normalized == "" {
		return ErrInvalidUsername
	}

	if len(normalized) < p.config.MinLength {
		return ErrUsernameTooShort
	}

	if p.config.MaxLength > 0 && len(normalized) > p.config.MaxLength {
		return ErrUsernameTooLong
	}

	if p.config.RegexValidator != nil && !p.config.RegexValidator.MatchString(normalized) {
		return ErrInvalidUsername
	}

	if p.config.CustomValidator != nil {
		if err := p.config.CustomValidator(ctx, normalized); err != nil {
			return err
		}
	}

	return nil
}

// IsAvailable checks whether the specified username is free for registration.
func (p *Plugin) IsAvailable(ctx context.Context, username string) (*IsUsernameAvailableResult, error) {
	normalized := p.Normalize(username)
	if err := p.ValidateUsername(ctx, normalized); err != nil {
		return &IsUsernameAvailableResult{Available: false, Username: normalized}, nil
	}

	available, err := p.repo.IsUsernameAvailable(ctx, normalized)
	if err != nil {
		return nil, err
	}

	return &IsUsernameAvailableResult{
		Available: available,
		Username:  normalized,
	}, nil
}

// ProcessSignUpUsername validates, normalizes, and prepares username & displayUsername for user registration.
// If displayUsername is empty, it defaults to the unnormalized or normalized username.
func (p *Plugin) ProcessSignUpUsername(ctx context.Context, rawUsername, rawDisplayUsername string) (normalizedUsername, finalDisplayUsername string, err error) {
	if rawUsername == "" {
		return "", "", ErrInvalidParameter
	}

	if err := p.ValidateUsername(ctx, rawUsername); err != nil {
		return "", "", err
	}

	normalizedUsername = p.Normalize(rawUsername)

	available, err := p.repo.IsUsernameAvailable(ctx, normalizedUsername)
	if err != nil {
		return "", "", err
	}
	if !available {
		return "", "", ErrUsernameAlreadyTaken
	}

	finalDisplayUsername = strings.TrimSpace(rawDisplayUsername)
	if finalDisplayUsername == "" {
		finalDisplayUsername = rawUsername
	}

	return normalizedUsername, finalDisplayUsername, nil
}

// SignIn authenticates a user by username and password.
// Employs a dummy bcrypt check on nonexistent users to prevent timing attacks.
func (p *Plugin) SignIn(ctx context.Context, params SignInUsernameParams) (*SignInUsernameResult, error) {
	rawUsername := strings.TrimSpace(params.Username)
	password := params.Password

	if rawUsername == "" || password == "" {
		return nil, ErrInvalidUsernameOrPassword
	}

	normalized := p.Normalize(rawUsername)

	if p.ctx != nil && p.ctx.Events() != nil {
		p.ctx.Events().Publish(EventSignInBefore, ctx, &params)
	}

	user, err := p.repo.GetUserByUsername(ctx, normalized)
	if err != nil || user == nil {
		// Timing attack protection: perform dummy bcrypt check
		p.comparePassword(dummyBcryptHash, password)
		return nil, ErrInvalidUsernameOrPassword
	}

	// Verify email requirement if configured
	if p.config.RequireEmailVerification && !user.EmailVerified {
		return nil, ErrEmailNotVerified
	}

	account, err := p.repo.GetAccountByUserIDAndProvider(ctx, user.ID, CredentialProvider)
	if err != nil || account == nil {
		p.comparePassword(dummyBcryptHash, password)
		return nil, ErrInvalidUsernameOrPassword
	}

	if !p.comparePassword(account.Password, password) {
		return nil, ErrInvalidUsernameOrPassword
	}

	sessionToken := uuid.New().String()
	expiresAt := time.Now().Add(24 * time.Hour)
	if params.RememberMe != nil && *params.RememberMe {
		expiresAt = time.Now().Add(30 * 24 * time.Hour)
	}

	session, err := p.repo.CreateSession(ctx, &dto.CreateSessionParams{
		UserID:    user.ID,
		Token:     sessionToken,
		ExpiresAt:      expiresAt,
		ExtraContainer: params.ExtraContainer,
	})
	if err != nil {
		return nil, err
	}

	result := &SignInUsernameResult{
		User:         user,
		SessionToken: sessionToken,
		Session:      session,
	}

	if p.ctx != nil && p.ctx.Events() != nil {
		p.ctx.Events().Publish(EventSignInAfter, ctx, result)
	}

	return result, nil
}

// UpdateUsername validates and modifies the username and displayUsername for a user entity.
func (p *Plugin) UpdateUsername(ctx context.Context, params UpdateUsernameParams) (*UpdateUsernameResult, error) {
	if params.UserID == "" {
		return nil, ErrInvalidParameter
	}

	if err := p.ValidateUsername(ctx, params.Username); err != nil {
		return nil, err
	}

	normalized := p.Normalize(params.Username)

	existingUser, err := p.repo.GetUserByID(ctx, params.UserID)
	if err != nil || existingUser == nil {
		return nil, ErrUserNotFound
	}

	// Check availability if username is changing
	if existingUser.Username != normalized {
		available, err := p.repo.IsUsernameAvailable(ctx, normalized)
		if err != nil {
			return nil, err
		}
		if !available {
			return nil, ErrUsernameAlreadyTaken
		}
	}

	displayUsername := strings.TrimSpace(params.DisplayUsername)
	if displayUsername == "" {
		displayUsername = params.Username
	}

	if p.ctx != nil && p.ctx.Events() != nil {
		p.ctx.Events().Publish(EventUpdateBefore, ctx, &params)
	}

	if err := p.repo.UpdateUsername(ctx, params.UserID, normalized, displayUsername); err != nil {
		return nil, err
	}

	updatedUser, err := p.repo.GetUserByID(ctx, params.UserID)
	if err != nil {
		return nil, err
	}

	result := &UpdateUsernameResult{
		Success: true,
		User:    updatedUser,
	}

	if p.ctx != nil && p.ctx.Events() != nil {
		p.ctx.Events().Publish(EventUpdateAfter, ctx, result)
	}

	return result, nil
}

// comparePassword securely verifies a password hash using context CryptoUtils or bcrypt fallback.
func (p *Plugin) comparePassword(hash, password string) bool {
	if p.ctx != nil && p.ctx.Crypto() != nil {
		return p.ctx.Crypto().ComparePassword(hash, password)
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}
