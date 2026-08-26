package genericoauth

import (
	"context"
	"fmt"
	"time"

	"github.com/BladiCreator/go-modular-auth/domain/entity"
	"github.com/BladiCreator/go-modular-auth/plugin"
	"github.com/google/uuid"
)

// PluginID is the unique string identifier for the Generic OAuth plugin ("generic-oauth").
const PluginID = "generic-oauth"

// Plugin implements Generic OAuth authentication for go-modular-auth.
type Plugin struct {
	repo   Repository
	config Config
	ctx    *plugin.Context
}

// New creates a new Generic OAuth plugin instance configured with a repository and options.
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

// ID returns the unique identifier for the Generic OAuth plugin ("generic-oauth").
func (p *Plugin) ID() string {
	return PluginID
}

// Init initializes the plugin within the global GoModularAuth context.
func (p *Plugin) Init(ctx *plugin.Context) error {
	p.ctx = ctx
	return nil
}

// Config returns the active configuration of the Generic OAuth plugin.
func (p *Plugin) Config() Config {
	return p.config
}

// GetProvider retrieves a ProviderConfig by provider ID.
func (p *Plugin) GetProvider(providerID string) (*ProviderConfig, error) {
	provider, ok := p.config.Providers[providerID]
	if !ok || provider == nil {
		return nil, fmt.Errorf("%w: %s", ErrProviderNotFound, providerID)
	}
	return provider, nil
}

// SignIn initiates an OAuth authorization flow for the given provider.
func (p *Plugin) SignIn(ctx context.Context, providerID string, callbackURL string) (*SignInData, error) {
	provider, err := p.GetProvider(providerID)
	if err != nil {
		return nil, err
	}

	if err := ResolveProviderConfig(ctx, p.config.HTTPClient, provider); err != nil {
		return nil, fmt.Errorf("failed to resolve discovery for provider %s: %w", providerID, err)
	}

	state, err := GenerateState()
	if err != nil {
		return nil, fmt.Errorf("failed to generate state: %w", err)
	}

	var verifier, challenge string
	if provider.PKCE {
		verifier, challenge, err = GeneratePKCE()
		if err != nil {
			return nil, fmt.Errorf("failed to generate PKCE: %w", err)
		}
	}

	authURL, err := BuildAuthorizationURL(provider, state, challenge)
	if err != nil {
		return nil, err
	}

	stateData := &StateData{
		ProviderID:   providerID,
		CodeVerifier: verifier,
		CallbackURL:  callbackURL,
		CreatedAt:    time.Now(),
	}

	if p.repo != nil {
		if err := p.repo.SaveState(ctx, state, stateData, p.config.StateTTL); err != nil {
			// Non-fatal if using pure cookie mode
		}
	}

	if p.ctx != nil && p.ctx.Events() != nil {
		p.ctx.Events().Publish(EventOAuthSignInStart, providerID, state)
	}

	return &SignInData{
		URL:          authURL,
		State:        state,
		CodeVerifier: verifier,
		Redirect:     true,
	}, nil
}

// Callback handles authorization code exchange, user lookup/creation, account linking, and session initialization.
func (p *Plugin) Callback(ctx context.Context, providerID string, code string, state string, codeVerifier string) (*entity.User, *entity.Session, *Tokens, error) {
	if code == "" {
		return nil, nil, nil, fmt.Errorf("%w: authorization code is required", ErrInvalidParameter)
	}

	provider, err := p.GetProvider(providerID)
	if err != nil {
		return nil, nil, nil, err
	}

	if err := ResolveProviderConfig(ctx, p.config.HTTPClient, provider); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to resolve discovery for provider %s: %w", providerID, err)
	}

	// Verify state if repository state validation is active
	if p.repo != nil && state != "" {
		storedState, err := p.repo.GetState(ctx, state)
		if err == nil && storedState != nil {
			if storedState.ProviderID != providerID {
				return nil, nil, nil, ErrInvalidState
			}
			if storedState.CodeVerifier != "" && codeVerifier == "" {
				codeVerifier = storedState.CodeVerifier
			}
			_ = p.repo.DeleteState(ctx, state)
		}
	}

	if provider.PKCE && codeVerifier == "" {
		return nil, nil, nil, ErrInvalidCodeVerifier
	}

	// Exchange code for tokens
	req := ExchangeRequest{
		Code:         code,
		CodeVerifier: codeVerifier,
		RedirectURI:  provider.RedirectURI,
	}

	tokens, err := ExchangeCode(ctx, p.config.HTTPClient, provider, req)
	if err != nil {
		if p.ctx != nil && p.ctx.Events() != nil {
			p.ctx.Events().Publish(EventOAuthSignInFailure, providerID, err.Error())
		}
		return nil, nil, nil, err
	}

	// Fetch user info from userinfo endpoint or id_token
	userInfo, err := FetchUserInfo(ctx, p.config.HTTPClient, provider, tokens)
	if err != nil {
		if p.ctx != nil && p.ctx.Events() != nil {
			p.ctx.Events().Publish(EventOAuthSignInFailure, providerID, err.Error())
		}
		return nil, nil, nil, err
	}

	if p.repo == nil {
		// Stateless mode: return user object constructed from profile without saving to DB
		user := &entity.User{
			ID:            userInfo.ID,
			Name:          userInfo.Name,
			Email:         userInfo.Email,
			EmailVerified: userInfo.EmailVerified,
			CreatedAt:     time.Now(),
			UpdatedAt:     time.Now(),
		}
		return user, nil, tokens, nil
	}

	// Look up existing social account binding
	accountID := userInfo.ID
	if accountID == "" {
		accountID = userInfo.Sub
	}
	if accountID == "" {
		return nil, nil, nil, fmt.Errorf("%w: provider user info does not contain sub or id", ErrUserInfoFailed)
	}

	var user *entity.User
	account, err := p.repo.GetAccountByProvider(ctx, providerID, accountID)
	if err == nil && account != nil {
		user, err = p.repo.GetUserByID(ctx, account.UserID)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to fetch user for account: %w", err)
		}
	} else if userInfo.Email != "" {
		// Look up user by email if social account link not found
		existingUser, err := p.repo.GetUserByEmail(ctx, userInfo.Email)
		if err == nil && existingUser != nil {
			user = existingUser
			// Link social account to existing user
			newAccount := &entity.Account{
				ID:        uuid.New().String(),
				UserID:    user.ID,
				Provider:  providerID,
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			}
			if _, err := p.repo.CreateAccount(ctx, newAccount); err != nil {
				return nil, nil, nil, fmt.Errorf("failed to bind social account to existing user: %w", err)
			}
		}
	}

	// Create user if not found
	if user == nil {
		if provider.DisableSignUp || provider.DisableImplicitSignUp {
			return nil, nil, nil, ErrSignUpDisabled
		}

		userName := userInfo.Name
		if userName == "" {
			userName = userInfo.Email
		}

		newUser := &entity.User{
			ID:            uuid.New().String(),
			Name:          userName,
			Email:         userInfo.Email,
			EmailVerified: userInfo.EmailVerified,
			CreatedAt:     time.Now(),
			UpdatedAt:     time.Now(),
		}

		user, err = p.repo.CreateUser(ctx, newUser)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to create new user: %w", err)
		}

		newAccount := &entity.Account{
			ID:        uuid.New().String(),
			UserID:    user.ID,
			Provider:  providerID,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
		if _, err := p.repo.CreateAccount(ctx, newAccount); err != nil {
			return nil, nil, nil, fmt.Errorf("failed to create social account record: %w", err)
		}
	}

	// Create user session
	sessionToken := uuid.New().String()
	session := &entity.Session{
		ID:        uuid.New().String(),
		UserID:    user.ID,
		Token:     sessionToken,
		ExpiresAt: time.Now().Add(24 * time.Hour),
		CreatedAt: time.Now(),
	}

	createdSession, err := p.repo.CreateSession(ctx, session)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create user session: %w", err)
	}

	if p.ctx != nil && p.ctx.Events() != nil {
		p.ctx.Events().Publish(EventOAuthSignInSuccess, user.ID, providerID)
	}

	return user, createdSession, tokens, nil
}

// LinkAccount explicitly links a social profile to an already authenticated user.
func (p *Plugin) LinkAccount(ctx context.Context, userID string, providerID string, code string, codeVerifier string) (*entity.Account, error) {
	if userID == "" {
		return nil, fmt.Errorf("%w: user ID is required to link account", ErrInvalidParameter)
	}

	provider, err := p.GetProvider(providerID)
	if err != nil {
		return nil, err
	}

	if p.repo == nil {
		return nil, fmt.Errorf("%w: repository required for linking accounts", ErrInvalidParameter)
	}

	user, err := p.repo.GetUserByID(ctx, userID)
	if err != nil || user == nil {
		return nil, ErrUserNotFound
	}

	tokens, err := ExchangeCode(ctx, p.config.HTTPClient, provider, ExchangeRequest{
		Code:         code,
		CodeVerifier: codeVerifier,
		RedirectURI:  provider.RedirectURI,
	})
	if err != nil {
		return nil, err
	}

	userInfo, err := FetchUserInfo(ctx, p.config.HTTPClient, provider, tokens)
	if err != nil {
		return nil, err
	}

	accountID := userInfo.ID
	if accountID == "" {
		accountID = userInfo.Sub
	}

	existingAccount, err := p.repo.GetAccountByProvider(ctx, providerID, accountID)
	if err == nil && existingAccount != nil {
		if existingAccount.UserID != userID {
			return nil, ErrAccountAlreadyLinked
		}
		return existingAccount, nil
	}

	newAccount := &entity.Account{
		ID:        uuid.New().String(),
		UserID:    userID,
		Provider:  providerID,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	createdAccount, err := p.repo.CreateAccount(ctx, newAccount)
	if err != nil {
		return nil, fmt.Errorf("failed to save linked account: %w", err)
	}

	if p.ctx != nil && p.ctx.Events() != nil {
		p.ctx.Events().Publish(EventOAuthAccountLinked, userID, providerID)
	}

	return createdAccount, nil
}
