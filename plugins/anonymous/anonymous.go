package anonymous

import (
	"context"
	"net/mail"
	"time"

	"github.com/BladiCreator/go-modular-auth/domain/dto"
	"github.com/BladiCreator/go-modular-auth/domain/entity"
	"github.com/BladiCreator/go-modular-auth/plugin"
	"github.com/google/uuid"
)

// PluginID is the unique string identifier for the Anonymous plugin ("anonymous").
const PluginID = "anonymous"

// Plugin implements the guest sessions (anonymous users) authentication plugin for go-modular-auth.
type Plugin struct {
	repo   Repository
	config Config
	ctx    *plugin.Context
}

// New instantiates a new Anonymous plugin configured with optional functional options and MemoryRepository.
func New(opts ...Option) *Plugin {
	return NewWithRepository(NewMemoryRepository(), opts...)
}

// NewWithRepository instantiates a new Anonymous plugin with a custom Repository implementation.
func NewWithRepository(repo Repository, opts ...Option) *Plugin {
	cfg := DefaultConfig()
	for _, opt := range opts {
		opt(&cfg)
	}

	return &Plugin{
		repo:   repo,
		config: cfg,
	}
}

// ID returns the unique string identifier for the plugin ("anonymous").
func (p *Plugin) ID() string {
	return PluginID
}

// Init initializes the plugin with the shared execution context.
func (p *Plugin) Init(ctx *plugin.Context) error {
	p.ctx = ctx
	if p.repo == nil {
		return ErrRepositoryRequired
	}
	return nil
}

// Config returns a copy of the active plugin configuration.
func (p *Plugin) Config() Config {
	return p.config
}

// SignInAnonymous creates a new temporary guest user and session, or rejects if the active session is already anonymous.
func (p *Plugin) SignInAnonymous(ctx context.Context, currentSession *entity.Session, params SignInAnonymousParams) (*SignInAnonymousResult, error) {
	// 1. Verify if current session already belongs to an anonymous user
	if currentSession != nil && currentSession.UserID != "" {
		if u, err := p.repo.GetUserByID(ctx, currentSession.UserID); err == nil && u != nil {
			if u.IsAnonymous {
				return nil, ErrAnonymousUsersCannotSignInAgain
			}
		}
	}

	// 2. Generate email address
	var email string
	var err error
	if p.config.GenerateRandomEmail != nil {
		email, err = p.config.GenerateRandomEmail(ctx)
		if err != nil {
			return nil, err
		}
	} else {
		email = "temp-" + uuid.NewString() + "@" + p.config.EmailDomainName
	}

	// Validate email address format
	if _, parseErr := mail.ParseAddress(email); parseErr != nil {
		return nil, ErrInvalidEmailFormat
	}

	// 3. Generate display name
	var name string
	if p.config.GenerateName != nil {
		name, err = p.config.GenerateName(ctx)
		if err != nil {
			return nil, err
		}
	} else {
		name = "Anonymous"
	}

	p.publishEvent(EventSignInAnonymousBefore, ctx, &SignInAnonymousEventPayload{})

	// 4. Create anonymous user in repository
	user, err := p.repo.CreateAnonymousUser(ctx, email, name)
	if err != nil {
		return nil, err
	}

	// 5. Generate random session token
	var token string
	if p.ctx != nil && p.ctx.Crypto() != nil {
		token, err = p.ctx.Crypto().GenerateRandomToken(32)
		if err != nil || token == "" {
			token = uuid.NewString()
		}
	} else {
		token = uuid.NewString()
	}

	now := time.Now()
	expiresAt := now.Add(p.config.CookieMaxAge)

	sessParams := &dto.CreateSessionParams{
		UserID:    user.ID,
		Token:     token,
		IPAddress: params.IPAddress,
		UserAgent: params.UserAgent,
		ExpiresAt: expiresAt,
		CreatedAt: now,
	}

	// 6. Create session in repository
	session, err := p.repo.CreateSession(ctx, sessParams)
	if err != nil {
		return nil, err
	}

	res := &SignInAnonymousResult{
		User:    user,
		Session: session,
		Token:   token,
	}

	p.publishEvent(EventSignInAnonymousAfter, ctx, &SignInAnonymousEventPayload{
		User:    user,
		Session: session,
	})

	return res, nil
}

// DeleteAnonymousUser purges an anonymous user and all their active sessions.
func (p *Plugin) DeleteAnonymousUser(ctx context.Context, session *entity.Session) (*DeleteAnonymousUserResult, error) {
	if p.config.DisableDeleteAnonymousUser {
		return nil, ErrDeleteAnonymousUserDisabled
	}

	if session == nil || session.UserID == "" {
		return nil, ErrUserNotFound
	}

	user, err := p.repo.GetUserByID(ctx, session.UserID)
	if err != nil {
		return nil, err
	}

	if !user.IsAnonymous {
		return nil, ErrUserIsNotAnonymous
	}

	p.publishEvent(EventDeleteAnonymousBefore, ctx, &DeleteAnonymousEventPayload{UserID: user.ID})

	// Purge sessions first, then user record
	if err := p.repo.DeleteUserSessions(ctx, user.ID); err != nil {
		return nil, err
	}

	if err := p.repo.DeleteUser(ctx, user.ID); err != nil {
		return nil, err
	}

	p.publishEvent(EventDeleteAnonymousAfter, ctx, &DeleteAnonymousEventPayload{UserID: user.ID})

	return &DeleteAnonymousUserResult{Success: true}, nil
}

// LinkAccount triggers account linking callbacks and purges the previous anonymous account if enabled.
func (p *Plugin) LinkAccount(ctx context.Context, data *OnLinkAccountData) error {
	if data == nil || data.AnonymousUser.User == nil || data.NewUser.User == nil {
		return nil
	}

	// Execute custom account linking / data migration callback if configured
	if p.config.OnLinkAccount != nil {
		if err := p.config.OnLinkAccount(ctx, data); err != nil {
			return err // Abort deletion on linking error to safeguard user data
		}
	}

	// Purge previous anonymous account if enabled and accounts differ
	if !p.config.DisableDeleteAnonymousUser &&
		data.AnonymousUser.User.ID != data.NewUser.User.ID &&
		data.AnonymousUser.User.IsAnonymous {
		_ = p.repo.DeleteUserSessions(ctx, data.AnonymousUser.User.ID)
		_ = p.repo.DeleteUser(ctx, data.AnonymousUser.User.ID)
	}

	p.publishEvent(EventLinkAccountAfter, ctx, &LinkAccountEventPayload{Data: data})

	return nil
}

// publishEvent dispatches lifecycle events on the shared EventBus if present.
func (p *Plugin) publishEvent(eventName string, ctx context.Context, payload any) {
	if p.ctx != nil && p.ctx.Events() != nil {
		p.ctx.Events().Publish(eventName, ctx, payload)
	}
}
