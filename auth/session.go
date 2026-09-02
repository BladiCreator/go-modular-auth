package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/BladiCreator/go-modular-auth/config"
	"github.com/BladiCreator/go-modular-auth/domain"
	"github.com/BladiCreator/go-modular-auth/domain/dto"
	"github.com/BladiCreator/go-modular-auth/domain/entity"
	"github.com/BladiCreator/go-modular-auth/domain/repository"
	"github.com/BladiCreator/go-modular-auth/plugin"
	"github.com/asaskevich/EventBus"
)

const (
	// EventSessionCreated is published when a new authenticated session is created.
	EventSessionCreated = "auth:session:created"

	// EventSessionRevoked is published when an active session is explicitly revoked.
	EventSessionRevoked = "auth:session:revoked"

	// EventSessionValidated is published when a session token is successfully validated.
	EventSessionValidated = "auth:session:validated"
)

var (
	// ErrSessionRepositoryRequired is returned when session operations are invoked without configuring a SessionRepository.
	ErrSessionRepositoryRequired = errors.New("auth: session repository is required")

	// ErrSessionManagerRequired is returned when session operations are invoked without an active SessionManager in context.
	ErrSessionManagerRequired = plugin.ErrSessionManagerRequired

	// ErrInvalidUserID is returned when an empty user ID is provided to session creation.
	ErrInvalidUserID = errors.New("auth: user ID cannot be empty")
)

// SessionCreatedPayload defines the payload published on EventSessionCreated.
type SessionCreatedPayload struct {
	Session *entity.Session
	Extra   map[string]any
}

// GetSession returns the Session entity from the payload.
func (p *SessionCreatedPayload) GetSession() *entity.Session {
	if p == nil {
		return nil
	}
	return p.Session
}

// GetExtra returns the dynamic extra metadata map from the payload.
func (p *SessionCreatedPayload) GetExtra() map[string]any {
	if p == nil {
		return nil
	}
	return p.Extra
}

// SessionRevokedPayload defines the payload published on EventSessionRevoked.
type SessionRevokedPayload struct {
	Token     string
	SessionID string
	UserID    string
	Extra     map[string]any
}

// GetToken returns the revoked session token string.
func (p *SessionRevokedPayload) GetToken() string {
	if p == nil {
		return ""
	}
	return p.Token
}

// Type aliases for seamless DX.
type (
	SessionConfig  = config.SessionConfig
	SessionOptions = plugin.SessionOptions
	SessionOption  = plugin.SessionOption
)

var (
	// DefaultSessionConfig returns default session lifetime settings.
	DefaultSessionConfig = config.DefaultSessionConfig

	// WithDuration configures a custom expiration duration for the session.
	WithDuration = plugin.WithDuration

	// WithRememberMe configures extended session lifetime for remember-me requests.
	WithRememberMe = plugin.WithRememberMe

	// WithIPAddress sets the client IP address initiating the session.
	WithIPAddress = plugin.WithIPAddress

	// WithUserAgent sets the client User-Agent initiating the session.
	WithUserAgent = plugin.WithUserAgent

	// WithDeviceID sets the physical device identifier for the session.
	WithDeviceID = plugin.WithDeviceID

	// WithExtra sets a single dynamic metadata key-value in the session.
	WithExtra = plugin.WithExtra

	// WithExtraMap copies dynamic metadata key-value pairs into the session.
	WithExtraMap = plugin.WithExtraMap
)

// UserResolver allows resolving user profiles by ID during session validation.
type UserResolver interface {
	GetUserByID(ctx context.Context, userID string) (*entity.User, error)
}

// SessionManager coordinates session lifecycle, cryptographic generation, persistence, and event dispatching.
type SessionManager struct {
	repo         repository.SessionRepository
	cfg          config.SessionConfig
	crypto       plugin.CryptoUtils
	events       EventBus.Bus
	userResolver UserResolver
}

var _ plugin.SessionManager = (*SessionManager)(nil)

// NewSessionManager creates a new central SessionManager instance.
func NewSessionManager(repo repository.SessionRepository, cfg config.SessionConfig, crypto plugin.CryptoUtils, events EventBus.Bus, userResolver ...UserResolver) *SessionManager {
	var ur UserResolver
	if len(userResolver) > 0 {
		ur = userResolver[0]
	}
	return &SessionManager{
		repo:         repo,
		cfg:          cfg,
		crypto:       crypto,
		events:       events,
		userResolver: ur,
	}
}

// CreateSession creates and persists a new authenticated user session with cryptographic token generation and event emission.
func (sm *SessionManager) CreateSession(ctx context.Context, userID string, opts ...SessionOption) (*entity.Session, error) {
	if sm == nil || sm.repo == nil {
		return nil, ErrSessionRepositoryRequired
	}
	if userID == "" {
		return nil, ErrInvalidUserID
	}

	optsData := SessionOptions{}
	for _, opt := range opts {
		opt(&optsData)
	}

	duration := sm.cfg.DefaultDuration
	if duration <= 0 {
		duration = 24 * time.Hour
	}

	if optsData.Duration != 0 {
		duration = optsData.Duration
	} else if optsData.RememberMe {
		remDur := sm.cfg.RememberMeDuration
		if remDur <= 0 {
			remDur = 30 * 24 * time.Hour
		}
		duration = remDur
	}

	now := time.Now()
	expiresAt := now.Add(duration)

	token, err := sm.crypto.GenerateRandomToken(32)
	if err != nil {
		return nil, fmt.Errorf("auth: failed to generate session token: %w", err)
	}

	params := &dto.CreateSessionParams{
		UserID:    userID,
		Token:     token,
		ExpiresAt: expiresAt,
		CreatedAt: now,
		IPAddress: optsData.IPAddress,
		UserAgent: optsData.UserAgent,
		DeviceID:  optsData.DeviceID,
	}
	if optsData.Extra != nil {
		params.Extra = optsData.Extra
	}

	sess, err := sm.repo.CreateSession(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("auth: failed to persist session: %w", err)
	}
	if sess.Extra == nil && optsData.Extra != nil {
		sess.Extra = optsData.Extra
	}

	if sm.events != nil {
		sm.events.Publish(EventSessionCreated, ctx, &SessionCreatedPayload{
			Session: sess,
			Extra:   optsData.Extra,
		})
	}

	return sess, nil
}

// ValidateSession validates an active session token, returning combined user and session data in *dto.SessionData.
func (sm *SessionManager) ValidateSession(ctx context.Context, token string) (*dto.SessionData, error) {
	if sm == nil || sm.repo == nil {
		return nil, ErrSessionRepositoryRequired
	}
	if token == "" {
		return nil, repository.ErrInvalidSessionToken
	}

	sess, err := sm.repo.GetSessionByToken(ctx, token)
	if err != nil {
		return nil, err
	}

	if !sess.ExpiresAt.IsZero() && time.Now().After(sess.ExpiresAt) {
		return nil, repository.ErrSessionExpired
	}

	var user *entity.User
	resolver := sm.userResolver
	if resolver == nil {
		if r, ok := sm.repo.(UserResolver); ok {
			resolver = r
		}
	}

	if resolver != nil {
		u, err := resolver.GetUserByID(ctx, sess.UserID)
		if err == nil {
			user = u
		} else if !errors.Is(err, domain.ErrUserNotFound) {
			return nil, fmt.Errorf("auth: failed to resolve user for session: %w", err)
		}
	}

	sessionData := &dto.SessionData{
		Session: sess,
		User:    user,
	}
	if sess.Extra != nil {
		sessionData.Extra = sess.Extra
	} else if customRepo, ok := sm.repo.(interface {
		GetCustomSessionFields(ctx context.Context, sessionID string) (map[string]any, error)
	}); ok {
		if fields, err := customRepo.GetCustomSessionFields(ctx, sess.ID); err == nil && len(fields) > 0 {
			sessionData.Extra = fields
			sess.Extra = fields
		}
	}

	if sm.events != nil {
		sm.events.Publish(EventSessionValidated, ctx, sessionData)
	}

	return sessionData, nil
}

// RevokeSession revokes an active session by token, removing it from storage and publishing EventSessionRevoked.
func (sm *SessionManager) RevokeSession(ctx context.Context, token string) error {
	if sm == nil || sm.repo == nil {
		return ErrSessionRepositoryRequired
	}
	if token == "" {
		return repository.ErrInvalidSessionToken
	}

	sess, _ := sm.repo.GetSessionByToken(ctx, token)

	if err := sm.repo.DeleteSession(ctx, token); err != nil {
		return fmt.Errorf("auth: failed to revoke session: %w", err)
	}

	if sm.events != nil {
		payload := &SessionRevokedPayload{
			Token: token,
		}
		if sess != nil {
			payload.SessionID = sess.ID
			payload.UserID = sess.UserID
			payload.Extra = sess.Extra
		}
		sm.events.Publish(EventSessionRevoked, ctx, payload)
	}

	return nil
}

// GetSessionByToken retrieves an active session by its unique token without loading the user.
func (sm *SessionManager) GetSessionByToken(ctx context.Context, token string) (*entity.Session, error) {
	if sm == nil || sm.repo == nil {
		return nil, ErrSessionRepositoryRequired
	}
	if token == "" {
		return nil, repository.ErrInvalidSessionToken
	}

	sess, err := sm.repo.GetSessionByToken(ctx, token)
	if err != nil {
		return nil, err
	}

	if !sess.ExpiresAt.IsZero() && time.Now().After(sess.ExpiresAt) {
		return nil, repository.ErrSessionExpired
	}

	return sess, nil
}

// GetSessionByID retrieves an active session by its primary key ID.
func (sm *SessionManager) GetSessionByID(ctx context.Context, id string) (*entity.Session, error) {
	if sm == nil || sm.repo == nil {
		return nil, ErrSessionRepositoryRequired
	}
	if id == "" {
		return nil, repository.ErrSessionNotFound
	}
	return sm.repo.GetSessionByID(ctx, id)
}

// RevokeSessionsByUserID deletes all active sessions for the specified user.
func (sm *SessionManager) RevokeSessionsByUserID(ctx context.Context, userID string) error {
	if sm == nil || sm.repo == nil {
		return ErrSessionRepositoryRequired
	}
	if userID == "" {
		return ErrInvalidUserID
	}
	return sm.repo.DeleteSessionsByUserID(ctx, userID)
}

// ListSessionsByUserID retrieves all active sessions for the specified user.
func (sm *SessionManager) ListSessionsByUserID(ctx context.Context, userID string) ([]*entity.Session, error) {
	if sm == nil || sm.repo == nil {
		return nil, ErrSessionRepositoryRequired
	}
	if userID == "" {
		return nil, ErrInvalidUserID
	}
	return sm.repo.ListSessionsByUserID(ctx, userID)
}
