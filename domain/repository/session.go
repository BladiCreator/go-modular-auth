// Package repository defines centralized persistent data storage contracts for the core domain entities.
package repository

import (
	"context"
	"errors"
	"maps"
	"sync"
	"time"

	"github.com/BladiCreator/go-modular-auth/domain"
	"github.com/BladiCreator/go-modular-auth/domain/dto"
	"github.com/BladiCreator/go-modular-auth/domain/entity"
	"github.com/google/uuid"
)

var (
	// ErrSessionNotFound is returned when no session matches the queried ID or token.
	ErrSessionNotFound = domain.ErrSessionNotFound

	// ErrSessionExpired is returned when a retrieved session has exceeded its validity expiration time.
	ErrSessionExpired = domain.ErrSessionExpired

	// ErrInvalidSessionToken is returned when an empty or malformed session token is provided.
	ErrInvalidSessionToken = errors.New("repository: invalid session token")

	// ErrSessionRevoked is returned when attempting an operation on an explicitly revoked session.
	ErrSessionRevoked = errors.New("repository: session has been revoked")
)

// SessionRepository defines the centralized persistent storage contract for managing authentication sessions.
// Implement this interface on your custom database adapter (e.g. PostgreSQL, MySQL, SQLite, MongoDB, GORM, Redis).
//
// # Implementation Example (GORM / database/sql):
//
//	type GormSessionRepository struct {
//		db *gorm.DB
//	}
//
//	func (r *GormSessionRepository) GetSessionByToken(ctx context.Context, token string) (*entity.Session, error) {
//		var s entity.Session
//		if err := r.db.WithContext(ctx).Where("token = ?", token).First(&s).Error; err != nil {
//			if errors.Is(err, gorm.ErrRecordNotFound) {
//				return nil, repository.ErrSessionNotFound
//			}
//			return nil, err
//		}
//		return &s, nil
//	}
//
// # Storage and Caching Recommendation (Redis / Cache-Aside Strategy):
//
// Because `GetSessionByToken` is invoked on **every authenticated API and HTTP request**, querying
// the relational database on every HTTP call can become a performance bottleneck.
// Decorating your database repository with Redis or an in-memory Cache-Aside wrapper is strongly recommended:
//
//	type CachedSessionRepository struct {
//		dbRepo repository.SessionRepository
//		redis  *redis.Client
//		ttl    time.Duration
//	}
//
//	func (r *CachedSessionRepository) GetSessionByToken(ctx context.Context, token string) (*entity.Session, error) {
//		cacheKey := "session:" + token
//		val, err := r.redis.Get(ctx, cacheKey).Bytes()
//		if err == nil {
//			var sess entity.Session
//			if json.Unmarshal(val, &sess) == nil {
//				return &sess, nil // Fast Cache Hit ($O(1)$ response)
//			}
//		}
//		sess, err := r.dbRepo.GetSessionByToken(ctx, token)
//		if err != nil {
//			return nil, err
//		}
//		bytes, _ := json.Marshal(sess)
//		r.redis.Set(ctx, cacheKey, bytes, r.ttl)
//		return sess, nil
//	}
type SessionRepository interface {
	// CreateSession persists a new authenticated user session in storage.
	//
	// Function:
	//   Called upon successful login, registration, OAuth callback, WebAuthn passkey assertion,
	//   magic link verification, or admin impersonation to issue and persist an active session.
	//
	// Storage:
	//   Database (GORM / SQL) - Inserts a new row into the sessions table.
	//
	// Arguments:
	//   - ctx: Request cancellation and deadline context.
	//   - params: Pointer to CreateSessionParams containing UserID, Token, IPAddress, UserAgent, and Expiry.
	//
	// Returns:
	//   - *entity.Session: Populated active session entity.
	//   - error: Nil on success, or database infrastructure error.
	//
	// Example SQL:
	//   INSERT INTO sessions (id, user_id, token, ip_address, user_agent, impersonated_by, active_organization_id, active_team_id, expires_at, created_at)
	//   VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING *;
	CreateSession(ctx context.Context, params *dto.CreateSessionParams) (*entity.Session, error)

	// GetSessionByToken retrieves an active session by its unique raw session token string.
	//
	// Function:
	//   Used on every authenticated HTTP request (Bearer token, cookie session, OTT exchange) to validate caller credentials.
	//
	// Storage:
	//   Both (Cache-Aside Strategy) - High-frequency lookup per HTTP request cached in Redis (`session:<token>`).
	//
	// Arguments:
	//   - ctx: Request cancellation and deadline context.
	//   - token: Raw session token string.
	//
	// Returns:
	//   - *entity.Session: Matching session entity if found.
	//   - error: ErrSessionNotFound if missing, or database error.
	//
	// Example SQL:
	//   SELECT id, user_id, token, ip_address, user_agent, impersonated_by, active_organization_id, active_team_id, expires_at, created_at, updated_at
	//   FROM sessions WHERE token = $1 LIMIT 1;
	//
	// Example Cache (Redis):
	//   val, err := rdb.Get(ctx, "session:" + token).Bytes()
	GetSessionByToken(ctx context.Context, token string) (*entity.Session, error)

	// GetSessionByID retrieves an active session entity by its unique primary key ID.
	//
	// Function:
	//   Used during OAuth2 prompt verification, OpenID Connect RP-Initiated logout, and session field mutations.
	//
	// Storage:
	//   Both (Cache-Aside Strategy) - Primary key lookup on sessions table.
	//
	// Arguments:
	//   - ctx: Request cancellation and deadline context.
	//   - id: Unique primary key session ID.
	//
	// Returns:
	//   - *entity.Session: Matching session entity if found.
	//   - error: ErrSessionNotFound if missing, or database error.
	//
	// Example SQL:
	//   SELECT id, user_id, token, ip_address, user_agent, impersonated_by, active_organization_id, active_team_id, expires_at, created_at, updated_at
	//   FROM sessions WHERE id = $1 LIMIT 1;
	//
	// Example Cache (Redis):
	//   val, err := rdb.Get(ctx, "session:id:" + id).Bytes()
	GetSessionByID(ctx context.Context, id string) (*entity.Session, error)

	// ListSessionsByUserID retrieves all active sessions belonging to the specified user.
	//
	// Function:
	//   Used in administrative session governance panels, security dashboards, and active device listings.
	//
	// Storage:
	//   Database (GORM / SQL) - Relational user session list query.
	//
	// Arguments:
	//   - ctx: Request cancellation and deadline context.
	//   - userID: Unique user primary key ID.
	//
	// Returns:
	//   - []*entity.Session: Slice of active session entities.
	//   - error: Nil on success, or database error.
	//
	// Example SQL:
	//   SELECT id, user_id, token, ip_address, user_agent, impersonated_by, active_organization_id, active_team_id, expires_at, created_at, updated_at
	//   FROM sessions WHERE user_id = $1 ORDER BY created_at DESC;
	ListSessionsByUserID(ctx context.Context, userID string) ([]*entity.Session, error)

	// UpdateSession updates modified fields of an existing session record in storage.
	//
	// Function:
	//   Used when extending session lifetime (sliding expiration), updating client IP/UserAgent, or modifying session state.
	//
	// Storage:
	//   Database (GORM / SQL) - Relational session row update.
	//
	// Arguments:
	//   - ctx: Request cancellation and deadline context.
	//   - session: Modified Session domain entity.
	//
	// Returns:
	//   - error: Nil on success, ErrSessionNotFound if missing, or database error.
	//
	// Example SQL:
	//   UPDATE sessions SET ip_address = $1, user_agent = $2, expires_at = $3, active_organization_id = $4, active_team_id = $5, updated_at = NOW() WHERE id = $6;
	UpdateSession(ctx context.Context, session *entity.Session) error

	// SetActiveOrganization updates the active organization context associated with an active session.
	//
	// Function:
	//   Called when switching active organization context in multi-tenant environments.
	//
	// Storage:
	//   Database (GORM / SQL) - Column update on sessions table.
	//
	// Arguments:
	//   - ctx: Request cancellation and deadline context.
	//   - sessionID: Unique session primary key ID.
	//   - orgID: Target organization primary key ID.
	//
	// Returns:
	//   - error: Nil on success, ErrSessionNotFound if missing, or database error.
	//
	// Example SQL:
	//   UPDATE sessions SET active_organization_id = $1, updated_at = NOW() WHERE id = $2;
	SetActiveOrganization(ctx context.Context, sessionID, orgID string) error

	// SetActiveTeam updates the active team context associated with an active session.
	//
	// Function:
	//   Called when switching active team context within an organization.
	//
	// Storage:
	//   Database (GORM / SQL) - Column update on sessions table.
	//
	// Arguments:
	//   - ctx: Request cancellation and deadline context.
	//   - sessionID: Unique session primary key ID.
	//   - teamID: Target team primary key ID.
	//
	// Returns:
	//   - error: Nil on success, ErrSessionNotFound if missing, or database error.
	//
	// Example SQL:
	//   UPDATE sessions SET active_team_id = $1, updated_at = NOW() WHERE id = $2;
	SetActiveTeam(ctx context.Context, sessionID, teamID string) error

	// SaveCustomSessionFields persists dynamic additional key-value metadata for a specific session ID.
	//
	// Function:
	//   Called by the customsession plugin when storing dynamic session attributes.
	//
	// Storage:
	//   Database (GORM / SQL) - JSONB/extra_fields update.
	//
	// Arguments:
	//   - ctx: Request cancellation and deadline context.
	//   - sessionID: Unique identifier of the target active session.
	//   - fields: Key-value map of dynamic extra fields to persist.
	//
	// Returns:
	//   - error: Nil on success, or database error.
	//
	// Example SQL:
	//   UPDATE sessions SET extra_fields = $1, updated_at = NOW() WHERE id = $2;
	SaveCustomSessionFields(ctx context.Context, sessionID string, fields map[string]any) error

	// GetCustomSessionFields retrieves dynamic additional key-value metadata for a specific session ID.
	//
	// Function:
	//   Called by the customsession plugin during session payload transformation.
	//
	// Storage:
	//   Database (GORM / SQL) or Redis Cache-Aside.
	//
	// Arguments:
	//   - ctx: Request cancellation and deadline context.
	//   - sessionID: Unique identifier of the target active session.
	//
	// Returns:
	//   - map[string]any: Key-value map of dynamic session fields.
	//   - error: Nil on success, or database error.
	//
	// Example SQL:
	//   SELECT extra_fields FROM sessions WHERE id = $1 LIMIT 1;
	GetCustomSessionFields(ctx context.Context, sessionID string) (map[string]any, error)

	// DeleteSession permanently removes a single session by its raw token string.
	//
	// Function:
	//   Called during standard user logout or single-session revocation.
	//
	// Storage:
	//   Database (GORM / SQL) - Deletes row matching token.
	//
	// Arguments:
	//   - ctx: Request cancellation and deadline context.
	//   - token: Target session token string.
	//
	// Returns:
	//   - error: Nil on success, or database error.
	//
	// Example SQL:
	//   DELETE FROM sessions WHERE token = $1;
	DeleteSession(ctx context.Context, token string) error

	// DeleteSessionByID permanently removes a single session by its primary key ID.
	//
	// Function:
	//   Called during OpenID Connect RP-Initiated logout or administrative session deletion.
	//
	// Storage:
	//   Database (GORM / SQL) - Deletes row matching session ID.
	//
	// Arguments:
	//   - ctx: Request cancellation and deadline context.
	//   - id: Unique primary key session ID.
	//
	// Returns:
	//   - error: Nil on success, or database error.
	//
	// Example SQL:
	//   DELETE FROM sessions WHERE id = $1;
	DeleteSessionByID(ctx context.Context, id string) error

	// DeleteSessionsByUserID deletes all active sessions belonging to the specified user.
	//
	// Function:
	//   Used during account bans, password resets, 2FA credential resets, or global security lockouts.
	//
	// Storage:
	//   Database (GORM / SQL) - Bulk user session deletion.
	//
	// Arguments:
	//   - ctx: Request cancellation and deadline context.
	//   - userID: Target user primary key ID.
	//
	// Returns:
	//   - error: Nil on success, or database error.
	//
	// Example SQL:
	//   DELETE FROM sessions WHERE user_id = $1;
	DeleteSessionsByUserID(ctx context.Context, userID string) error

	// DeleteExpiredSessions purges all sessions whose expiration timestamp is prior to current time.
	//
	// Function:
	//   Called by background cleanup cron routines and maintenance tasks.
	//
	// Storage:
	//   Database (GORM / SQL) - Bulk expired record deletion.
	//
	// Arguments:
	//   - ctx: Request cancellation and deadline context.
	//
	// Returns:
	//   - int64: Count of successfully purged expired session rows.
	//   - error: Nil on success, or database error.
	//
	// Example SQL:
	//   DELETE FROM sessions WHERE expires_at <= NOW();
	DeleteExpiredSessions(ctx context.Context) (int64, error)
}

// MemorySessionRepository provides a thread-safe, in-memory implementation of SessionRepository for testing and development.
type MemorySessionRepository struct {
	mu           sync.RWMutex
	sessions     map[string]*entity.Session // key: session.ID
	tokens       map[string]string          // token -> session.ID
	customFields map[string]map[string]any  // session.ID -> extra_fields
}

// NewMemorySessionRepository initializes and returns a fresh, thread-safe in-memory SessionRepository.
func NewMemorySessionRepository() *MemorySessionRepository {
	return &MemorySessionRepository{
		sessions:     make(map[string]*entity.Session),
		tokens:       make(map[string]string),
		customFields: make(map[string]map[string]any),
	}
}

// CreateSession persists a new session in memory.
func (r *MemorySessionRepository) CreateSession(_ context.Context, params *dto.CreateSessionParams) (*entity.Session, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if params == nil || params.UserID == "" || params.Token == "" {
		return nil, ErrInvalidSessionToken
	}

	now := time.Now()
	createdAt := params.CreatedAt
	if createdAt.IsZero() {
		createdAt = now
	}

	sess := &entity.Session{
		ID:                   uuid.NewString(),
		UserID:               params.UserID,
		Token:                params.Token,
		ExpiresAt:            params.ExpiresAt,
		CreatedAt:            createdAt,
		IPAddress:            params.IPAddress,
		UserAgent:            params.UserAgent,
		ImpersonatedBy:       params.ImpersonatedBy,
		ActiveOrganizationID: params.ActiveOrganizationID,
		ActiveTeamID:         params.ActiveTeamID,
	}
	if params.DeviceID != "" {
		sess.DeviceID = &params.DeviceID
	}

	r.sessions[sess.ID] = sess
	r.tokens[sess.Token] = sess.ID

	if params.Extra != nil {
		cpFields := make(map[string]any, len(params.Extra))
		maps.Copy(cpFields, params.Extra)
		r.customFields[sess.ID] = cpFields
		sess.Extra = cpFields
	}

	res := *sess
	return &res, nil
}

// GetSessionByToken retrieves a session from memory by its unique raw token string.
func (r *MemorySessionRepository) GetSessionByToken(_ context.Context, token string) (*entity.Session, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	sessID, ok := r.tokens[token]
	if !ok {
		return nil, ErrSessionNotFound
	}

	sess, ok := r.sessions[sessID]
	if !ok {
		return nil, ErrSessionNotFound
	}

	if time.Now().After(sess.ExpiresAt) {
		return nil, ErrSessionExpired
	}

	res := *sess
	return &res, nil
}

// GetSessionByID retrieves a session from memory by its primary key ID.
func (r *MemorySessionRepository) GetSessionByID(_ context.Context, id string) (*entity.Session, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	sess, ok := r.sessions[id]
	if !ok {
		return nil, ErrSessionNotFound
	}

	if time.Now().After(sess.ExpiresAt) {
		return nil, ErrSessionExpired
	}

	res := *sess
	return &res, nil
}

// ListSessionsByUserID retrieves all active sessions for a user from memory.
func (r *MemorySessionRepository) ListSessionsByUserID(_ context.Context, userID string) ([]*entity.Session, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	now := time.Now()
	var list []*entity.Session
	for _, sess := range r.sessions {
		if sess.UserID == userID && now.Before(sess.ExpiresAt) {
			cp := *sess
			list = append(list, &cp)
		}
	}
	return list, nil
}

// UpdateSession updates an existing session entity in memory.
func (r *MemorySessionRepository) UpdateSession(_ context.Context, session *entity.Session) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if session == nil || session.ID == "" {
		return ErrSessionNotFound
	}

	existing, ok := r.sessions[session.ID]
	if !ok {
		return ErrSessionNotFound
	}

	// Update token map if token string changed
	if existing.Token != session.Token {
		delete(r.tokens, existing.Token)
		r.tokens[session.Token] = session.ID
	}

	now := time.Now()
	session.UpdatedAt = &now
	cp := *session
	r.sessions[session.ID] = &cp
	return nil
}

// SetActiveOrganization updates the active organization ID for a session in memory.
func (r *MemorySessionRepository) SetActiveOrganization(_ context.Context, sessionID, orgID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	sess, ok := r.sessions[sessionID]
	if !ok {
		return ErrSessionNotFound
	}

	now := time.Now()
	sess.ActiveOrganizationID = &orgID
	sess.UpdatedAt = &now
	return nil
}

// SetActiveTeam updates the active team ID for a session in memory.
func (r *MemorySessionRepository) SetActiveTeam(_ context.Context, sessionID, teamID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	sess, ok := r.sessions[sessionID]
	if !ok {
		return ErrSessionNotFound
	}

	now := time.Now()
	sess.ActiveTeamID = &teamID
	sess.UpdatedAt = &now
	return nil
}

// SaveCustomSessionFields stores dynamic extra metadata for a session in memory.
func (r *MemorySessionRepository) SaveCustomSessionFields(_ context.Context, sessionID string, fields map[string]any) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	sess, ok := r.sessions[sessionID]
	if !ok {
		return ErrSessionNotFound
	}

	cpFields := make(map[string]any, len(fields))
	maps.Copy(cpFields, fields)
	r.customFields[sessionID] = cpFields
	sess.Extra = cpFields

	now := time.Now()
	sess.UpdatedAt = &now
	return nil
}

// GetCustomSessionFields retrieves dynamic extra metadata for a session from memory.
func (r *MemorySessionRepository) GetCustomSessionFields(_ context.Context, sessionID string) (map[string]any, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if _, ok := r.sessions[sessionID]; !ok {
		return nil, ErrSessionNotFound
	}

	fields, ok := r.customFields[sessionID]
	if !ok {
		return make(map[string]any), nil
	}

	res := make(map[string]any, len(fields))
	maps.Copy(res, fields)
	return res, nil
}

// DeleteSession removes a session by token from memory.
func (r *MemorySessionRepository) DeleteSession(_ context.Context, token string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	sessID, ok := r.tokens[token]
	if !ok {
		return nil
	}

	delete(r.tokens, token)
	delete(r.sessions, sessID)
	delete(r.customFields, sessID)
	return nil
}

// DeleteSessionByID removes a session by ID from memory.
func (r *MemorySessionRepository) DeleteSessionByID(_ context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	sess, ok := r.sessions[id]
	if !ok {
		return nil
	}

	delete(r.tokens, sess.Token)
	delete(r.sessions, id)
	delete(r.customFields, id)
	return nil
}

// DeleteSessionsByUserID removes all sessions for a user from memory.
func (r *MemorySessionRepository) DeleteSessionsByUserID(_ context.Context, userID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	for id, sess := range r.sessions {
		if sess.UserID == userID {
			delete(r.tokens, sess.Token)
			delete(r.sessions, id)
			delete(r.customFields, id)
		}
	}
	return nil
}

// DeleteExpiredSessions purges all expired sessions from memory.
func (r *MemorySessionRepository) DeleteExpiredSessions(_ context.Context) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	var count int64
	for id, sess := range r.sessions {
		if now.After(sess.ExpiresAt) {
			delete(r.tokens, sess.Token)
			delete(r.sessions, id)
			delete(r.customFields, id)
			count++
		}
	}
	return count, nil
}
