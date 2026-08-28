package anonymous

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/BladiCreator/go-modular-auth/domain/dto"
	"github.com/BladiCreator/go-modular-auth/domain/entity"
	"github.com/google/uuid"
)

var (
	// ErrInvalidEmailFormat is returned when an anonymous email address fails syntax validation.
	ErrInvalidEmailFormat = errors.New("anonymous: invalid email format")

	// ErrFailedToCreateUser is returned when database insertion of an anonymous user record fails.
	ErrFailedToCreateUser = errors.New("anonymous: failed to create anonymous user")

	// ErrCouldNotCreateSession is returned when database insertion of an anonymous session record fails.
	ErrCouldNotCreateSession = errors.New("anonymous: failed to create session")

	// ErrAnonymousUsersCannotSignInAgain is returned when a user with an active anonymous session attempts to sign in anonymously again.
	ErrAnonymousUsersCannotSignInAgain = errors.New("anonymous: active anonymous user cannot sign in as anonymous again")

	// ErrFailedToDeleteAnonymousUser is returned when database deletion of an anonymous user record fails.
	ErrFailedToDeleteAnonymousUser = errors.New("anonymous: failed to delete anonymous user")

	// ErrFailedToDeleteAnonymousUserSessions is returned when purging sessions for an anonymous user fails.
	ErrFailedToDeleteAnonymousUserSessions = errors.New("anonymous: failed to delete user sessions")

	// ErrUserIsNotAnonymous is returned when an operation intended for guest accounts is attempted on a non-anonymous user.
	ErrUserIsNotAnonymous = errors.New("anonymous: user is not an anonymous account")

	// ErrDeleteAnonymousUserDisabled is returned when attempting to delete an anonymous account while DisableDeleteAnonymousUser is active.
	ErrDeleteAnonymousUserDisabled = errors.New("anonymous: deletion of anonymous users is disabled by configuration")

	// ErrUserNotFound is returned when no user matches the queried user ID.
	ErrUserNotFound = errors.New("anonymous: user not found")

	// ErrRepositoryRequired is returned when initializing the Anonymous plugin without a configured Repository.
	ErrRepositoryRequired = errors.New("anonymous: repository implementation is required")
)

// Repository defines the persistent storage contract required by the Anonymous plugin.
// Implement this interface on your custom database adapter (e.g. PostgreSQL, MySQL, SQLite, MongoDB, GORM, Redis).
//
// # Implementation Example (GORM / database/sql):
//
//	type GormAnonymousRepository struct {
//		db *gorm.DB
//	}
//
//	func (r *GormAnonymousRepository) CreateAnonymousUser(ctx context.Context, email, name string) (*entity.User, error) {
//		u := &entity.User{
//			ID:          uuid.NewString(),
//			Name:        name,
//			Email:       email,
//			IsAnonymous: true,
//			CreatedAt:   time.Now(),
//			UpdatedAt:   time.Now(),
//		}
//		if err := r.db.WithContext(ctx).Create(u).Error; err != nil {
//			return nil, anonymous.ErrFailedToCreateUser
//		}
//		return u, nil
//	}
//
// # Storage and Caching Recommendation (Redis / Cache-Aside Strategy):
//
// Because anonymous user validation occurs frequently on guest interactions, decorating
// repository queries with Redis or an in-memory Cache-Aside layer optimizes performance:
//
//	type CachedAnonymousRepository struct {
//		dbRepo anonymous.Repository
//		redis  *redis.Client
//		ttl    time.Duration
//	}
//
//	func (r *CachedAnonymousRepository) GetUserByID(ctx context.Context, userID string) (*entity.User, error) {
//		cacheKey := "user:" + userID
//		val, err := r.redis.Get(ctx, cacheKey).Bytes()
//		if err == nil {
//			var u entity.User
//			if json.Unmarshal(val, &u) == nil {
//				return &u, nil
//			}
//		}
//		u, err := r.dbRepo.GetUserByID(ctx, userID)
//		if err != nil {
//			return nil, err
//		}
//		bytes, _ := json.Marshal(u)
//		r.redis.Set(ctx, cacheKey, bytes, r.ttl)
//		return u, nil
//	}
type Repository interface {
	// CreateAnonymousUser persists a new guest user entity with IsAnonymous set to true.
	//
	// Function:
	//   Called during anonymous sign-in (POST /sign-in/anonymous) to create a temporary guest user.
	//
	// Storage:
	//   Database (GORM / SQL) - Inserts a record into the users table with is_anonymous = true.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - email: Generated temporary email address (e.g. temp-{uuid}@anonymous.local).
	//   - name: Display name for the anonymous user (e.g. "Anonymous").
	//
	// Returns:
	//   - *entity.User: Newly created user entity.
	//   - error: ErrFailedToCreateUser or infrastructure database error.
	//
	// Example SQL:
	//   INSERT INTO users (id, name, email, is_anonymous, created_at, updated_at) VALUES ($1, $2, $3, true, NOW(), NOW()) RETURNING *;
	CreateAnonymousUser(ctx context.Context, email, name string) (*entity.User, error)

	// CreateSession persists a new session associated with an anonymous user.
	//
	// Function:
	//   Called during anonymous sign-in to issue and store a valid session token.
	//
	// Storage:
	//   Database (GORM / SQL) - Inserts a record into the sessions table.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - params: Session parameters including UserID, Token, IPAddress, UserAgent, and Expiry.
	//
	// Returns:
	//   - *entity.Session: Newly created session entity.
	//   - error: ErrCouldNotCreateSession or infrastructure database error.
	//
	// Example SQL:
	//   INSERT INTO sessions (id, user_id, token, ip_address, user_agent, expires_at, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *;
	CreateSession(ctx context.Context, params *dto.CreateSessionParams) (*entity.Session, error)

	// GetUserByID fetches a user entity by primary key ID.
	//
	// Function:
	//   Used to verify whether a user exists and check their IsAnonymous status.
	//
	// Storage:
	//   Both (Cache-Aside Strategy) - Relational DB lookup with optional Redis caching.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - userID: Target user primary key identifier.
	//
	// Returns:
	//   - *entity.User: User entity if found.
	//   - error: ErrUserNotFound if missing, or infrastructure error.
	//
	// Example SQL:
	//   SELECT id, name, email, is_anonymous, created_at, updated_at FROM users WHERE id = $1 LIMIT 1;
	GetUserByID(ctx context.Context, userID string) (*entity.User, error)

	// DeleteUser removes a user record from persistent storage by ID.
	//
	// Function:
	//   Invoked during anonymous account cleanup (after linking or explicit deletion).
	//
	// Storage:
	//   Database (GORM / SQL) - Deletes record from users table.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - userID: Target user primary key identifier to purge.
	//
	// Returns:
	//   - error: Nil on success, ErrUserNotFound if missing, or ErrFailedToDeleteAnonymousUser.
	//
	// Example SQL:
	//   DELETE FROM users WHERE id = $1 AND is_anonymous = true;
	DeleteUser(ctx context.Context, userID string) error

	// DeleteUserSessions removes all active session records for a specified user ID.
	//
	// Function:
	//   Invoked prior to purging an anonymous user to invalidate all active session tokens.
	//
	// Storage:
	//   Database (GORM / SQL) - Deletes associated records from sessions table.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - userID: Target user primary key identifier whose sessions should be removed.
	//
	// Returns:
	//   - error: Nil on success, or ErrFailedToDeleteAnonymousUserSessions.
	//
	// Example SQL:
	//   DELETE FROM sessions WHERE user_id = $1;
	DeleteUserSessions(ctx context.Context, userID string) error
}

// MemoryRepository provides a thread-safe, in-memory implementation of Repository for testing and lightweight usage.
type MemoryRepository struct {
	mu       sync.RWMutex
	users    map[string]*entity.User
	sessions map[string]*entity.Session
}

// NewMemoryRepository initializes a fresh MemoryRepository instance.
func NewMemoryRepository() *MemoryRepository {
	return &MemoryRepository{
		users:    make(map[string]*entity.User),
		sessions: make(map[string]*entity.Session),
	}
}

// CreateAnonymousUser stores a new anonymous user record in memory.
func (r *MemoryRepository) CreateAnonymousUser(_ context.Context, email, name string) (*entity.User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	u := &entity.User{
		ID:          uuid.NewString(),
		Name:        name,
		Email:       email,
		IsAnonymous: true,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	r.users[u.ID] = u
	return u, nil
}

// CreateSession stores a new session record in memory.
func (r *MemoryRepository) CreateSession(_ context.Context, params *dto.CreateSessionParams) (*entity.Session, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	sess := &entity.Session{
		ID:        uuid.NewString(),
		UserID:    params.UserID,
		Token:     params.Token,
		IPAddress: params.IPAddress,
		UserAgent: params.UserAgent,
		ExpiresAt: params.ExpiresAt,
		CreatedAt: params.CreatedAt,
	}

	r.sessions[sess.ID] = sess
	return sess, nil
}

// GetUserByID retrieves a user record from memory by ID.
func (r *MemoryRepository) GetUserByID(_ context.Context, userID string) (*entity.User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	u, ok := r.users[userID]
	if !ok {
		return nil, ErrUserNotFound
	}
	return u, nil
}

// DeleteUser removes a user record from memory by ID.
func (r *MemoryRepository) DeleteUser(_ context.Context, userID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, ok := r.users[userID]; !ok {
		return ErrUserNotFound
	}
	delete(r.users, userID)
	return nil
}

// DeleteUserSessions removes all session records matching the specified user ID from memory.
func (r *MemoryRepository) DeleteUserSessions(_ context.Context, userID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	for id, sess := range r.sessions {
		if sess.UserID == userID {
			delete(r.sessions, id)
		}
	}
	return nil
}
