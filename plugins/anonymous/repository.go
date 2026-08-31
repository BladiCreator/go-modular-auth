package anonymous

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/BladiCreator/go-modular-auth/domain/entity"
	"github.com/BladiCreator/go-modular-auth/domain/repository"
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
type Repository interface {
	repository.SessionRepository

	// CreateAnonymousUser persists a new guest user entity with IsAnonymous set to true.
	CreateAnonymousUser(ctx context.Context, email, name string) (*entity.User, error)

	// GetUserByID fetches a user entity by primary key ID.
	GetUserByID(ctx context.Context, userID string) (*entity.User, error)

	// DeleteUser removes a user record from persistent storage by ID.
	DeleteUser(ctx context.Context, userID string) error
}

// MemoryRepository provides a thread-safe, in-memory implementation of Repository for testing and lightweight usage.
type MemoryRepository struct {
	*repository.MemorySessionRepository
	mu    sync.RWMutex
	users map[string]*entity.User
}

// NewMemoryRepository initializes a fresh MemoryRepository instance.
func NewMemoryRepository() *MemoryRepository {
	return &MemoryRepository{
		MemorySessionRepository: repository.NewMemorySessionRepository(),
		users:                   make(map[string]*entity.User),
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
