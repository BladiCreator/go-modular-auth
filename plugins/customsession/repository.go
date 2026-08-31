package customsession

import (
	"context"
	"errors"
	"maps"
	"sync"

	"github.com/BladiCreator/go-modular-auth/domain/repository"
)

var (
	// ErrSessionNotFound is returned when a requested session entity does not exist in storage.
	ErrSessionNotFound = errors.New("customsession: session not found")

	// ErrInvalidTransformResult is returned when a transform callback returns an incompatible data structure.
	ErrInvalidTransformResult = errors.New("customsession: invalid transform result")

	// ErrRepositoryRequired is returned when an operation requires persistent storage but no repository was supplied.
	ErrRepositoryRequired = errors.New("customsession: repository implementation required")
)

// Repository defines the persistent storage contract required by the CustomSession plugin.
// Implement this interface on your custom database adapter (e.g. PostgreSQL, MySQL, SQLite, MongoDB, GORM, Redis).
type Repository interface {
	repository.SessionRepository

	// GetCustomUserFields retrieves dynamic additional fields associated with a specific user ID.
	GetCustomUserFields(ctx context.Context, userID string) (map[string]any, error)

	// SaveCustomUserFields persists dynamic additional fields for a specific user ID.
	SaveCustomUserFields(ctx context.Context, userID string, fields map[string]any) error
}

// MemoryRepository provides a thread-safe in-memory implementation of the Repository interface.
type MemoryRepository struct {
	*repository.MemorySessionRepository
	mu         sync.RWMutex
	userFields map[string]map[string]any
}

// NewMemoryRepository initializes and returns a new thread-safe in-memory custom session repository.
func NewMemoryRepository() *MemoryRepository {
	return &MemoryRepository{
		MemorySessionRepository: repository.NewMemorySessionRepository(),
		userFields:              make(map[string]map[string]any),
	}
}

// GetCustomUserFields retrieves dynamic user fields from in-memory storage.
func (m *MemoryRepository) GetCustomUserFields(ctx context.Context, userID string) (map[string]any, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	fields, ok := m.userFields[userID]
	if !ok {
		return make(map[string]any), nil
	}
	result := make(map[string]any, len(fields))
	maps.Copy(result, fields)
	return result, nil
}

// SaveCustomUserFields stores dynamic user fields in in-memory storage.
func (m *MemoryRepository) SaveCustomUserFields(ctx context.Context, userID string, fields map[string]any) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	copyMap := make(map[string]any, len(fields))
	maps.Copy(copyMap, fields)
	m.userFields[userID] = copyMap
	return nil
}
