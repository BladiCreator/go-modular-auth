package customsession

import (
	"context"
	"errors"
	"sync"
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
//
// # Implementation Example (GORM / database/sql):
//
//	type GormCustomSessionRepository struct {
//		db *gorm.DB
//	}
//
//	func (r *GormCustomSessionRepository) GetCustomUserFields(ctx context.Context, userID string) (map[string]any, error) {
//		var fields JSONBMap
//		if err := r.db.WithContext(ctx).Table("users").Select("extra_fields").Where("id = ?", userID).Scan(&fields).Error; err != nil {
//			return nil, err
//		}
//		return fields, nil
//	}
//
// # Storage and Caching Recommendation (Redis / Cache-Aside Strategy):
//
// Because dynamic user and session custom fields may be read on every authenticated HTTP request,
// decorating your database repository with Redis or an in-memory Cache-Aside wrapper is recommended:
//
//	type CachedCustomSessionRepository struct {
//		dbRepo customsession.Repository
//		redis  *redis.Client
//		ttl    time.Duration
//	}
//
//	func (r *CachedCustomSessionRepository) GetCustomUserFields(ctx context.Context, userID string) (map[string]any, error) {
//		cacheKey := "user_fields:" + userID
//		val, err := r.redis.Get(ctx, cacheKey).Bytes()
//		if err == nil {
//			var fields map[string]any
//			if json.Unmarshal(val, &fields) == nil {
//				return fields, nil
//			}
//		}
//		fields, err := r.dbRepo.GetCustomUserFields(ctx, userID)
//		if err != nil {
//			return nil, err
//		}
//		bytes, _ := json.Marshal(fields)
//		r.redis.Set(ctx, cacheKey, bytes, r.ttl)
//		return fields, nil
//	}
type Repository interface {
	// GetCustomUserFields retrieves dynamic additional fields associated with a specific user ID.
	//
	// Function:
	//   Called during session transformation or user retrieval to load persisted extra metadata.
	//
	// Storage:
	//   Database (GORM / SQL) or Redis Cache-Aside.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - userID: Unique identifier of the target user.
	//
	// Returns:
	//   - map[string]any: Key-value map of dynamic user fields.
	//   - error: Database query error if execution fails.
	//
	// Example SQL:
	//   SELECT extra_fields FROM users WHERE id = $1 LIMIT 1;
	GetCustomUserFields(ctx context.Context, userID string) (map[string]any, error)

	// SaveCustomUserFields persists dynamic additional fields for a specific user ID.
	//
	// Function:
	//   Called when updating or initializing dynamic user attributes.
	//
	// Storage:
	//   Database (GORM / SQL).
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - userID: Unique identifier of the target user.
	//   - fields: Key-value map of dynamic extra fields to persist.
	//
	// Returns:
	//   - error: Database execution error if update fails.
	//
	// Example SQL:
	//   UPDATE users SET extra_fields = $2 WHERE id = $1;
	SaveCustomUserFields(ctx context.Context, userID string, fields map[string]any) error

	// GetCustomSessionFields retrieves dynamic additional fields associated with a specific session ID.
	//
	// Function:
	//   Called during session payload transformation to load custom session metadata.
	//
	// Storage:
	//   Database (GORM / SQL) or Redis Cache-Aside.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - sessionID: Unique identifier of the target active session.
	//
	// Returns:
	//   - map[string]any: Key-value map of dynamic session fields.
	//   - error: Database query error if execution fails.
	//
	// Example SQL:
	//   SELECT extra_fields FROM sessions WHERE id = $1 LIMIT 1;
	GetCustomSessionFields(ctx context.Context, sessionID string) (map[string]any, error)

	// SaveCustomSessionFields persists dynamic additional fields for a specific session ID.
	//
	// Function:
	//   Called when storing dynamic session attributes during sign-in or session updates.
	//
	// Storage:
	//   Database (GORM / SQL).
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - sessionID: Unique identifier of the target active session.
	//   - fields: Key-value map of dynamic extra fields to persist.
	//
	// Returns:
	//   - error: Database execution error if update fails.
	//
	// Example SQL:
	//   UPDATE sessions SET extra_fields = $2 WHERE id = $1;
	SaveCustomSessionFields(ctx context.Context, sessionID string, fields map[string]any) error
}

// MemoryRepository provides a thread-safe in-memory implementation of the Repository interface.
type MemoryRepository struct {
	mu            sync.RWMutex
	userFields    map[string]map[string]any
	sessionFields map[string]map[string]any
}

// NewMemoryRepository initializes and returns a new thread-safe in-memory custom session repository.
func NewMemoryRepository() *MemoryRepository {
	return &MemoryRepository{
		userFields:    make(map[string]map[string]any),
		sessionFields: make(map[string]map[string]any),
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
	for k, v := range fields {
		result[k] = v
	}
	return result, nil
}

// SaveCustomUserFields stores dynamic user fields in in-memory storage.
func (m *MemoryRepository) SaveCustomUserFields(ctx context.Context, userID string, fields map[string]any) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	copyMap := make(map[string]any, len(fields))
	for k, v := range fields {
		copyMap[k] = v
	}
	m.userFields[userID] = copyMap
	return nil
}

// GetCustomSessionFields retrieves dynamic session fields from in-memory storage.
func (m *MemoryRepository) GetCustomSessionFields(ctx context.Context, sessionID string) (map[string]any, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	fields, ok := m.sessionFields[sessionID]
	if !ok {
		return make(map[string]any), nil
	}
	result := make(map[string]any, len(fields))
	for k, v := range fields {
		result[k] = v
	}
	return result, nil
}

// SaveCustomSessionFields stores dynamic session fields in in-memory storage.
func (m *MemoryRepository) SaveCustomSessionFields(ctx context.Context, sessionID string, fields map[string]any) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	copyMap := make(map[string]any, len(fields))
	for k, v := range fields {
		copyMap[k] = v
	}
	m.sessionFields[sessionID] = copyMap
	return nil
}
