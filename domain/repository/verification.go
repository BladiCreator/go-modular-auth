package repository

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/BladiCreator/go-modular-auth/domain"
	"github.com/BladiCreator/go-modular-auth/domain/entity"
	"uuid"
)

var (
	// ErrVerificationNotFound is returned when no verification record matches the queried identifier.
	ErrVerificationNotFound = domain.ErrVerificationNotFound

	// ErrVerificationExpired is returned when a retrieved verification record has passed its expiration time.
	ErrVerificationExpired = domain.ErrVerificationExpired

	// ErrInvalidVerification is returned when creating or updating with nil or missing parameters.
	ErrInvalidVerification = errors.New("repository: invalid verification record")
)

// VerificationRepository defines the persistent storage contract for ephemeral verification records (e.g. tokens, OTPs, recovery codes).
// Implement this interface on your custom database adapter (e.g. PostgreSQL, MySQL, SQLite, MongoDB, GORM, Redis).
//
// # Implementation Example (GORM / database/sql):
//
//	type GormVerificationRepository struct {
//		db *gorm.DB
//	}
//
//	func (r *GormVerificationRepository) CreateVerification(ctx context.Context, record *entity.Verification) error {
//		return r.db.WithContext(ctx).Clauses(clause.OnConflict{
//			Columns:   []clause.Column{{Name: "identifier"}},
//			DoUpdates: clause.AssignmentColumns([]string{"value", "expires_at", "updated_at"}),
//		}).Create(record).Error
//	}
//
//	func (r *GormVerificationRepository) FindVerification(ctx context.Context, identifier string) (*entity.Verification, error) {
//		var rec entity.Verification
//		if err := r.db.WithContext(ctx).Where("identifier = ?", identifier).First(&rec).Error; err != nil {
//			if errors.Is(err, gorm.ErrRecordNotFound) {
//				return nil, repository.ErrVerificationNotFound
//			}
//			return nil, err
//		}
//		return &rec, nil
//	}
//
//	func (r *GormVerificationRepository) ConsumeVerification(ctx context.Context, identifier string) (*entity.Verification, error) {
//		var rec entity.Verification
//		err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
//			if err := tx.Where("identifier = ?", identifier).First(&rec).Error; err != nil {
//				return err
//			}
//			return tx.Delete(&rec).Error
//		})
//		if err != nil {
//			if errors.Is(err, gorm.ErrRecordNotFound) {
//				return nil, repository.ErrVerificationNotFound
//			}
//			return nil, err
//		}
//		return &rec, nil
//	}
//
//	func (r *GormVerificationRepository) DeleteVerification(ctx context.Context, identifier string) error {
//		return r.db.WithContext(ctx).Where("identifier = ?", identifier).Delete(&entity.Verification{}).Error
//	}
//
// # Storage and Caching Recommendation (Redis / Atomic Ephemeral Storage):
//
// Ephemeral verification tokens, OTPs, and magic link secrets benefit from Redis TTL and atomic single-use
// consumption (`GETDEL`), which inherently prevents replay attacks and double-click race conditions without periodic DB sweeps:
//
//	type RedisVerificationRepository struct {
//		redis *redis.Client
//	}
//
//	func (r *RedisVerificationRepository) CreateVerification(ctx context.Context, record *entity.Verification) error {
//		data, _ := json.Marshal(record)
//		ttl := time.Until(record.ExpiresAt)
//		return r.redis.Set(ctx, "verification:"+record.Identifier, data, ttl).Err()
//	}
//
//	func (r *RedisVerificationRepository) ConsumeVerification(ctx context.Context, identifier string) (*entity.Verification, error) {
//		key := "verification:" + identifier
//		data, err := r.redis.GetDel(ctx, key).Bytes()
//		if err != nil {
//			return nil, repository.ErrVerificationNotFound
//		}
//		var rec entity.Verification
//		_ = json.Unmarshal(data, &rec)
//		return &rec, nil
//	}
type VerificationRepository interface {
	// CreateVerification creates or replaces an ephemeral verification record in persistent storage.
	//
	// Function:
	//   Called during OTP generation, password reset request, email verification dispatch,
	//   magic link issuance, or OTT creation to persist the verification token.
	//
	// Storage:
	//   Cache (Redis / In-Memory TTL) or Database (GORM / SQL upsert on identifier).
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - record: Verification entity containing ID, Identifier, Value, and ExpiresAt.
	//
	// Returns:
	//   - error: Nil on success, or database error on failure.
	//
	// Example SQL:
	//   INSERT INTO verifications (id, identifier, value, expires_at, created_at, updated_at)
	//   VALUES ($1, $2, $3, $4, $5, $6)
	//   ON CONFLICT (identifier) DO UPDATE SET value = EXCLUDED.value, expires_at = EXCLUDED.expires_at, updated_at = EXCLUDED.updated_at;
	//
	// Example Cache (Redis):
	//   err := rdb.Set(ctx, "verification:" + record.Identifier, bytes, ttl).Err()
	CreateVerification(ctx context.Context, record *entity.Verification) error

	// FindVerification retrieves an unconsumed verification record matching the unique identifier.
	//
	// Function:
	//   Used to inspect an active verification record without deleting it (e.g. checking remaining attempts or expiration).
	//
	// Storage:
	//   Cache (Redis / In-Memory TTL) or Database (GORM / SQL query by identifier).
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - identifier: The composite lookup key (email, phone number, or raw token string).
	//
	// Returns:
	//   - *entity.Verification: The matching verification record if found.
	//   - error: ErrVerificationNotFound if not found, ErrVerificationExpired if expired, or database error.
	//
	// Example SQL:
	//   SELECT id, identifier, value, expires_at, created_at, updated_at FROM verifications WHERE identifier = $1 LIMIT 1;
	//
	// Example Cache (Redis):
	//   val, err := rdb.Get(ctx, "verification:" + identifier).Bytes()
	FindVerification(ctx context.Context, identifier string) (*entity.Verification, error)

	// ConsumeVerification atomically retrieves and deletes a verification record in a single transaction.
	// This provides strict single-use anti-replay protection under high concurrency.
	//
	// Function:
	//   Called during password reset confirmation, email verification, OTP submission,
	//   magic link consumption, or OTT exchange.
	//
	// Storage:
	//   Cache (Redis GETDEL) or Database (SQL DELETE ... RETURNING or transactional read + delete).
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - identifier: The composite lookup key.
	//
	// Returns:
	//   - *entity.Verification: The consumed verification record if found.
	//   - error: ErrVerificationNotFound if not found, ErrVerificationExpired if expired, or database error.
	//
	// Example SQL:
	//   DELETE FROM verifications WHERE identifier = $1 RETURNING id, identifier, value, expires_at, created_at, updated_at;
	//
	// Example Cache (Redis):
	//   val, err := rdb.GetDel(ctx, "verification:" + identifier).Bytes()
	ConsumeVerification(ctx context.Context, identifier string) (*entity.Verification, error)

	// DeleteVerification removes a verification record from persistent storage by its identifier key.
	//
	// Function:
	//   Explicit invalidation or cleanup of a verification record.
	//
	// Storage:
	//   Cache (Redis / In-Memory TTL) or Database (GORM / SQL DELETE).
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - identifier: The composite lookup key.
	//
	// Returns:
	//   - error: Nil on success, or database error on failure.
	//
	// Example SQL:
	//   DELETE FROM verifications WHERE identifier = $1;
	//
	// Example Cache (Redis):
	//   err := rdb.Del(ctx, "verification:" + identifier).Err()
	DeleteVerification(ctx context.Context, identifier string) error
}

// MemoryVerificationRepository provides a thread-safe, in-memory implementation of VerificationRepository.
type MemoryVerificationRepository struct {
	mu      sync.RWMutex
	records map[string]*entity.Verification // key: identifier
}

// NewMemoryVerificationRepository initializes and returns a fresh, thread-safe in-memory VerificationRepository.
func NewMemoryVerificationRepository() *MemoryVerificationRepository {
	return &MemoryVerificationRepository{
		records: make(map[string]*entity.Verification),
	}
}

// CreateVerification stores or overwrites a verification record in memory.
func (r *MemoryVerificationRepository) CreateVerification(_ context.Context, record *entity.Verification) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if record == nil || record.Identifier == "" {
		return ErrInvalidVerification
	}

	cp := *record
	if cp.ID == "" {
		cp.ID = uuid.NewV7().String()
	}
	if cp.CreatedAt.IsZero() {
		cp.CreatedAt = time.Now()
	}
	r.records[cp.Identifier] = &cp
	return nil
}

// FindVerification retrieves an unconsumed verification record by identifier from memory.
func (r *MemoryVerificationRepository) FindVerification(_ context.Context, identifier string) (*entity.Verification, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	rec, ok := r.records[identifier]
	if !ok {
		return nil, ErrVerificationNotFound
	}

	if time.Now().After(rec.ExpiresAt) {
		return nil, ErrVerificationExpired
	}

	cp := *rec
	return &cp, nil
}

// ConsumeVerification atomically retrieves and deletes a verification record by identifier from memory.
func (r *MemoryVerificationRepository) ConsumeVerification(_ context.Context, identifier string) (*entity.Verification, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	rec, ok := r.records[identifier]
	if !ok {
		return nil, ErrVerificationNotFound
	}

	delete(r.records, identifier)

	if time.Now().After(rec.ExpiresAt) {
		return nil, ErrVerificationExpired
	}

	cp := *rec
	return &cp, nil
}

// DeleteVerification removes a verification record by identifier from memory.
func (r *MemoryVerificationRepository) DeleteVerification(_ context.Context, identifier string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	delete(r.records, identifier)
	return nil
}
