package bearer

import (
	"context"
	"errors"

	"github.com/BladiCreator/go-modular-auth/domain/entity"
)

var (
	// ErrInvalidTokenFormat is returned when a signed token string does not adhere to the "<token>.<signature>" format.
	ErrInvalidTokenFormat = errors.New("bearer: invalid token format")

	// ErrInvalidSignature is returned when the cryptographic HMAC-SHA256 signature verification fails.
	ErrInvalidSignature = errors.New("bearer: signature verification failed")

	// ErrTokenEmpty is returned when an empty token string or header is provided.
	ErrTokenEmpty = errors.New("bearer: token is empty")

	// ErrInvalidHeader is returned when an authorization header does not start with the required "Bearer " prefix.
	ErrInvalidHeader = errors.New("bearer: invalid authorization header scheme")

	// ErrSecretRequired is returned when signing or verifying tokens without a configured Secret key.
	ErrSecretRequired = errors.New("bearer: secret key is required for token signing and verification")

	// ErrSessionNotFound is returned when a verified token does not match any active session in the database.
	ErrSessionNotFound = errors.New("bearer: session not found")

	// ErrSessionExpired is returned when a retrieved session has exceeded its validity timestamp.
	ErrSessionExpired = errors.New("bearer: session has expired")
)

// Repository defines the persistent storage contract required by the Bearer plugin to look up active sessions.
// Implement this interface on your custom database adapter (e.g. PostgreSQL, MySQL, MongoDB, GORM, Redis).
//
// # Implementation Example (GORM / database/sql):
//
//	type GormBearerRepository struct {
//		db *gorm.DB
//	}
//
//	func (r *GormBearerRepository) GetSessionByToken(ctx context.Context, token string) (*entity.Session, error) {
//		var s entity.Session
//		if err := r.db.WithContext(ctx).Where("token = ?", token).First(&s).Error; err != nil {
//			if errors.Is(err, gorm.ErrRecordNotFound) {
//				return nil, bearer.ErrSessionNotFound
//			}
//			return nil, err
//		}
//		return &s, nil
//	}
//
// # Storage and Caching Recommendation (Redis / Cache-Aside Strategy):
//
// Because `GetSessionByToken` is invoked on **every Bearer-authenticated API request**, querying
// the relational database on every HTTP call can become a performance bottleneck.
//
// Decorating your database repository with Redis or an in-memory Cache-Aside wrapper is strongly recommended:
//
//	type CachedBearerRepository struct {
//		dbRepo bearer.Repository
//		redis  *redis.Client
//		ttl    time.Duration
//	}
//
//	func (r *CachedBearerRepository) GetSessionByToken(ctx context.Context, token string) (*entity.Session, error) {
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
type Repository interface {
	// GetSessionByToken retrieves an active session by its raw token identifier.
	//
	// Function:
	//   Queries storage for the session entity associated with the verified raw token string.
	//
	// Storage:
	//   Both (Cache-Aside Strategy) - High-frequency lookup per HTTP request.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - token: Raw session token string (unstripped of HMAC signature).
	//
	// Returns:
	//   - *entity.Session: Active session entity if found.
	//   - error: ErrSessionNotFound if not found, or infrastructure error.
	//
	// Example SQL:
	//   SELECT id, user_id, token, expires_at, created_at, ip_address, user_agent FROM sessions WHERE token = $1 LIMIT 1;
	//
	// Example Cache (Redis):
	//   val, err := rdb.Get(ctx, "session:" + token).Bytes()
	GetSessionByToken(ctx context.Context, token string) (*entity.Session, error)
}
