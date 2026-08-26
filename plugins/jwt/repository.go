package jwt

import (
	"context"
	"errors"
	"time"
)

var (
	// ErrKeyNotFound is returned when no active or matching signing key is found in the repository.
	ErrKeyNotFound = errors.New("jwt: signing key not found in repository")

	// ErrInvalidToken is returned when a JWT string does not adhere to the 3-part RFC 7519 format.
	ErrInvalidToken = errors.New("jwt: invalid token format")

	// ErrTokenExpired is returned when a token's 'exp' claim is prior to the current verification time.
	ErrTokenExpired = errors.New("jwt: token has expired")

	// ErrTokenNotValidYet is returned when a token's 'nbf' claim is subsequent to the current verification time.
	ErrTokenNotValidYet = errors.New("jwt: token is not valid yet (nbf)")

	// ErrInvalidSignature is returned when cryptographic signature verification fails.
	ErrInvalidSignature = errors.New("jwt: invalid token signature")

	// ErrMissingKid is returned when a token's JWS header lacks the required 'kid' (Key ID) parameter.
	ErrMissingKid = errors.New("jwt: token header missing 'kid'")

	// ErrDecryptionFailed is returned when an encrypted private key cannot be decrypted with the configured secret.
	ErrDecryptionFailed = errors.New("jwt: failed to decrypt private key with configured secret")

	// ErrUnsupportedAlgorithm is returned when an unsupported or unrecognized signature algorithm is requested.
	ErrUnsupportedAlgorithm = errors.New("jwt: unsupported signature algorithm")

	// ErrSecretRequired is returned when private key encryption is enabled but no secret key is provided.
	ErrSecretRequired = errors.New("jwt: secret key is required for private key encryption")

	// ErrSessionNotFound is returned when attempting to generate a token for an invalid or missing session.
	ErrSessionNotFound = errors.New("jwt: session not found")

	// ErrSessionExpired is returned when the provided session has expired.
	ErrSessionExpired = errors.New("jwt: session has expired")
)

// Algorithm defines the cryptographic signature algorithm type.
type Algorithm string

// JWKRecord represents the persisted cryptographic key-pair record in the database.
type JWKRecord struct {
	// ID is the unique Key ID ("kid") assigned to this key-pair.
	ID string `json:"id"`

	// PublicKey is the serialized JSON representation of the RFC 7517 public JWK.
	PublicKey string `json:"publicKey"`

	// PrivateKey is the serialized private key bytes or base64url-encoded AES-256-GCM ciphertext.
	PrivateKey string `json:"privateKey"`

	// Algorithm specifies the JWS signing algorithm (e.g. EdDSA, ES256, RS256).
	Algorithm Algorithm `json:"alg"`

	// Curve specifies the elliptic curve name for EC/OKP keys (e.g. "Ed25519", "P-256", "P-521").
	Curve string `json:"crv,omitempty"`

	// CreatedAt is the timestamp when the key-pair was generated.
	CreatedAt time.Time `json:"createdAt"`

	// ExpiresAt is the optional expiration timestamp after which this key is rotated out of active signing.
	ExpiresAt *time.Time `json:"expiresAt,omitempty"`
}

// JWK represents a single JSON Web Key conforming to RFC 7517.
type JWK struct {
	// Kty is the Key Type ("OKP", "EC", "RSA").
	Kty string `json:"kty"`

	// Kid is the unique Key ID string.
	Kid string `json:"kid"`

	// Use specifies the intended public key use (usually "sig").
	Use string `json:"use,omitempty"`

	// Alg identifies the cryptographic algorithm intended for use with the key.
	Alg string `json:"alg,omitempty"`

	// Crv identifies the cryptographic curve (for "OKP" and "EC" keys).
	Crv string `json:"crv,omitempty"`

	// X contains the Base64URL-encoded public key coordinate (or public Ed25519 key).
	X string `json:"x,omitempty"`

	// Y contains the Base64URL-encoded Y coordinate (for EC keys).
	Y string `json:"y,omitempty"`

	// N contains the Base64URL-encoded RSA modulus.
	N string `json:"n,omitempty"`

	// E contains the Base64URL-encoded RSA exponent.
	E string `json:"e,omitempty"`
}

// JWKS represents a JSON Web Key Set conforming to RFC 7517.
type JWKS struct {
	// Keys is the collection of public JSON Web Keys.
	Keys []JWK `json:"keys"`
}

// Repository defines the persistent storage contract required by the JWT plugin to manage key-pairs.
// Implement this interface on your custom database adapter (e.g. PostgreSQL, MySQL, SQLite, MongoDB, GORM).
//
// # Implementation Example (GORM / SQL):
//
//	type GormJWKRepository struct {
//		db *gorm.DB
//	}
//
//	func (r *GormJWKRepository) GetLatestKey(ctx context.Context) (*jwt.JWKRecord, error) {
//		var rec jwt.JWKRecord
//		err := r.db.WithContext(ctx).Order("created_at DESC").First(&rec).Error
//		if err != nil {
//			if errors.Is(err, gorm.ErrRecordNotFound) {
//				return nil, jwt.ErrKeyNotFound
//			}
//			return nil, err
//		}
//		return &rec, nil
//	}
//
//	func (r *GormJWKRepository) GetKeyByID(ctx context.Context, id string) (*jwt.JWKRecord, error) {
//		var rec jwt.JWKRecord
//		err := r.db.WithContext(ctx).Where("id = ?", id).First(&rec).Error
//		if err != nil {
//			if errors.Is(err, gorm.ErrRecordNotFound) {
//				return nil, jwt.ErrKeyNotFound
//			}
//			return nil, err
//		}
//		return &rec, nil
//	}
//
//	func (r *GormJWKRepository) GetAllKeys(ctx context.Context) ([]*jwt.JWKRecord, error) {
//		var records []*jwt.JWKRecord
//		err := r.db.WithContext(ctx).Order("created_at DESC").Find(&records).Error
//		return records, err
//	}
//
//	func (r *GormJWKRepository) CreateKey(ctx context.Context, record *jwt.JWKRecord) error {
//		return r.db.WithContext(ctx).Create(record).Error
//	}
//
//	func (r *GormJWKRepository) DeleteKey(ctx context.Context, id string) error {
//		return r.db.WithContext(ctx).Where("id = ?", id).Delete(&jwt.JWKRecord{}).Error
//	}
//
// # Storage and Caching Recommendation (In-Memory Key Caching):
//
// Cryptographic signing keys (JWKs) change infrequently. Caching the active signing key and
// public key set in local application memory avoids redundant database queries on token issuance.
//
// Recommended In-Memory Decorator Example:
//
//	type CachedJWKRepository struct {
//		dbRepo jwt.Repository
//		mu     sync.RWMutex
//		latest *jwt.JWKRecord
//		byID   map[string]*jwt.JWKRecord
//	}
//
//	func (r *CachedJWKRepository) GetLatestKey(ctx context.Context) (*jwt.JWKRecord, error) {
//		r.mu.RLock()
//		if r.latest != nil {
//			defer r.mu.RUnlock()
//			return r.latest, nil
//		}
//		r.mu.RUnlock()
//		rec, err := r.dbRepo.GetLatestKey(ctx)
//		if err == nil {
//			r.mu.Lock()
//			r.latest = rec
//			r.mu.Unlock()
//		}
//		return rec, err
//	}
type Repository interface {
	// GetLatestKey retrieves the most recently created signing key record.
	//
	// Function:
	//   Used during initialization and token signing to acquire the active private key.
	//
	// Storage:
	//   Both (Cache-Aside Strategy) - Cached in memory/Redis to eliminate DB lookups per token signing.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//
	// Returns:
	//   - *JWKRecord: The latest active key record.
	//   - error: ErrKeyNotFound if no keys exist, or database error.
	//
	// Example SQL:
	//   SELECT id, public_key, private_key, alg, crv, created_at, expires_at FROM jwks ORDER BY created_at DESC LIMIT 1;
	//
	// Example Cache (In-Memory/Redis):
	//   val, err := rdb.Get(ctx, "jwks:latest").Bytes()
	GetLatestKey(ctx context.Context) (*JWKRecord, error)

	// GetKeyByID retrieves a specific key-pair record by its unique Key ID ("kid").
	//
	// Function:
	//   Used during token verification to locate the public/private key matching the token's header 'kid'.
	//
	// Storage:
	//   Both (Cache-Aside Strategy) - Cached in memory/Redis by kid.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - id: Unique Key ID string ("kid").
	//
	// Returns:
	//   - *JWKRecord: The matching key record.
	//   - error: ErrKeyNotFound if not found, or database error.
	//
	// Example SQL:
	//   SELECT id, public_key, private_key, alg, crv, created_at, expires_at FROM jwks WHERE id = $1 LIMIT 1;
	//
	// Example Cache (In-Memory/Redis):
	//   val, err := rdb.Get(ctx, "jwks:kid:" + id).Bytes()
	GetKeyByID(ctx context.Context, id string) (*JWKRecord, error)

	// GetAllKeys retrieves all persisted key records.
	//
	// Function:
	//   Used to assemble the public JWKS exposed to clients and microservices.
	//
	// Storage:
	//   Database (GORM / SQL) - Relational key set persistence.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//
	// Returns:
	//   - []*JWKRecord: Slice of all key records.
	//   - error: Database error if query fails.
	//
	// Example SQL:
	//   SELECT id, public_key, private_key, alg, crv, created_at, expires_at FROM jwks ORDER BY created_at DESC;
	GetAllKeys(ctx context.Context) ([]*JWKRecord, error)

	// CreateKey stores a newly generated key-pair record.
	//
	// Function:
	//   Invoked during initial bootstrap or key rotation to persist the new key pair.
	//
	// Storage:
	//   Database (GORM / SQL) - Persistent storage for cryptographic key pairs.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - record: Key pair record containing public JWK JSON and (optionally encrypted) private key.
	//
	// Returns:
	//   - error: Database error if insert fails.
	//
	// Example SQL:
	//   INSERT INTO jwks (id, public_key, private_key, alg, crv, created_at, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7);
	CreateKey(ctx context.Context, record *JWKRecord) error

	// DeleteKey deletes a key-pair record by its Key ID.
	//
	// Function:
	//   Optional maintenance operation for purging revoked or expired keys.
	//
	// Storage:
	//   Database (GORM / SQL) - Persistent record removal.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - id: Unique Key ID string to delete.
	//
	// Returns:
	//   - error: Database error if deletion fails.
	//
	// Example SQL:
	//   DELETE FROM jwks WHERE id = $1;
	DeleteKey(ctx context.Context, id string) error
}
