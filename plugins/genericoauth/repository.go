package genericoauth

import (
	"context"
	"errors"
	"time"

	"github.com/BladiCreator/go-modular-auth/domain/entity"
)

// Sentinel errors for the Generic OAuth plugin.
var (
	// ErrProviderNotFound is returned when a requested provider ID is not registered in plugin configuration.
	ErrProviderNotFound = errors.New("genericoauth: provider not found")

	// ErrInvalidState is returned when the OAuth state parameter is missing, invalid, or expired.
	ErrInvalidState = errors.New("genericoauth: invalid or expired OAuth state")

	// ErrIssuerMismatch is returned when the discovery metadata issuer does not match the configured issuer.
	ErrIssuerMismatch = errors.New("genericoauth: discovery issuer mismatch")

	// ErrInvalidCodeVerifier is returned when PKCE validation fails due to missing or invalid code_verifier.
	ErrInvalidCodeVerifier = errors.New("genericoauth: missing or invalid PKCE code_verifier")

	// ErrSignUpDisabled is returned when attempting to sign up a new user when implicit sign-up is disabled.
	ErrSignUpDisabled = errors.New("genericoauth: new user sign-up is disabled for this provider")

	// ErrAccountAlreadyLinked is returned when a social profile is already bound to another user account.
	ErrAccountAlreadyLinked = errors.New("genericoauth: social account already linked to another user")

	// ErrUserInfoFailed is returned when user info could not be fetched from the provider.
	ErrUserInfoFailed = errors.New("genericoauth: failed to retrieve user info from provider")

	// ErrUserNotFound is returned when looking up a user that does not exist.
	ErrUserNotFound = errors.New("genericoauth: user not found")

	// ErrInvalidParameter is returned when required parameters are missing or malformed.
	ErrInvalidParameter = errors.New("genericoauth: invalid or missing parameter")

	// ErrCodeExchangeFailed is returned when exchanging the authorization code for tokens fails.
	ErrCodeExchangeFailed = errors.New("genericoauth: failed to exchange authorization code for tokens")
)

// StateData represents ephemeral authorization state metadata.
type StateData struct {
	ProviderID   string    `json:"provider_id"`
	CodeVerifier string    `json:"code_verifier,omitempty"`
	CallbackURL  string    `json:"callback_url,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
}

// Repository defines storage operations required by the Generic OAuth plugin.
// Implement this interface on your custom database adapter (e.g. PostgreSQL, MySQL, SQLite, MongoDB, GORM).
//
// # Implementation Example (GORM / database/sql):
//
//	type GormGenericOAuthRepository struct {
//		db *gorm.DB
//	}
//
//	func (r *GormGenericOAuthRepository) GetAccountByProvider(ctx context.Context, providerID, accountID string) (*entity.Account, error) {
//		var acc entity.Account
//		if err := r.db.WithContext(ctx).Where("provider = ? AND account_id = ?", providerID, accountID).First(&acc).Error; err != nil {
//			if errors.Is(err, gorm.ErrRecordNotFound) {
//				return nil, nil
//			}
//			return nil, err
//		}
//		return &acc, nil
//	}
//
// # Storage and Caching Recommendation (Transient OAuth State Storage):
//
// Transient OAuth state parameters (`SaveState`, `GetState`, `DeleteState`) holding PKCE code_verifiers and callback URLs
// are short-lived. Storing transient state in Redis key-value storage with TTL provides optimal performance:
//
//	type RedisGenericOAuthStateStore struct {
//		redis *redis.Client
//	}
//
//	func (r *RedisGenericOAuthStateStore) SaveState(ctx context.Context, key string, data *genericoauth.StateData, ttl time.Duration) error {
//		bytes, _ := json.Marshal(data)
//		return r.redis.Set(ctx, "oauth:state:"+key, bytes, ttl).Err()
//	}
//
//	func (r *RedisGenericOAuthStateStore) GetState(ctx context.Context, key string) (*genericoauth.StateData, error) {
//		val, err := r.redis.Get(ctx, "oauth:state:"+key).Bytes()
//		if err != nil {
//			return nil, genericoauth.ErrInvalidState
//		}
//		var state genericoauth.StateData
//		_ = json.Unmarshal(val, &state)
//		return &state, nil
//	}
type Repository interface {
	// GetUserByEmail finds a user entity matching the provided email address.
	//
	// Function:
	//   Used during OAuth Callback to match an existing user account by email when implicit account linking is enabled.
	//
	// Storage:
	//   Database (GORM / SQL) - Relational user entity lookup.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - email: Normalized email address string.
	//
	// Returns:
	//   - *entity.User: Matching user profile if found.
	//   - error: ErrUserNotFound if missing, or database error.
	//
	// Example SQL:
	//   SELECT id, email, name, email_verified, created_at, updated_at FROM users WHERE email = $1 LIMIT 1;
	GetUserByEmail(ctx context.Context, email string) (*entity.User, error)

	// GetUserByID finds a user entity by unique primary key identifier.
	//
	// Function:
	//   Used during LinkAccount flow to verify existence of the target user account.
	//
	// Storage:
	//   Database (GORM / SQL) - User primary key lookup.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - id: Unique primary key user ID.
	//
	// Returns:
	//   - *entity.User: User profile entity.
	//   - error: ErrUserNotFound if missing.
	//
	// Example SQL:
	//   SELECT id, email, name, email_verified, created_at, updated_at FROM users WHERE id = $1 LIMIT 1;
	GetUserByID(ctx context.Context, id string) (*entity.User, error)

	// GetAccountByProvider finds a social account binding by provider ID and provider subject/account ID.
	//
	// Function:
	//   Called during OAuth Callback to check if this social account was previously linked to a user.
	//
	// Storage:
	//   Database (GORM / SQL) - Social provider binding query.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - providerID: Registered provider key (e.g. "github", "google", "auth0").
	//   - accountID: Provider sub/id returned in UserInfo response.
	//
	// Returns:
	//   - *entity.Account: Linked account entity if found, or nil if not linked yet.
	//   - error: Nil if not found, or database error.
	//
	// Example SQL:
	//   SELECT id, user_id, provider, account_id, created_at, updated_at FROM accounts WHERE provider = $1 AND account_id = $2 LIMIT 1;
	GetAccountByProvider(ctx context.Context, providerID, accountID string) (*entity.Account, error)

	// CreateUser persists a new user entity in storage.
	//
	// Function:
	//   Called during OAuth Callback when a new social user logs in and auto-signup is enabled.
	//
	// Storage:
	//   Database (GORM / SQL) - User creation.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - user: User entity to persist.
	//
	// Returns:
	//   - *entity.User: Newly persisted user entity.
	//   - error: Nil on success, or database error.
	//
	// Example SQL:
	//   INSERT INTO users (id, email, name, email_verified, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6);
	CreateUser(ctx context.Context, user *entity.User) (*entity.User, error)

	// CreateAccount persists a new social account binding linking a provider subject ID to a user ID.
	//
	// Function:
	//   Called after user creation or account linking to store provider credentials/tokens.
	//
	// Storage:
	//   Database (GORM / SQL) - Account entity creation.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - account: Account entity containing UserID, Provider, and AccountID.
	//
	// Returns:
	//   - *entity.Account: Persisted account entity.
	//   - error: ErrAccountAlreadyLinked if bound to another user.
	//
	// Example SQL:
	//   INSERT INTO accounts (id, user_id, provider, account_id, access_token, refresh_token, created_at, updated_at)
	//   VALUES ($1, $2, $3, $4, $5, $6, $7, $8);
	CreateAccount(ctx context.Context, account *entity.Account) (*entity.Account, error)

	// CreateSession persists a new active user session after successful OAuth authentication.
	//
	// Function:
	//   Called at the end of Callback flow to issue a new session.
	//
	// Storage:
	//   Database (GORM / SQL) - Active session creation.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - session: Active session entity to persist.
	//
	// Returns:
	//   - *entity.Session: Active session entity.
	//   - error: Nil on success, or database error.
	//
	// Example SQL:
	//   INSERT INTO sessions (id, user_id, token, expires_at, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6);
	CreateSession(ctx context.Context, session *entity.Session) (*entity.Session, error)

	// SaveState persists transient state metadata (e.g. for non-cookie state storage).
	//
	// Function:
	//   Called during SignIn to store PKCE code_verifier and redirect URLs when cookie state is not used.
	//
	// Storage:
	//   Cache (Redis / In-Memory TTL) - Transient OAuth state with expiration TTL.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - key: State key identifier.
	//   - data: StateData struct.
	//   - ttl: Expiration lifetime duration.
	//
	// Returns:
	//   - error: Nil on success.
	//
	// Example Cache (Redis):
	//   err := rdb.Set(ctx, "oauth:state:" + key, bytes, ttl).Err()
	SaveState(ctx context.Context, key string, data *StateData, ttl time.Duration) error

	// GetState retrieves transient state metadata by state key.
	//
	// Function:
	//   Called during Callback to restore PKCE code_verifier and callback URL.
	//
	// Storage:
	//   Cache (Redis / In-Memory TTL) - Transient state lookup.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - key: State key identifier.
	//
	// Returns:
	//   - *StateData: State metadata if found and not expired.
	//   - error: ErrInvalidState if missing or expired.
	//
	// Example Cache (Redis):
	//   val, err := rdb.Get(ctx, "oauth:state:" + key).Bytes()
	GetState(ctx context.Context, key string) (*StateData, error)

	// DeleteState removes transient state metadata.
	//
	// Function:
	//   Called after consuming state during Callback to prevent state replay.
	//
	// Storage:
	//   Cache (Redis / In-Memory TTL) - Key eviction from Redis/memory.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - key: State key identifier.
	//
	// Returns:
	//   - error: Nil on success.
	//
	// Example Cache (Redis):
	//   err := rdb.Del(ctx, "oauth:state:" + key).Err()
	DeleteState(ctx context.Context, key string) error
}
