package multisession

import (
	"context"

	"github.com/BladiCreator/go-modular-auth/domain/entity"
)

// Repository defines data access contract required by the MultiSession plugin.
// Implement this interface on your custom database adapter (e.g. PostgreSQL, MySQL, SQLite, GORM).
//
// # Implementation Example (GORM / database/sql):
//
//	type GormMultiSessionRepository struct {
//		db *gorm.DB
//	}
//
//	func (r *GormMultiSessionRepository) GetSessionByToken(ctx context.Context, token string) (*entity.Session, error) {
//		var s entity.Session
//		if err := r.db.WithContext(ctx).Where("token = ?", token).First(&s).Error; err != nil {
//			return nil, err
//		}
//		return &s, nil
//	}
type Repository interface {
	// GetSessionByToken retrieves a session entity by its unique session token string.
	//
	// Function:
	//   Used during session validation and active device count evaluation.
	//
	// Storage:
	//   Database (GORM / SQL) - Query sessions table by token column index.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - token: Session token string.
	//
	// Returns:
	//   - *entity.Session: Matching session entity if found.
	//   - error: Nil on success, or database error.
	//
	// Example SQL:
	//   SELECT id, user_id, token, expires_at, created_at, updated_at FROM sessions WHERE token = $1 LIMIT 1;
	GetSessionByToken(ctx context.Context, token string) (*entity.Session, error)

	// GetUserByID retrieves a user entity by its unique user ID.
	//
	// Function:
	//   Used to resolve user details linked to active multi-session tokens.
	//
	// Storage:
	//   Database (GORM / SQL) - Primary key lookup on users table.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - id: Unique user primary key ID.
	//
	// Returns:
	//   - *entity.User: Matching user entity if found.
	//   - error: Nil on success, or database error.
	//
	// Example SQL:
	//   SELECT id, email, name, avatar, role, created_at, updated_at FROM users WHERE id = $1 LIMIT 1;
	GetUserByID(ctx context.Context, id string) (*entity.User, error)

	// DeleteSession removes a single session by token string.
	//
	// Function:
	//   Called during individual session revocation or logout.
	//
	// Storage:
	//   Database (GORM / SQL) - Delete row matching token.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - token: Target session token string to revoke.
	//
	// Returns:
	//   - error: Nil on success, or database error.
	//
	// Example SQL:
	//   DELETE FROM sessions WHERE token = $1;
	DeleteSession(ctx context.Context, token string) error

	// DeleteSessions removes multiple sessions by token strings.
	//
	// Function:
	//   Called during mass revocation or session limit enforcement.
	//
	// Storage:
	//   Database (GORM / SQL) - Batch delete rows where token IN ($1, $2, ...).
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - tokens: Slice of session token strings to revoke.
	//
	// Returns:
	//   - error: Nil on success, or database error.
	//
	// Example SQL:
	//   DELETE FROM sessions WHERE token IN ($1, $2, $3);
	DeleteSessions(ctx context.Context, tokens []string) error

	// FindSessionsByTokens returns all valid sessions and corresponding users for a given slice of session tokens.
	//
	// Function:
	//   Called during multi-session cookie evaluation to list all active accounts on a device.
	//
	// Storage:
	//   Database (GORM / SQL) - Join sessions and users where token IN ($1, $2, ...).
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - tokens: Slice of multi-session token strings.
	//
	// Returns:
	//   - []*entity.Session: List of active session entities.
	//   - []*entity.User: List of corresponding user entities.
	//   - error: Nil on success, or database error.
	//
	// Example SQL:
	//   SELECT s.id, s.user_id, s.token, s.expires_at, u.email, u.name FROM sessions s JOIN users u ON s.user_id = u.id WHERE s.token IN ($1, $2);
	FindSessionsByTokens(ctx context.Context, tokens []string) ([]*entity.Session, []*entity.User, error)
}
