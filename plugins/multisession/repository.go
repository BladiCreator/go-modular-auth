package multisession

import (
	"context"

	"github.com/BladiCreator/go-modular-auth/domain/entity"
)

// Repository defines data access contract required by the MultiSession plugin.
type Repository interface {
	// GetSessionByToken retrieves a session entity by its unique session token string.
	GetSessionByToken(ctx context.Context, token string) (*entity.Session, error)

	// GetUserByID retrieves a user entity by its unique user ID.
	GetUserByID(ctx context.Context, id string) (*entity.User, error)

	// DeleteSession removes a single session by token string.
	DeleteSession(ctx context.Context, token string) error

	// DeleteSessions removes multiple sessions by token strings.
	DeleteSessions(ctx context.Context, tokens []string) error

	// FindSessionsByTokens returns all valid sessions and corresponding users for a given slice of session tokens.
	FindSessionsByTokens(ctx context.Context, tokens []string) ([]*entity.Session, []*entity.User, error)
}
