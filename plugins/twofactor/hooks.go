package twofactor

import (
	"context"

	"github.com/BladiCreator/go-modular-auth/session"
)

// onBeforeSessionCreate enforces that users with active 2FA cannot have a final session created
// unless the context confirms AssuranceLevel 2.
func (s *service) onBeforeSessionCreate(ctx context.Context, sess *session.Session) error {
	if sess == nil {
		return nil
	}

	enabled, err := s.IsEnabled(ctx, sess.UserID)
	if err != nil || !enabled {
		return nil
	}

	level, ok := AssuranceLevelFrom(ctx)
	if !ok || level != AAL2 {
		return ErrAssuranceLevelInsufficient
	}

	return nil
}
