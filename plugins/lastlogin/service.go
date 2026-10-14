package lastlogin

import (
	"context"
	"errors"

	"github.com/BladiCreator/go-modular-auth/adapter"
	sdk "github.com/BladiCreator/go-modular-auth/plugin-sdk"
)

// LastLogin defines the service capability to track and query authentication history.
type LastLogin interface {
	Record(ctx context.Context, rec *Record) error
	Get(ctx context.Context, userID string) (*Record, error)
}

type service struct {
	ctx     *sdk.Context
	records *sdk.Repository[Record]
}

var _ LastLogin = (*service)(nil)

func newService(ctx *sdk.Context) *service {
	return &service{
		ctx:     ctx,
		records: sdk.Model[Record](ctx, ModelLastLogins),
	}
}

func (s *service) Record(ctx context.Context, rec *Record) error {
	if rec == nil || rec.UserID == "" {
		return ErrInvalidUserID
	}
	if rec.Method == "" {
		return ErrInvalidMethod
	}
	if rec.LoggedInAt.IsZero() {
		rec.LoggedInAt = s.ctx.Now()
	}

	existing, err := s.records.FindOne(ctx, adapter.Eq("user_id", rec.UserID))
	if err == nil && existing != nil {
		_, err = s.records.Update(ctx, []adapter.Condition{adapter.Eq("user_id", rec.UserID)}, map[string]any{
			"account_id":   rec.AccountID,
			"method":       rec.Method,
			"ip":           rec.IP,
			"user_agent":   rec.UserAgent,
			"logged_in_at": rec.LoggedInAt,
		})
		return err
	}

	return s.records.Create(ctx, rec)
}

func (s *service) Get(ctx context.Context, userID string) (*Record, error) {
	if userID == "" {
		return nil, ErrInvalidUserID
	}

	rec, err := s.records.FindOne(ctx, adapter.Eq("user_id", userID))
	if errors.Is(err, adapter.ErrNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	return rec, nil
}
