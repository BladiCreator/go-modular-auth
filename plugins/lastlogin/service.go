package lastlogin

import (
	"context"
	"errors"

	sdk "github.com/BladiCreator/go-modular-auth/plugin-sdk"
	"github.com/BladiCreator/go-modular-auth-lastlogin/store"
)

// LastLogin defines the service capability to track and query authentication history.
type LastLogin interface {
	Record(ctx context.Context, rec *Record) error
	Get(ctx context.Context, userID string) (*Record, error)
}

type service struct {
	ctx   *sdk.Context
	store store.Store
}

var _ LastLogin = (*service)(nil)

func newService(ctx *sdk.Context, st store.Store) *service {
	return &service{
		ctx:   ctx,
		store: st,
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

	stRec := &store.Record{
		UserID:     rec.UserID,
		AccountID:  rec.AccountID,
		Method:     rec.Method,
		IP:         rec.IP,
		UserAgent:  rec.UserAgent,
		LoggedInAt: rec.LoggedInAt,
	}

	return s.store.Save(ctx, stRec)
}

func (s *service) Get(ctx context.Context, userID string) (*Record, error) {
	if userID == "" {
		return nil, ErrInvalidUserID
	}

	rec, err := s.store.GetByUserID(ctx, userID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	return &Record{
		UserID:     rec.UserID,
		AccountID:  rec.AccountID,
		Method:     rec.Method,
		IP:         rec.IP,
		UserAgent:  rec.UserAgent,
		LoggedInAt: rec.LoggedInAt,
	}, nil
}
