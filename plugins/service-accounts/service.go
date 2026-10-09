package serviceaccounts

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"

	sdk "github.com/BladiCreator/go-modular-auth/plugin-sdk"
	"github.com/BladiCreator/go-modular-auth-service-accounts/store"
)

type ServiceAccountManager interface {
	Create(ctx context.Context, in CreateInput) (*ServiceAccount, string, error)
	Authenticate(ctx context.Context, id, secret string) (*ServiceAccount, error)
	RotateSecret(ctx context.Context, id string) (string, error)
	Get(ctx context.Context, id string) (*ServiceAccount, error)
	List(ctx context.Context, ownerID string) ([]*ServiceAccount, error)
	Revoke(ctx context.Context, id string) error
}

type service struct {
	ctx   *sdk.Context
	store store.Store
}

var _ ServiceAccountManager = (*service)(nil)

func newService(ctx *sdk.Context, st store.Store) *service {
	return &service{
		ctx:   ctx,
		store: st,
	}
}

func generateID(prefix string) string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return prefix + "_" + hex.EncodeToString(b)
}

func generateSecret() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return "sec_" + hex.EncodeToString(b)
}

func hashSecret(secret string) string {
	h := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(h[:])
}

func (s *service) Create(ctx context.Context, in CreateInput) (*ServiceAccount, string, error) {
	if in.Name == "" {
		return nil, "", ErrInvalidName
	}
	if in.OwnerID == "" {
		return nil, "", ErrInvalidOwnerID
	}

	secret := generateSecret()
	now := s.ctx.Now()
	id := generateID("sa")

	rec := &store.Record{
		ID:          id,
		Name:        in.Name,
		Description: in.Description,
		OwnerID:     in.OwnerID,
		Scopes:      in.Scopes,
		SecretHash:  hashSecret(secret),
		Active:      true,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	if err := s.store.Create(ctx, rec); err != nil {
		return nil, "", err
	}

	sa := &ServiceAccount{
		ID:          rec.ID,
		Name:        rec.Name,
		Description: rec.Description,
		OwnerID:     rec.OwnerID,
		Scopes:      rec.Scopes,
		Active:      rec.Active,
		CreatedAt:   rec.CreatedAt,
		UpdatedAt:   rec.UpdatedAt,
	}

	return sa, secret, nil
}

func (s *service) Authenticate(ctx context.Context, id, secret string) (*ServiceAccount, error) {
	if id == "" || secret == "" {
		return nil, ErrInvalidSecret
	}

	rec, err := s.store.GetByID(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrInvalidSecret
	}
	if err != nil {
		return nil, err
	}

	if !rec.Active {
		return nil, ErrInactive
	}

	expectedHash := hashSecret(secret)
	if subtle.ConstantTimeCompare([]byte(rec.SecretHash), []byte(expectedHash)) != 1 {
		return nil, ErrInvalidSecret
	}

	return &ServiceAccount{
		ID:          rec.ID,
		Name:        rec.Name,
		Description: rec.Description,
		OwnerID:     rec.OwnerID,
		Scopes:      rec.Scopes,
		Active:      rec.Active,
		CreatedAt:   rec.CreatedAt,
		UpdatedAt:   rec.UpdatedAt,
	}, nil
}

func (s *service) RotateSecret(ctx context.Context, id string) (string, error) {
	if id == "" {
		return "", ErrNotFound
	}

	rec, err := s.store.GetByID(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}

	newSecret := generateSecret()
	rec.SecretHash = hashSecret(newSecret)
	rec.UpdatedAt = s.ctx.Now()

	if err := s.store.Update(ctx, rec); err != nil {
		return "", err
	}

	return newSecret, nil
}

func (s *service) Get(ctx context.Context, id string) (*ServiceAccount, error) {
	if id == "" {
		return nil, ErrNotFound
	}

	rec, err := s.store.GetByID(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	return &ServiceAccount{
		ID:          rec.ID,
		Name:        rec.Name,
		Description: rec.Description,
		OwnerID:     rec.OwnerID,
		Scopes:      rec.Scopes,
		Active:      rec.Active,
		CreatedAt:   rec.CreatedAt,
		UpdatedAt:   rec.UpdatedAt,
	}, nil
}

func (s *service) List(ctx context.Context, ownerID string) ([]*ServiceAccount, error) {
	records, err := s.store.List(ctx, ownerID)
	if err != nil {
		return nil, err
	}

	var res []*ServiceAccount
	for _, r := range records {
		res = append(res, &ServiceAccount{
			ID:          r.ID,
			Name:        r.Name,
			Description: r.Description,
			OwnerID:     r.OwnerID,
			Scopes:      r.Scopes,
			Active:      r.Active,
			CreatedAt:   r.CreatedAt,
			UpdatedAt:   r.UpdatedAt,
		})
	}
	return res, nil
}

func (s *service) Revoke(ctx context.Context, id string) error {
	if id == "" {
		return ErrNotFound
	}

	rec, err := s.store.GetByID(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}

	rec.Active = false
	rec.UpdatedAt = s.ctx.Now()
	return s.store.Update(ctx, rec)
}
