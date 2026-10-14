package serviceaccounts

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"time"

	"github.com/BladiCreator/go-modular-auth/adapter"
	sdk "github.com/BladiCreator/go-modular-auth/plugin-sdk"
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
	ctx  *sdk.Context
	repo *sdk.Repository[ServiceAccount]
}

var _ ServiceAccountManager = (*service)(nil)

func newService(ctx *sdk.Context) *service {
	return &service{
		ctx:  ctx,
		repo: sdk.Model[ServiceAccount](ctx, ModelServiceAccounts),
	}
}

func (s *service) now() time.Time {
	if s.ctx != nil {
		return s.ctx.Now()
	}
	return time.Now()
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
	now := s.now()
	id := generateID("sa")

	sa := &ServiceAccount{
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

	if err := s.repo.Create(ctx, sa); err != nil {
		return nil, "", err
	}

	return sa, secret, nil
}

func (s *service) Authenticate(ctx context.Context, id, secret string) (*ServiceAccount, error) {
	if id == "" || secret == "" {
		return nil, ErrInvalidSecret
	}

	sa, err := s.repo.FindOne(ctx, adapter.Eq("id", id))
	if errors.Is(err, adapter.ErrNotFound) {
		return nil, ErrInvalidSecret
	}
	if err != nil {
		return nil, err
	}

	if !sa.Active {
		return nil, ErrInactive
	}

	expectedHash := hashSecret(secret)
	if subtle.ConstantTimeCompare([]byte(sa.SecretHash), []byte(expectedHash)) != 1 {
		return nil, ErrInvalidSecret
	}

	return sa, nil
}

func (s *service) RotateSecret(ctx context.Context, id string) (string, error) {
	if id == "" {
		return "", ErrNotFound
	}

	sa, err := s.repo.FindOne(ctx, adapter.Eq("id", id))
	if errors.Is(err, adapter.ErrNotFound) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}

	newSecret := generateSecret()
	newHash := hashSecret(newSecret)
	now := s.now()

	affected, err := s.repo.Update(ctx, []adapter.Condition{adapter.Eq("id", id)}, map[string]any{
		"secret_hash": newHash,
		"updated_at":  now,
	})
	if err != nil {
		return "", err
	}
	if affected == 0 {
		return "", ErrNotFound
	}

	sa.SecretHash = newHash
	sa.UpdatedAt = now

	return newSecret, nil
}

func (s *service) Get(ctx context.Context, id string) (*ServiceAccount, error) {
	if id == "" {
		return nil, ErrNotFound
	}

	sa, err := s.repo.FindOne(ctx, adapter.Eq("id", id))
	if errors.Is(err, adapter.ErrNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	return sa, nil
}

func (s *service) List(ctx context.Context, ownerID string) ([]*ServiceAccount, error) {
	var where []adapter.Condition
	if ownerID != "" {
		where = append(where, adapter.Eq("owner_id", ownerID))
	}

	records, err := s.repo.FindMany(ctx, adapter.Query{
		Model: ModelServiceAccounts,
		Where: where,
	})
	if err != nil {
		return nil, err
	}

	res := make([]*ServiceAccount, len(records))
	for i := range records {
		res[i] = &records[i]
	}
	return res, nil
}

func (s *service) Revoke(ctx context.Context, id string) error {
	if id == "" {
		return ErrNotFound
	}

	now := s.now()
	affected, err := s.repo.Update(ctx, []adapter.Condition{adapter.Eq("id", id)}, map[string]any{
		"active":     false,
		"updated_at": now,
	})
	if err != nil {
		return err
	}
	if affected == 0 {
		return ErrNotFound
	}
	return nil
}
