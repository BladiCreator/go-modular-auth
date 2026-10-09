package store

import (
	"context"
	"errors"
	"time"
)

var (
	ErrNotFound = errors.New("serviceaccounts/store: not found")
	ErrConflict = errors.New("serviceaccounts/store: conflict")
)

type Record struct {
	ID          string
	Name        string
	Description string
	OwnerID     string
	Scopes      []string
	SecretHash  string
	Active      bool
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type Store interface {
	Create(ctx context.Context, sa *Record) error
	GetByID(ctx context.Context, id string) (*Record, error)
	List(ctx context.Context, ownerID string) ([]*Record, error)
	Update(ctx context.Context, sa *Record) error
	Delete(ctx context.Context, id string) error
}
