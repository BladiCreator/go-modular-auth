package store

import (
	"context"
	"errors"
	"time"
)

var (
	ErrNotFound = errors.New("lastlogin/store: not found")
)

// Record persists the latest login details for an identity.
type Record struct {
	UserID     string
	AccountID  string
	Method     string
	IP         string
	UserAgent  string
	LoggedInAt time.Time
}

// Store persists last login records.
type Store interface {
	Save(ctx context.Context, record *Record) error
	GetByUserID(ctx context.Context, userID string) (*Record, error)
}
