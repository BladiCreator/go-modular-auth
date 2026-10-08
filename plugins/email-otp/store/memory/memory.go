// Package memory provides an in-memory implementation of store.Store for unit testing and local development.
package memory

import (
	"context"
	"sync"
	"time"

	"github.com/BladiCreator/go-modular-auth-email-otp/store"
)

// Store is an in-memory, thread-safe implementation of store.Store.
type Store struct {
	mu      sync.RWMutex
	records map[string]*store.Record
}

var _ store.Store = (*Store)(nil)

// New constructs a new in-memory Store.
func New() *Store {
	return &Store{
		records: make(map[string]*store.Record),
	}
}

// Create persists a new OTP record.
func (s *Store) Create(ctx context.Context, rec *store.Record) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	clone := *rec
	s.records[rec.ID] = &clone
	return nil
}

// GetActiveByEmail retrieves the most recent unconsumed record for the given email.
func (s *Store) GetActiveByEmail(ctx context.Context, email string, now time.Time) (*store.Record, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	var latest *store.Record
	for _, rec := range s.records {
		if rec.Email == email && !rec.Used() {
			if latest == nil || rec.CreatedAt.After(latest.CreatedAt) {
				latest = rec
			}
		}
	}

	if latest == nil {
		return nil, store.ErrNotFound
	}

	clone := *latest
	return &clone, nil
}

// IncrementAttempts atomically increments failed verification attempts for an OTP record.
func (s *Store) IncrementAttempts(ctx context.Context, id string) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, ok := s.records[id]
	if !ok {
		return 0, store.ErrNotFound
	}

	rec.Attempts++
	return rec.Attempts, nil
}

// MarkUsed atomically sets UsedAt if the record is currently unused and unlocked.
func (s *Store) MarkUsed(ctx context.Context, id string, at time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, ok := s.records[id]
	if !ok {
		return store.ErrNotFound
	}

	if rec.Used() || rec.Locked() {
		return store.ErrConflict
	}

	usedAt := at
	rec.UsedAt = &usedAt
	return nil
}

// RevokeByEmail removes or marks used all active OTP records for the email.
func (s *Store) RevokeByEmail(ctx context.Context, email string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	for id, rec := range s.records {
		if rec.Email == email {
			delete(s.records, id)
		}
	}
	return nil
}

// DeleteExpired removes records that expired before the given timestamp.
func (s *Store) DeleteExpired(ctx context.Context, before time.Time) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	count := 0
	for id, rec := range s.records {
		if rec.Expired(before) || rec.Used() {
			delete(s.records, id)
			count++
		}
	}
	return count, nil
}
