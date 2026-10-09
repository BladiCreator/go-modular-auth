// Package memory provides an in-memory, thread-safe implementation of store.Store.
package memory

import (
	"context"
	"maps"
	"strings"
	"sync"
	"time"

	"github.com/BladiCreator/go-modular-auth-admin/store"
)

type txKey struct{ s *Store }

type data struct {
	byUserID map[string]*store.UserRecord
}

func newData() data {
	return data{
		byUserID: make(map[string]*store.UserRecord),
	}
}

func (d data) clone() data {
	cloned := make(map[string]*store.UserRecord, len(d.byUserID))
	for k, v := range d.byUserID {
		cloned[k] = cloneRecord(v)
	}
	return data{byUserID: cloned}
}

// Store implements store.Store using in-memory maps guarded by mutexes.
type Store struct {
	txMu sync.Mutex
	mu   sync.RWMutex
	data data
}

var _ store.Store = (*Store)(nil)

// New constructs an initialized in-memory admin store.
func New() *Store {
	return &Store{
		data: newData(),
	}
}

func (s *Store) inTx(ctx context.Context) bool {
	v, _ := ctx.Value(txKey{s}).(bool)
	return v
}

// Transaction runs fn atomically with snapshot rollback.
func (s *Store) Transaction(ctx context.Context, fn func(ctx context.Context) error) error {
	if s.inTx(ctx) {
		return fn(ctx)
	}

	s.txMu.Lock()
	defer s.txMu.Unlock()

	s.mu.RLock()
	snapshot := s.data.clone()
	s.mu.RUnlock()

	txCtx := context.WithValue(ctx, txKey{s}, true)
	if err := fn(txCtx); err != nil {
		s.mu.Lock()
		s.data = snapshot
		s.mu.Unlock()
		return err
	}
	return nil
}

func (s *Store) read(ctx context.Context, fn func(d *data) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return fn(&s.data)
}

func (s *Store) write(ctx context.Context, fn func(d *data) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !s.inTx(ctx) {
		s.txMu.Lock()
		defer s.txMu.Unlock()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return fn(&s.data)
}

// UpsertUser persists or updates an administrative user record.
func (s *Store) UpsertUser(ctx context.Context, r *store.UserRecord) error {
	return s.write(ctx, func(d *data) error {
		d.byUserID[r.UserID] = cloneRecord(r)
		return nil
	})
}

// GetUser retrieves the record by UserID.
func (s *Store) GetUser(ctx context.Context, userID string) (*store.UserRecord, error) {
	var result *store.UserRecord
	err := s.read(ctx, func(d *data) error {
		rec, exists := d.byUserID[userID]
		if !exists {
			return store.ErrNotFound
		}
		result = cloneRecord(rec)
		return nil
	})
	return result, err
}

// UpdateUserStatus modifies the disabled status.
func (s *Store) UpdateUserStatus(ctx context.Context, userID string, disabled bool, reason string, at *time.Time) error {
	return s.write(ctx, func(d *data) error {
		rec, exists := d.byUserID[userID]
		if !exists {
			return store.ErrNotFound
		}
		rec.Disabled = disabled
		rec.DisabledReason = reason
		rec.DisabledAt = at
		rec.UpdatedAt = time.Now()
		return nil
	})
}

// DeleteUser deletes the user record.
func (s *Store) DeleteUser(ctx context.Context, userID string) error {
	return s.write(ctx, func(d *data) error {
		if _, exists := d.byUserID[userID]; !exists {
			return store.ErrNotFound
		}
		delete(d.byUserID, userID)
		return nil
	})
}

// ListUsers returns paginated records.
func (s *Store) ListUsers(ctx context.Context, filter store.ListFilter) ([]*store.UserRecord, int, error) {
	var all []*store.UserRecord
	err := s.read(ctx, func(d *data) error {
		search := strings.ToLower(strings.TrimSpace(filter.Search))
		for _, rec := range d.byUserID {
			if search != "" && !strings.Contains(strings.ToLower(rec.Email), search) {
				continue
			}
			if filter.Status == "active" && rec.Disabled {
				continue
			}
			if filter.Status == "disabled" && !rec.Disabled {
				continue
			}
			all = append(all, cloneRecord(rec))
		}
		return nil
	})
	if err != nil {
		return nil, 0, err
	}

	total := len(all)
	if filter.Offset >= len(all) {
		return nil, total, nil
	}
	end := len(all)
	if filter.Limit > 0 && filter.Offset+filter.Limit < end {
		end = filter.Offset + filter.Limit
	}
	return all[filter.Offset:end], total, nil
}

// IsUserDisabled checks if user is disabled.
func (s *Store) IsUserDisabled(ctx context.Context, userID string) (bool, error) {
	var disabled bool
	err := s.read(ctx, func(d *data) error {
		rec, exists := d.byUserID[userID]
		if !exists {
			return nil
		}
		disabled = rec.Disabled
		return nil
	})
	return disabled, err
}

// IsAdmin checks if user is an administrator.
func (s *Store) IsAdmin(ctx context.Context, userID string) (bool, error) {
	var isAdmin bool
	err := s.read(ctx, func(d *data) error {
		rec, exists := d.byUserID[userID]
		if !exists {
			return nil
		}
		isAdmin = rec.IsAdmin
		return nil
	})
	return isAdmin, err
}

// SetAdminRole updates role and admin flag.
func (s *Store) SetAdminRole(ctx context.Context, userID string, isAdmin bool, role string) error {
	return s.write(ctx, func(d *data) error {
		rec, exists := d.byUserID[userID]
		if !exists {
			return store.ErrNotFound
		}
		rec.IsAdmin = isAdmin
		rec.Role = role
		rec.UpdatedAt = time.Now()
		return nil
	})
}

func cloneRecord(r *store.UserRecord) *store.UserRecord {
	if r == nil {
		return nil
	}
	c := *r
	if r.DisabledAt != nil {
		t := *r.DisabledAt
		c.DisabledAt = &t
	}
	if r.Metadata != nil {
		c.Metadata = maps.Clone(r.Metadata)
	}
	return &c
}
