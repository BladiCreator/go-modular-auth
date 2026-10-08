package memory

import (
	"context"
	"sync"
	"time"

	"github.com/BladiCreator/go-modular-auth-twofactor/store"
)

// Store provides a thread-safe in-memory implementation of store.Store.
// Ideal for unit testing, integration testing, and local development.
type Store struct {
	mu            sync.RWMutex
	factors       map[string]*store.FactorRecord
	recoveryCodes map[string]*store.RecoveryCodeRecord
	challenges    map[string]*store.ChallengeRecord
}

var _ store.Store = (*Store)(nil)

// New creates a new empty in-memory Store.
func New() *Store {
	return &Store{
		factors:       make(map[string]*store.FactorRecord),
		recoveryCodes: make(map[string]*store.RecoveryCodeRecord),
		challenges:    make(map[string]*store.ChallengeRecord),
	}
}

func cloneFactor(f *store.FactorRecord) *store.FactorRecord {
	if f == nil {
		return nil
	}
	cpy := *f
	if f.ConfirmedAt != nil {
		t := *f.ConfirmedAt
		cpy.ConfirmedAt = &t
	}
	if f.LastUsedAt != nil {
		t := *f.LastUsedAt
		cpy.LastUsedAt = &t
	}
	return &cpy
}

func cloneRecoveryCode(c *store.RecoveryCodeRecord) *store.RecoveryCodeRecord {
	if c == nil {
		return nil
	}
	cpy := *c
	if c.UsedAt != nil {
		t := *c.UsedAt
		cpy.UsedAt = &t
	}
	return &cpy
}

func cloneChallenge(c *store.ChallengeRecord) *store.ChallengeRecord {
	if c == nil {
		return nil
	}
	cpy := *c
	if c.UsedAt != nil {
		t := *c.UsedAt
		cpy.UsedAt = &t
	}
	return &cpy
}

// SaveFactor persists a newly created factor record.
func (s *Store) SaveFactor(ctx context.Context, f *store.FactorRecord) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.factors[f.ID]; exists {
		return store.ErrConflict
	}
	s.factors[f.ID] = cloneFactor(f)
	return nil
}

// GetFactor retrieves a factor record by its ID.
func (s *Store) GetFactor(ctx context.Context, factorID string) (*store.FactorRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	f, exists := s.factors[factorID]
	if !exists {
		return nil, store.ErrNotFound
	}
	return cloneFactor(f), nil
}

// ListFactorsByUser returns all factors belonging to a user.
func (s *Store) ListFactorsByUser(ctx context.Context, userID string) ([]*store.FactorRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*store.FactorRecord
	for _, f := range s.factors {
		if f.UserID == userID {
			result = append(result, cloneFactor(f))
		}
	}
	return result, nil
}

// UpdateFactor modifies an existing factor record.
func (s *Store) UpdateFactor(ctx context.Context, f *store.FactorRecord) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.factors[f.ID]; !exists {
		return store.ErrNotFound
	}
	s.factors[f.ID] = cloneFactor(f)
	return nil
}

// DeleteFactor removes a single factor record by its ID.
func (s *Store) DeleteFactor(ctx context.Context, factorID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.factors[factorID]; !exists {
		return store.ErrNotFound
	}
	delete(s.factors, factorID)
	return nil
}

// DeleteFactorsByUser removes all factor records for a given user.
func (s *Store) DeleteFactorsByUser(ctx context.Context, userID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	for id, f := range s.factors {
		if f.UserID == userID {
			delete(s.factors, id)
		}
	}
	return nil
}

// SaveRecoveryCodes persists a batch of hashed recovery code records.
func (s *Store) SaveRecoveryCodes(ctx context.Context, codes []*store.RecoveryCodeRecord) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, c := range codes {
		s.recoveryCodes[c.ID] = cloneRecoveryCode(c)
	}
	return nil
}

// ListActiveRecoveryCodesByUser returns all unused recovery codes for a user.
func (s *Store) ListActiveRecoveryCodesByUser(ctx context.Context, userID string) ([]*store.RecoveryCodeRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*store.RecoveryCodeRecord
	for _, c := range s.recoveryCodes {
		if c.UserID == userID && c.UsedAt == nil {
			result = append(result, cloneRecoveryCode(c))
		}
	}
	return result, nil
}

// MarkRecoveryCodeUsed atomically marks a recovery code as consumed.
func (s *Store) MarkRecoveryCodeUsed(ctx context.Context, id string, at time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	c, exists := s.recoveryCodes[id]
	if !exists {
		return store.ErrNotFound
	}
	if c.UsedAt != nil {
		return store.ErrConflict
	}
	t := at
	c.UsedAt = &t
	return nil
}

// DeleteRecoveryCodesByUser removes all recovery codes for a given user.
func (s *Store) DeleteRecoveryCodesByUser(ctx context.Context, userID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	for id, c := range s.recoveryCodes {
		if c.UserID == userID {
			delete(s.recoveryCodes, id)
		}
	}
	return nil
}

// SaveChallenge persists a short-lived MFA challenge record.
func (s *Store) SaveChallenge(ctx context.Context, c *store.ChallengeRecord) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	s.challenges[c.ID] = cloneChallenge(c)
	return nil
}

// GetChallenge retrieves an MFA challenge record by its ID.
func (s *Store) GetChallenge(ctx context.Context, id string) (*store.ChallengeRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	c, exists := s.challenges[id]
	if !exists {
		return nil, store.ErrNotFound
	}
	return cloneChallenge(c), nil
}

// MarkChallengeUsed atomically marks an MFA challenge as consumed.
func (s *Store) MarkChallengeUsed(ctx context.Context, id string, at time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	c, exists := s.challenges[id]
	if !exists {
		return store.ErrNotFound
	}
	if c.UsedAt != nil {
		return store.ErrConflict
	}
	t := at
	c.UsedAt = &t
	return nil
}
