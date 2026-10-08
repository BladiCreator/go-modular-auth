package memory

import (
	"context"
	"sync"
	"time"

	"github.com/BladiCreator/go-modular-auth-jwt/store"
)

// Store implements store.Store using an in-memory, thread-safe hash map.
type Store struct {
	mu       sync.RWMutex
	tokens   map[string]*store.RevocationRecord
	subjects map[string]*store.SubjectRevocationRecord
}

var _ store.Store = (*Store)(nil)

// New constructs an empty in-memory revocation store.
func New() *Store {
	return &Store{
		tokens:   make(map[string]*store.RevocationRecord),
		subjects: make(map[string]*store.SubjectRevocationRecord),
	}
}

// RevokeToken persists an individual token revocation in memory.
func (s *Store) RevokeToken(_ context.Context, record *store.RevocationRecord) error {
	if record == nil || record.JTI == "" {
		return store.ErrNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	recCopy := *record
	s.tokens[record.JTI] = &recCopy
	return nil
}

// IsTokenRevoked reports whether the specified JTI is currently recorded as revoked.
func (s *Store) IsTokenRevoked(_ context.Context, jti string) (bool, error) {
	if jti == "" {
		return false, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	rec, exists := s.tokens[jti]
	if !exists {
		return false, nil
	}
	if !rec.ExpiresAt.IsZero() && time.Now().After(rec.ExpiresAt) {
		return false, nil
	}
	return true, nil
}

// RevokeSubject records a subject revocation invalidating tokens issued before Cutoff.
func (s *Store) RevokeSubject(_ context.Context, record *store.SubjectRevocationRecord) error {
	if record == nil || record.Subject == "" {
		return store.ErrNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	existing, exists := s.subjects[record.Subject]
	if exists && existing.Cutoff.After(record.Cutoff) {
		// Keep the later cutoff
		return nil
	}

	recCopy := *record
	s.subjects[record.Subject] = &recCopy
	return nil
}

// IsSubjectRevoked reports whether tokens for subject issued at issuedAt are invalidated.
func (s *Store) IsSubjectRevoked(_ context.Context, subject string, issuedAt time.Time) (bool, error) {
	if subject == "" || issuedAt.IsZero() {
		return false, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	rec, exists := s.subjects[subject]
	if !exists {
		return false, nil
	}
	// If issuedAt is on or before cutoff, token is revoked
	return !issuedAt.After(rec.Cutoff), nil
}

// DeleteExpired removes token revocation records whose original expiration timestamp is in the past.
func (s *Store) DeleteExpired(_ context.Context, now time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	count := 0
	for jti, rec := range s.tokens {
		if !rec.ExpiresAt.IsZero() && now.After(rec.ExpiresAt) {
			delete(s.tokens, jti)
			count++
		}
	}
	return count, nil
}
