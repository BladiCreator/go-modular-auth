// Package memory provides an in-memory thread-safe implementation of store.Store.
package memory

import (
	"context"
	"sync"
	"time"

	"github.com/BladiCreator/go-modular-auth-account-linking/store"
)

// Store implements store.Store using in-memory maps protected by a sync.RWMutex.
type Store struct {
	mu      sync.RWMutex
	tickets map[string]*store.LinkingTicket // tokenHash -> ticket
	byID    map[string]string               // id -> tokenHash
}

var _ store.Store = (*Store)(nil)

// New creates an initialized in-memory store.
func New() *Store {
	return &Store{
		tickets: make(map[string]*store.LinkingTicket),
		byID:    make(map[string]string),
	}
}

func cloneTicket(t *store.LinkingTicket) *store.LinkingTicket {
	if t == nil {
		return nil
	}
	cp := *t
	if t.Metadata != nil {
		cp.Metadata = make(map[string]string, len(t.Metadata))
		for k, v := range t.Metadata {
			cp.Metadata[k] = v
		}
	}
	return &cp
}

// SaveTicket persists a new linking ticket.
func (s *Store) SaveTicket(_ context.Context, ticket *store.LinkingTicket) error {
	if ticket == nil || ticket.ID == "" || ticket.TokenHash == "" {
		return store.ErrNotFound
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.tickets[ticket.TokenHash]; exists {
		return store.ErrConflict
	}
	if _, exists := s.byID[ticket.ID]; exists {
		return store.ErrConflict
	}

	s.tickets[ticket.TokenHash] = cloneTicket(ticket)
	s.byID[ticket.ID] = ticket.TokenHash
	return nil
}

// GetTicketByHash retrieves a ticket by its token hash without consuming it.
func (s *Store) GetTicketByHash(_ context.Context, tokenHash string) (*store.LinkingTicket, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	t, exists := s.tickets[tokenHash]
	if !exists {
		return nil, store.ErrNotFound
	}
	return cloneTicket(t), nil
}

// ConsumeTicket atomically marks a ticket as consumed at the given time.
func (s *Store) ConsumeTicket(_ context.Context, tokenHash string, now time.Time) (*store.LinkingTicket, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	t, exists := s.tickets[tokenHash]
	if !exists {
		return nil, store.ErrNotFound
	}

	if t.ConsumedAt != nil {
		return nil, store.ErrTicketConsumed
	}

	t.ConsumedAt = &now
	return cloneTicket(t), nil
}

// DeleteTicket permanently removes a ticket by its ID.
func (s *Store) DeleteTicket(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	hash, exists := s.byID[id]
	if !exists {
		return store.ErrNotFound
	}

	delete(s.tickets, hash)
	delete(s.byID, id)
	return nil
}

// PurgeExpiredTickets removes all tickets expired before the given cutoff timestamp.
func (s *Store) PurgeExpiredTickets(_ context.Context, before time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	count := 0
	for hash, t := range s.tickets {
		if !before.Before(t.ExpiresAt) {
			delete(s.tickets, hash)
			delete(s.byID, t.ID)
			count++
		}
	}
	return count, nil
}
