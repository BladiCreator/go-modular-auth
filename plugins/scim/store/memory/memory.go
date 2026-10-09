package memory

import (
	"context"
	"sync"

	"github.com/BladiCreator/go-modular-auth-scim/store"
)

type Store struct {
	mu     sync.RWMutex
	users  map[string]*store.UserMetadata
	groups map[string]*store.GroupRecord
}

var _ store.Store = (*Store)(nil)

func New() *Store {
	return &Store{
		users:  make(map[string]*store.UserMetadata),
		groups: make(map[string]*store.GroupRecord),
	}
}

func (s *Store) SaveUserMetadata(ctx context.Context, meta *store.UserMetadata) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	cp := *meta
	s.users[meta.UserID] = &cp
	return nil
}

func (s *Store) GetUserMetadata(ctx context.Context, userID string) (*store.UserMetadata, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	m, ok := s.users[userID]
	if !ok {
		return nil, store.ErrNotFound
	}
	cp := *m
	return &cp, nil
}

func (s *Store) GetUserMetadataByExternalID(ctx context.Context, externalID string) (*store.UserMetadata, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, m := range s.users {
		if m.ExternalID == externalID {
			cp := *m
			return &cp, nil
		}
	}
	return nil, store.ErrNotFound
}

func (s *Store) DeleteUserMetadata(ctx context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.users, userID)
	return nil
}

func (s *Store) CreateGroup(ctx context.Context, grp *store.GroupRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.groups[grp.ID]; exists {
		return store.ErrConflict
	}
	cp := *grp
	s.groups[grp.ID] = &cp
	return nil
}

func (s *Store) GetGroup(ctx context.Context, id string) (*store.GroupRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	g, ok := s.groups[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	cp := *g
	return &cp, nil
}

func (s *Store) ListGroups(ctx context.Context) ([]*store.GroupRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var list []*store.GroupRecord
	for _, g := range s.groups {
		cp := *g
		list = append(list, &cp)
	}
	return list, nil
}

func (s *Store) UpdateGroup(ctx context.Context, grp *store.GroupRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.groups[grp.ID]; !exists {
		return store.ErrNotFound
	}
	cp := *grp
	s.groups[grp.ID] = &cp
	return nil
}

func (s *Store) DeleteGroup(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.groups[id]; !exists {
		return store.ErrNotFound
	}
	delete(s.groups, id)
	return nil
}
