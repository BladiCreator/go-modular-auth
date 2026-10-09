package memory

import (
	"context"
	"errors"
	"sync"

	auth "github.com/BladiCreator/go-modular-auth"
	"github.com/BladiCreator/go-modular-auth-rbac/store"
)

var (
	ErrNotFound      = errors.New("record not found")
	ErrAlreadyExists = errors.New("record already exists")
)

type MemoryStore struct {
	mu              sync.RWMutex
	rolesByID       map[string]*store.Role
	rolesByName     map[string]*store.Role
	assignmentsByID map[string]*store.RoleAssignment
}

var _ store.Store = (*MemoryStore)(nil)

func NewStore() *MemoryStore {
	return &MemoryStore{
		rolesByID:       make(map[string]*store.Role),
		rolesByName:     make(map[string]*store.Role),
		assignmentsByID: make(map[string]*store.RoleAssignment),
	}
}

func (s *MemoryStore) CreateRole(_ context.Context, r *store.Role) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.rolesByID[r.ID]; exists {
		return ErrAlreadyExists
	}
	if _, exists := s.rolesByName[r.Name]; exists {
		return ErrAlreadyExists
	}

	cp := *r
	cp.Permissions = append([]string(nil), r.Permissions...)
	s.rolesByID[r.ID] = &cp
	s.rolesByName[r.Name] = &cp
	return nil
}

func (s *MemoryStore) GetRole(_ context.Context, id string) (*store.Role, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	r, exists := s.rolesByID[id]
	if !exists {
		return nil, ErrNotFound
	}
	cp := *r
	cp.Permissions = append([]string(nil), r.Permissions...)
	return &cp, nil
}

func (s *MemoryStore) GetRoleByName(_ context.Context, name string) (*store.Role, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	r, exists := s.rolesByName[name]
	if !exists {
		return nil, ErrNotFound
	}
	cp := *r
	cp.Permissions = append([]string(nil), r.Permissions...)
	return &cp, nil
}

func (s *MemoryStore) UpdateRole(_ context.Context, r *store.Role) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	existing, exists := s.rolesByID[r.ID]
	if !exists {
		return ErrNotFound
	}

	if existing.Name != r.Name {
		if _, nameTaken := s.rolesByName[r.Name]; nameTaken {
			return ErrAlreadyExists
		}
		delete(s.rolesByName, existing.Name)
	}

	cp := *r
	cp.Permissions = append([]string(nil), r.Permissions...)
	s.rolesByID[r.ID] = &cp
	s.rolesByName[r.Name] = &cp
	return nil
}

func (s *MemoryStore) DeleteRole(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	r, exists := s.rolesByID[id]
	if !exists {
		return ErrNotFound
	}

	delete(s.rolesByID, id)
	delete(s.rolesByName, r.Name)
	return nil
}

func (s *MemoryStore) ListRoles(_ context.Context, scope store.Scope) ([]*store.Role, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*store.Role
	for _, r := range s.rolesByID {
		if scope != "" && r.Scope != scope {
			continue
		}
		cp := *r
		cp.Permissions = append([]string(nil), r.Permissions...)
		result = append(result, &cp)
	}
	return result, nil
}

func (s *MemoryStore) CreateAssignment(_ context.Context, a *store.RoleAssignment) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.assignmentsByID[a.ID]; exists {
		return ErrAlreadyExists
	}

	for _, existing := range s.assignmentsByID {
		if existing.RoleID == a.RoleID &&
			existing.PrincipalSubject == a.PrincipalSubject &&
			existing.PrincipalType == a.PrincipalType &&
			existing.Scope == a.Scope &&
			existing.ScopeID == a.ScopeID {
			return ErrAlreadyExists
		}
	}

	cp := *a
	s.assignmentsByID[a.ID] = &cp
	return nil
}

func (s *MemoryStore) DeleteAssignment(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.assignmentsByID[id]; !exists {
		return ErrNotFound
	}
	delete(s.assignmentsByID, id)
	return nil
}

func (s *MemoryStore) GetAssignment(_ context.Context, id string) (*store.RoleAssignment, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	a, exists := s.assignmentsByID[id]
	if !exists {
		return nil, ErrNotFound
	}
	cp := *a
	return &cp, nil
}

func (s *MemoryStore) ListAssignmentsByPrincipal(_ context.Context, subject string, pType auth.PrincipalType) ([]*store.RoleAssignment, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*store.RoleAssignment
	for _, a := range s.assignmentsByID {
		if a.PrincipalSubject != subject {
			continue
		}
		if pType != "" && a.PrincipalType != "" && a.PrincipalType != pType {
			continue
		}
		cp := *a
		result = append(result, &cp)
	}
	return result, nil
}

func (s *MemoryStore) ListAssignmentsByRole(_ context.Context, roleID string) ([]*store.RoleAssignment, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*store.RoleAssignment
	for _, a := range s.assignmentsByID {
		if a.RoleID == roleID {
			cp := *a
			result = append(result, &cp)
		}
	}
	return result, nil
}

func (s *MemoryStore) DeleteAssignmentsByRole(_ context.Context, roleID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for id, a := range s.assignmentsByID {
		if a.RoleID == roleID {
			delete(s.assignmentsByID, id)
		}
	}
	return nil
}

func (s *MemoryStore) DeleteAssignmentsByPrincipal(_ context.Context, subject string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for id, a := range s.assignmentsByID {
		if a.PrincipalSubject == subject {
			delete(s.assignmentsByID, id)
		}
	}
	return nil
}
