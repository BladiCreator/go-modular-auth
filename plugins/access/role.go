package access

import (
	"encoding/json"
	"fmt"
	"sync"
)

// Role represents a named or anonymous role definition paired with its granted permission statements.
type Role struct {
	name       string
	statements Statements
	evaluator  *Evaluator
	mu         sync.RWMutex
}

// NewRole instantiates a new Role with the given identifier and statements.
func NewRole(name string, statements Statements, allowWildcards bool) *Role {
	return &Role{
		name:       name,
		statements: CloneStatements(statements),
		evaluator:  NewEvaluator(allowWildcards),
	}
}

// Name returns the role's identifier name.
func (r *Role) Name() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.name
}

// Statements returns an isolated deep copy of the role's permission statements.
func (r *Role) Statements() Statements {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return CloneStatements(r.statements)
}

// Authorize evaluates an AuthorizeRequest against the role's statements using an optional global Connector (default: AND).
func (r *Role) Authorize(request AuthorizeRequest, connector ...Connector) AuthorizeResult {
	r.mu.RLock()
	defer r.mu.RUnlock()

	conn := ConnectorAND
	if len(connector) > 0 {
		conn = connector[0]
	}
	return r.evaluator.Evaluate(r.statements, request, conn)
}

// HasPermission is a high-performance convenience helper to check a single resource and action permission.
func (r *Role) HasPermission(resource string, action string) bool {
	res := r.Authorize(Req(resource, action))
	return res.Success
}

// Extend derives a new Role combining the existing statements with additional statements without mutating the parent role.
func (r *Role) Extend(newName string, additionalStatements Statements) *Role {
	r.mu.RLock()
	defer r.mu.RUnlock()

	merged := CloneStatements(r.statements)
	for res, actions := range additionalStatements {
		merged[res] = mergeUnique(merged[res], actions)
	}
	return NewRole(newName, merged, r.evaluator.allowWildcards)
}

// Clone creates an exact deep copy of the Role, optionally assigning a new name.
func (r *Role) Clone(newName ...string) *Role {
	r.mu.RLock()
	defer r.mu.RUnlock()

	targetName := r.name
	if len(newName) > 0 && newName[0] != "" {
		targetName = newName[0]
	}
	return NewRole(targetName, r.statements, r.evaluator.allowWildcards)
}

// MarshalJSON serializes the Role into JSON format for database persistence and caching.
func (r *Role) MarshalJSON() ([]byte, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	type roleDTO struct {
		Name       string     `json:"name"`
		Statements Statements `json:"statements"`
	}

	return json.Marshal(roleDTO{
		Name:       r.name,
		Statements: r.statements,
	})
}

// UnmarshalJSON deserializes a Role from JSON format.
func (r *Role) UnmarshalJSON(data []byte) error {
	type roleDTO struct {
		Name       string     `json:"name"`
		Statements Statements `json:"statements"`
	}

	var dto roleDTO
	if err := json.Unmarshal(data, &dto); err != nil {
		return fmt.Errorf("failed to unmarshal role: %w", err)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.name = dto.Name
	r.statements = CloneStatements(dto.Statements)
	if r.evaluator == nil {
		r.evaluator = NewEvaluator(true)
	}
	return nil
}
