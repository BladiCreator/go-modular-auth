package access

import (
	"fmt"
	"slices"
	"strings"
	"sync"
)

// AccessControl is the central coordinator managing master statements schemas, registered roles, and multi-role evaluations.
type AccessControl struct {
	masterStatements Statements
	roles            map[string]*Role
	allowWildcards   bool
	strictResources  bool
	mu               sync.RWMutex
}

// CreateAccessControl creates and initializes an AccessControl instance with master statements and options.
func CreateAccessControl(masterStatements Statements, opts ...Option) *AccessControl {
	cfg := DefaultConfig()
	cfg.MasterStatements = CloneStatements(masterStatements)
	for _, opt := range opts {
		opt(&cfg)
	}

	ac := &AccessControl{
		masterStatements: CloneStatements(cfg.MasterStatements),
		roles:            make(map[string]*Role),
		allowWildcards:   cfg.AllowWildcards,
		strictResources:  cfg.StrictResources,
	}

	// Register initial roles configured in options
	for name, stmts := range cfg.InitialRoles {
		_, _ = ac.registerRoleInternal(name, stmts)
	}

	return ac
}

// MasterStatements returns an isolated copy of the schema master statements.
func (ac *AccessControl) MasterStatements() Statements {
	ac.mu.RLock()
	defer ac.mu.RUnlock()
	return CloneStatements(ac.masterStatements)
}

// NewRole creates and registers a new Role under the given name after validating against master statements (if strict).
func (ac *AccessControl) NewRole(name string, roleStatements Statements) (*Role, error) {
	ac.mu.Lock()
	defer ac.mu.Unlock()
	return ac.registerRoleInternal(name, roleStatements)
}

// registerRoleInternal validates and registers a role while holding the write lock.
func (ac *AccessControl) registerRoleInternal(name string, roleStatements Statements) (*Role, error) {
	if strings.TrimSpace(name) == "" {
		return nil, fmt.Errorf("%s: role name cannot be empty", ErrMsgInvalidRequest)
	}

	if ac.strictResources && len(ac.masterStatements) > 0 {
		for res, actions := range roleStatements {
			masterActions, exists := ac.masterStatements[res]
			if !exists {
				if !ac.allowWildcards || res != WildcardAll {
					return nil, fmt.Errorf("resource '%s' is not defined in master statements", res)
				}
				continue
			}
			for _, act := range actions {
				if !slices.Contains(masterActions, act) && (!ac.allowWildcards || act != WildcardAll) {
					return nil, fmt.Errorf("action '%s' is not allowed for resource '%s' in master statements", act, res)
				}
			}
		}
	}

	r := NewRole(name, roleStatements, ac.allowWildcards)
	ac.roles[name] = r
	return r, nil
}

// MustNewRole creates a new role and panics if an error occurs.
func (ac *AccessControl) MustNewRole(name string, roleStatements Statements) *Role {
	r, err := ac.NewRole(name, roleStatements)
	if err != nil {
		panic(err)
	}
	return r
}

// NewAnonymousRole creates an unregistered Role instance with the given statements.
func (ac *AccessControl) NewAnonymousRole(roleStatements Statements) (*Role, error) {
	ac.mu.RLock()
	defer ac.mu.RUnlock()

	if ac.strictResources && len(ac.masterStatements) > 0 {
		for res, actions := range roleStatements {
			masterActions, exists := ac.masterStatements[res]
			if !exists {
				if !ac.allowWildcards || res != WildcardAll {
					return nil, fmt.Errorf("resource '%s' is not defined in master statements", res)
				}
				continue
			}
			for _, act := range actions {
				if !slices.Contains(masterActions, act) && (!ac.allowWildcards || act != WildcardAll) {
					return nil, fmt.Errorf("action '%s' is not allowed for resource '%s' in master statements", act, res)
				}
			}
		}
	}

	return NewRole("", roleStatements, ac.allowWildcards), nil
}

// GetRole retrieves a registered role by its name.
func (ac *AccessControl) GetRole(name string) (*Role, bool) {
	ac.mu.RLock()
	defer ac.mu.RUnlock()
	r, ok := ac.roles[name]
	return r, ok
}

// GetAllRoles returns a snapshot copy of all registered roles.
func (ac *AccessControl) GetAllRoles() map[string]*Role {
	ac.mu.RLock()
	defer ac.mu.RUnlock()

	result := make(map[string]*Role, len(ac.roles))
	for k, v := range ac.roles {
		result[k] = v.Clone()
	}
	return result
}

// DeleteRole removes a registered role from AccessControl. Returns true if the role existed and was removed.
func (ac *AccessControl) DeleteRole(name string) bool {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	if _, ok := ac.roles[name]; ok {
		delete(ac.roles, name)
		return true
	}
	return false
}

// AuthorizeRoles evaluates an AuthorizeRequest against multiple role names assigned to a subject.
// Statements from all matched roles are combined with union semantics before evaluation.
func (ac *AccessControl) AuthorizeRoles(roleNames []string, request AuthorizeRequest, connector ...Connector) AuthorizeResult {
	if len(roleNames) == 0 {
		return AuthorizeResult{Success: false, Error: ErrMsgNotAuthorized}
	}

	mergedStatements := make(Statements)
	ac.mu.RLock()
	for _, rawName := range roleNames {
		for _, name := range strings.Split(rawName, ",") {
			trimmed := strings.TrimSpace(name)
			if trimmed == "" {
				continue
			}
			if r, ok := ac.roles[trimmed]; ok {
				r.mu.RLock()
				for res, actions := range r.statements {
					mergedStatements[res] = mergeUnique(mergedStatements[res], actions)
				}
				r.mu.RUnlock()
			}
		}
	}
	ac.mu.RUnlock()

	if len(mergedStatements) == 0 {
		return AuthorizeResult{Success: false, Error: ErrMsgNotAuthorized}
	}

	evaluator := NewEvaluator(ac.allowWildcards)
	conn := ConnectorAND
	if len(connector) > 0 {
		conn = connector[0]
	}
	return evaluator.Evaluate(mergedStatements, request, conn)
}

// AuthorizeRoleString evaluates a comma-separated role string (e.g. "admin,billing_manager") against an AuthorizeRequest.
func (ac *AccessControl) AuthorizeRoleString(roleString string, request AuthorizeRequest, connector ...Connector) AuthorizeResult {
	parts := strings.Split(roleString, ",")
	return ac.AuthorizeRoles(parts, request, connector...)
}

// MergeRoles combines multiple registered roles into a single consolidated Role instance.
func (ac *AccessControl) MergeRoles(roleNames ...string) (*Role, error) {
	if len(roleNames) == 0 {
		return nil, fmt.Errorf("%s: at least one role is required", ErrMsgInvalidRequest)
	}

	merged := make(Statements)
	ac.mu.RLock()
	defer ac.mu.RUnlock()

	for _, name := range roleNames {
		trimmed := strings.TrimSpace(name)
		r, ok := ac.roles[trimmed]
		if !ok {
			return nil, fmt.Errorf("role '%s' not found", trimmed)
		}
		r.mu.RLock()
		for res, actions := range r.statements {
			merged[res] = mergeUnique(merged[res], actions)
		}
		r.mu.RUnlock()
	}

	combinedName := strings.Join(roleNames, "+")
	return NewRole(combinedName, merged, ac.allowWildcards), nil
}
