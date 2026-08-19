package access

import (
	"errors"
	"slices"
	"strings"
)

// Statements defines a map of resource names to allowed action strings.
// Example: Statements{"project": {"create", "read", "update", "delete"}, "user": {"read"}}
type Statements map[string][]string

// ActionRequest defines the set of requested actions for a specific resource,
// along with a local evaluation connector (AND or OR).
type ActionRequest struct {
	Actions   []string  `json:"actions"`
	Connector Connector `json:"connector,omitempty"`
}

// AuthorizeRequest defines a map of resource names to their respective action requests.
type AuthorizeRequest map[string]ActionRequest

// AuthorizeResult encapsulates the outcome of an authorization evaluation.
type AuthorizeResult struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

// Err converts the AuthorizeResult into a standard Go error if Success is false, or returns nil if successful.
func (r AuthorizeResult) Err() error {
	if r.Success {
		return nil
	}
	return errors.New(r.Error)
}

// Req creates a single-resource AuthorizeRequest with ConnectorAND.
// Example: access.Req("project", "create", "read")
func Req(resource string, actions ...string) AuthorizeRequest {
	return AuthorizeRequest{
		resource: ActionRequest{
			Actions:   actions,
			Connector: ConnectorAND,
		},
	}
}

// ReqOR creates a single-resource AuthorizeRequest with ConnectorOR.
// Example: access.ReqOR("project", "create", "read")
func ReqOR(resource string, actions ...string) AuthorizeRequest {
	return AuthorizeRequest{
		resource: ActionRequest{
			Actions:   actions,
			Connector: ConnectorOR,
		},
	}
}

// Actions creates an ActionRequest configured with ConnectorAND.
func Actions(actions ...string) ActionRequest {
	return ActionRequest{
		Actions:   actions,
		Connector: ConnectorAND,
	}
}

// ActionsOR creates an ActionRequest configured with ConnectorOR.
func ActionsOR(actions ...string) ActionRequest {
	return ActionRequest{
		Actions:   actions,
		Connector: ConnectorOR,
	}
}

// AuthorizeRequestBuilder provides a fluent builder pattern for constructing AuthorizeRequest.
type AuthorizeRequestBuilder struct {
	req AuthorizeRequest
}

// NewAuthorizeRequest initializes a new fluent AuthorizeRequestBuilder.
func NewAuthorizeRequest() *AuthorizeRequestBuilder {
	return &AuthorizeRequestBuilder{
		req: make(AuthorizeRequest),
	}
}

// Require adds a resource check with ConnectorAND.
func (b *AuthorizeRequestBuilder) Require(resource string, actions ...string) *AuthorizeRequestBuilder {
	b.req[resource] = ActionRequest{
		Actions:   actions,
		Connector: ConnectorAND,
	}
	return b
}

// RequireOR adds a resource check with ConnectorOR.
func (b *AuthorizeRequestBuilder) RequireOR(resource string, actions ...string) *AuthorizeRequestBuilder {
	b.req[resource] = ActionRequest{
		Actions:   actions,
		Connector: ConnectorOR,
	}
	return b
}

// Build returns the underlying AuthorizeRequest.
func (b *AuthorizeRequestBuilder) Build() AuthorizeRequest {
	return b.req
}

// CloneStatements creates an isolated deep copy of a Statements map.
func CloneStatements(s Statements) Statements {
	if s == nil {
		return make(Statements)
	}
	clone := make(Statements, len(s))
	for res, actions := range s {
		copied := make([]string, len(actions))
		copy(copied, actions)
		clone[res] = copied
	}
	return clone
}

// MergeStatements merges source statements into destination statements without duplicating actions.
func MergeStatements(dst, src Statements) Statements {
	if dst == nil {
		dst = make(Statements)
	}
	for res, actions := range src {
		dst[res] = mergeUnique(dst[res], actions)
	}
	return dst
}

// mergeUnique appends items from src to dst if they do not already exist in dst.
func mergeUnique(dst, src []string) []string {
	result := append([]string(nil), dst...)
	for _, item := range src {
		if !slices.Contains(result, item) {
			result = append(result, item)
		}
	}
	return result
}

// hasAction checks if targetAction exists in allowedActions or matches a wildcard.
func hasAction(allowedActions []string, targetAction string, allowWildcards bool) bool {
	for _, act := range allowedActions {
		if (allowWildcards && act == WildcardAll) || strings.EqualFold(act, targetAction) {
			return true
		}
	}
	return false
}
