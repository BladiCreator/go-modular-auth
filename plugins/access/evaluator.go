package access

import (
	"fmt"
	"slices"
)

// Evaluator executes access control evaluation algorithms against Statements.
type Evaluator struct {
	allowWildcards bool
}

// NewEvaluator creates a new Evaluator instance with the specified wildcard configuration.
func NewEvaluator(allowWildcards bool) *Evaluator {
	return &Evaluator{allowWildcards: allowWildcards}
}

// Evaluate evaluates an AuthorizeRequest against Statements using the given global Connector.
// It complies with 100% Better Auth TypeScript parity and short-circuit evaluation.
func (e *Evaluator) Evaluate(statements Statements, request AuthorizeRequest, globalConnector Connector) AuthorizeResult {
	if len(request) == 0 {
		return AuthorizeResult{Success: false, Error: ErrMsgNotAuthorized}
	}

	connector := globalConnector
	if connector != ConnectorOR {
		connector = ConnectorAND
	}

	hasAuthorizedResource := false

	for requestedResource, actionReq := range request {
		allowedActions, exists := e.lookupResource(statements, requestedResource)
		if !exists {
			if connector == ConnectorAND {
				return AuthorizeResult{
					Success: false,
					Error:   fmt.Sprintf("%s%s", ErrPrefixUnknownResource, requestedResource),
				}
			}
			continue
		}

		isAuthorized := e.isResourceAuthorized(allowedActions, actionReq)
		if isAuthorized {
			hasAuthorizedResource = true
			if connector == ConnectorOR {
				return AuthorizeResult{Success: true}
			}
		} else {
			if connector == ConnectorAND {
				return AuthorizeResult{
					Success: false,
					Error:   fmt.Sprintf("%s\"%s\"", ErrPrefixUnauthorized, requestedResource),
				}
			}
		}
	}

	if hasAuthorizedResource {
		return AuthorizeResult{Success: true}
	}

	return AuthorizeResult{
		Success: false,
		Error:   ErrMsgNotAuthorized,
	}
}

// isResourceAuthorized determines whether the requested actions on a single resource are satisfied.
func (e *Evaluator) isResourceAuthorized(allowedActions []string, req ActionRequest) bool {
	if len(req.Actions) == 0 {
		return false
	}

	connector := req.Connector
	if connector != ConnectorOR {
		connector = ConnectorAND
	}

	// Superuser wildcard in allowed actions grants all actions
	if e.allowWildcards && slices.Contains(allowedActions, WildcardAll) {
		return true
	}

	if connector == ConnectorOR {
		for _, action := range req.Actions {
			if e.hasAllowedAction(allowedActions, action) {
				return true
			}
		}
		return false
	}

	// ConnectorAND by default
	for _, action := range req.Actions {
		if !e.hasAllowedAction(allowedActions, action) {
			return false
		}
	}
	return true
}

// hasAllowedAction checks if a specific action is present or granted via wildcard.
func (e *Evaluator) hasAllowedAction(allowedActions []string, requestedAction string) bool {
	if e.allowWildcards && slices.Contains(allowedActions, WildcardAll) {
		return true
	}
	return slices.Contains(allowedActions, requestedAction)
}

// lookupResource searches for resource-specific statements, falling back to wildcard '*' if enabled.
func (e *Evaluator) lookupResource(statements Statements, resource string) ([]string, bool) {
	if statements == nil {
		return nil, false
	}
	if actions, ok := statements[resource]; ok {
		return actions, true
	}
	if e.allowWildcards {
		if actions, ok := statements[WildcardAll]; ok {
			return actions, true
		}
	}
	return nil, false
}
