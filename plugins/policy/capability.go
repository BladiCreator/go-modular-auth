package policy

import "context"

// Policy is the strongly typed capability exposed by the gomodularauth-policy plugin.
type Policy interface {
	// Authorize evaluates all registered policies against the request.
	// Returns nil if allowed, ErrForbidden if denied, or ErrChallengeRequired if challenge is needed.
	Authorize(ctx context.Context, req Request) error

	// Evaluate runs deterministic evaluation and returns the detailed structured Decision.
	Evaluate(ctx context.Context, req Request) (Decision, error)

	// RegisterPolicy registers a new composable policy evaluator.
	RegisterPolicy(p Evaluator) error

	// RemovePolicy unregisters an evaluator by its unique ID.
	RemovePolicy(policyID string) error

	// GetPolicy retrieves a registered policy evaluator by ID.
	GetPolicy(policyID string) (Evaluator, error)

	// ListPolicies returns all currently registered policy evaluators.
	ListPolicies() []Evaluator

	// InvalidatePrincipalCache evicts cached decisions for a specific principal.
	InvalidatePrincipalCache(ctx context.Context, principalSubject string) error

	// InvalidateResourceCache evicts cached decisions for a specific resource.
	InvalidateResourceCache(ctx context.Context, resourceType, resourceID string) error

	// InvalidateAllCache purges all cached policy decisions.
	InvalidateAllCache(ctx context.Context) error
}
