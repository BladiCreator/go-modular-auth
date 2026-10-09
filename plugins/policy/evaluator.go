package policy

import (
	"context"
	"fmt"
)

// Evaluator is the contract implemented by every composable policy rule.
type Evaluator interface {
	ID() string
	Description() string
	Evaluate(ctx context.Context, req Request) (Decision, error)
}

// Func adapts an ordinary function to the Evaluator interface.
type Func func(ctx context.Context, req Request) (Decision, error)

type rule struct {
	id          string
	description string
	fn          Func
}

func (r *rule) ID() string          { return r.id }
func (r *rule) Description() string { return r.description }
func (r *rule) Evaluate(ctx context.Context, req Request) (Decision, error) {
	return r.fn(ctx, req)
}

// NewRule constructs a simple function-based Evaluator.
func NewRule(id, description string, fn Func) Evaluator {
	return &rule{
		id:          id,
		description: description,
		fn:          fn,
	}
}

// AllOf combines multiple evaluators requiring ALL to allow access.
// If any evaluator denies, it denies immediately.
// If any requires a challenge and none denies, it returns the challenge.
func AllOf(id, description string, evaluators ...Evaluator) Evaluator {
	return NewRule(id, description, func(ctx context.Context, req Request) (Decision, error) {
		if len(evaluators) == 0 {
			return Deny(id, "empty AllOf policy denies by default"), nil
		}

		var pendingChallenge *Decision

		for _, e := range evaluators {
			d, err := e.Evaluate(ctx, req)
			if err != nil {
				return Decision{}, fmt.Errorf("evaluating policy %q: %w", e.ID(), err)
			}
			if d.IsDenied() {
				return Deny(id, fmt.Sprintf("denied by sub-policy %q: %s", e.ID(), d.Reason)), nil
			}
			if d.IsChallenge() && pendingChallenge == nil {
				pendingChallenge = &d
			}
		}

		if pendingChallenge != nil {
			return *pendingChallenge, nil
		}

		return Allow(id, "all sub-policies allowed"), nil
	})
}

// AnyOf combines multiple evaluators granting access if AT LEAST ONE allows access.
func AnyOf(id, description string, evaluators ...Evaluator) Evaluator {
	return NewRule(id, description, func(ctx context.Context, req Request) (Decision, error) {
		if len(evaluators) == 0 {
			return Deny(id, "empty AnyOf policy denies by default"), nil
		}

		var pendingChallenge *Decision

		for _, e := range evaluators {
			d, err := e.Evaluate(ctx, req)
			if err != nil {
				return Decision{}, fmt.Errorf("evaluating policy %q: %w", e.ID(), err)
			}
			if d.IsAllowed() {
				return Allow(id, fmt.Sprintf("allowed by sub-policy %q", e.ID())), nil
			}
			if d.IsChallenge() && pendingChallenge == nil {
				pendingChallenge = &d
			}
		}

		if pendingChallenge != nil {
			return *pendingChallenge, nil
		}

		return Deny(id, "no sub-policy in AnyOf allowed access"), nil
	})
}

// DenyOverrides combines policies with standard ABAC deny-overrides semantics:
// If any policy denies, the decision is Deny.
// Otherwise, if any policy challenges, the decision is Challenge.
// Otherwise, if at least one policy allows, the decision is Allow.
// Otherwise, denies by default.
func DenyOverrides(id, description string, evaluators ...Evaluator) Evaluator {
	return NewRule(id, description, func(ctx context.Context, req Request) (Decision, error) {
		if len(evaluators) == 0 {
			return Deny(id, "empty policy set denies by default"), nil
		}

		var allowed bool
		var pendingChallenge *Decision

		for _, e := range evaluators {
			d, err := e.Evaluate(ctx, req)
			if err != nil {
				return Decision{}, fmt.Errorf("evaluating policy %q: %w", e.ID(), err)
			}
			if d.IsDenied() {
				return Deny(id, fmt.Sprintf("denied by sub-policy %q: %s", e.ID(), d.Reason)), nil
			}
			if d.IsChallenge() && pendingChallenge == nil {
				pendingChallenge = &d
			}
			if d.IsAllowed() {
				allowed = true
			}
		}

		if pendingChallenge != nil {
			return *pendingChallenge, nil
		}

		if allowed {
			return Allow(id, "allowed under deny-overrides"), nil
		}

		return Deny(id, "no policy explicitly allowed access"), nil
	})
}

// Not inverts the decision of an evaluator: Allow becomes Deny, Deny becomes Allow.
// Challenge remains Challenge.
func Not(id, description string, eval Evaluator) Evaluator {
	return NewRule(id, description, func(ctx context.Context, req Request) (Decision, error) {
		d, err := eval.Evaluate(ctx, req)
		if err != nil {
			return Decision{}, err
		}
		if d.IsChallenge() {
			return d, nil
		}
		if d.IsAllowed() {
			return Deny(id, fmt.Sprintf("inverted from allow in %q", eval.ID())), nil
		}
		return Allow(id, fmt.Sprintf("inverted from deny in %q", eval.ID())), nil
	})
}

// RequireAuthenticated ensures the request carries an authenticated principal.
func RequireAuthenticated() Evaluator {
	return NewRule("core:require_authenticated", "Requires authenticated principal", func(_ context.Context, req Request) (Decision, error) {
		if req.Principal.Subject == "" {
			return Deny("core:require_authenticated", "anonymous or unauthenticated principal not permitted"), nil
		}
		return Allow("core:require_authenticated", "principal authenticated"), nil
	})
}

// RequireResourceOwner checks whether the principal subject matches resource.OwnerID.
func RequireResourceOwner() Evaluator {
	return NewRule("core:require_owner", "Requires principal to be resource owner", func(_ context.Context, req Request) (Decision, error) {
		if req.Principal.Subject == "" {
			return Deny("core:require_owner", "unauthenticated principal"), nil
		}
		if req.Resource.OwnerID == "" {
			return Deny("core:require_owner", "resource has no owner specified"), nil
		}
		if req.Principal.Subject != req.Resource.OwnerID {
			return Deny("core:require_owner", "principal is not resource owner"), nil
		}
		return Allow("core:require_owner", "principal is resource owner"), nil
	})
}

// RequireOrganizationBoundary enforces that request.Organization matches resource.OrganizationID.
func RequireOrganizationBoundary() Evaluator {
	return NewRule("core:require_org_boundary", "Enforces organization tenant boundary", func(_ context.Context, req Request) (Decision, error) {
		if req.Resource.OrganizationID == "" {
			return Allow("core:require_org_boundary", "resource not scoped to organization"), nil
		}
		if req.Organization == "" {
			return Deny("core:require_org_boundary", "request has no active organization context"), nil
		}
		if req.Organization != req.Resource.OrganizationID {
			return Deny("core:require_org_boundary", "cross-organization access prohibited"), nil
		}
		return Allow("core:require_org_boundary", "organization boundary matches"), nil
	})
}
