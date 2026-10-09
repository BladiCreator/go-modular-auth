package policy_test

import (
	"context"
	"errors"
	"testing"
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	adaptermem "github.com/BladiCreator/go-modular-auth/adapters/memory"
	policy "github.com/BladiCreator/go-modular-auth-policy"
	"github.com/BladiCreator/go-modular-auth-policy/cache"
	"github.com/BladiCreator/go-modular-auth-policy/plugins"
	"github.com/BladiCreator/go-modular-auth-policy/store/memory"
)

func TestPolicy_RegistrationAndBasicEvaluation(t *testing.T) {
	ctx := context.Background()
	coreStore := adaptermem.NewStore()
	policyStore := memory.NewStore()
	memCache := cache.NewMemoryCache(5 * time.Minute)

	// Define an owner-or-admin rule
	ownerRule := policy.RequireResourceOwner()
	authRule := policy.RequireAuthenticated()
	docPolicy := policy.AllOf("doc:access", "Requires auth and ownership", authRule, ownerRule)

	plugin := policy.New(
		policy.WithStore(policyStore),
		policy.WithCache(memCache),
		policy.WithInitialPolicies(docPolicy),
	)

	a, err := auth.New(auth.Config{
		Store:   coreStore,
		Plugins: []auth.PluginModule{plugin},
	})
	if err != nil {
		t.Fatalf("auth.New failed: %v", err)
	}

	policySvc, err := auth.Get[plugins.Policy](a)
	if err != nil {
		t.Fatalf("auth.Get failed: %v", err)
	}

	ownerPrincipal := auth.Principal{Subject: "user-alice", Type: auth.PrincipalUser}
	resOwned := policy.NewResource("document", "doc-1").WithOwner("user-alice")

	// 1. Owner access -> Allowed
	reqAllow := policy.Request{
		Principal: ownerPrincipal,
		Resource:  resOwned,
		Action:    "read",
	}
	if err := policySvc.Authorize(ctx, reqAllow); err != nil {
		t.Fatalf("expected owner to be authorized, got: %v", err)
	}

	// 2. Non-owner access -> Denied
	otherPrincipal := auth.Principal{Subject: "user-bob", Type: auth.PrincipalUser}
	reqDeny := policy.Request{
		Principal: otherPrincipal,
		Resource:  resOwned,
		Action:    "read",
	}
	if err := policySvc.Authorize(ctx, reqDeny); !errors.Is(err, policy.ErrForbidden) {
		t.Fatalf("expected ErrForbidden for non-owner, got: %v", err)
	}
}

func TestPolicy_ChallengeDecision(t *testing.T) {
	ctx := context.Background()

	// High value transaction rule that triggers step-up MFA challenge
	highValueTransferPolicy := policy.NewRule("finance:step_up", "Requires MFA for transfers over $1000", func(_ context.Context, req policy.Request) (policy.Decision, error) {
		amount := req.Attributes.GetInt("amount")
		if amount > 1000 {
			mfaVerified := req.Attributes.GetBool("mfa_verified")
			if !mfaVerified {
				return policy.Challenge("finance:step_up", policy.ChallengeInfo{
					Type:    "step_up_mfa",
					Message: "Transactions exceeding $1000 require step-up multi-factor authentication",
					Details: map[string]any{"threshold": 1000, "current": amount},
				}), nil
			}
		}
		return policy.Allow("finance:step_up", "transaction permitted"), nil
	})

	plugin := policy.New(policy.WithInitialPolicies(highValueTransferPolicy))

	a, err := auth.New(auth.Config{
		Store:   adaptermem.NewStore(),
		Plugins: []auth.PluginModule{plugin},
	})
	if err != nil {
		t.Fatalf("auth.New failed: %v", err)
	}

	policySvc, err := auth.Get[plugins.Policy](a)
	if err != nil {
		t.Fatalf("auth.Get failed: %v", err)
	}

	principal := auth.Principal{Subject: "user-investor", Type: auth.PrincipalUser}
	bankRes := policy.NewResource("account", "acc-99")

	// 1. Small transfer ($500) -> Allowed immediately
	reqSmall := policy.Request{
		Principal:  principal,
		Resource:   bankRes,
		Action:     "transfer",
		Attributes: policy.Attributes{"amount": 500},
	}
	if err := policySvc.Authorize(ctx, reqSmall); err != nil {
		t.Fatalf("expected small transfer to be allowed, got: %v", err)
	}

	// 2. Large transfer ($5000) without MFA -> Challenge required
	reqLarge := policy.Request{
		Principal:  principal,
		Resource:   bankRes,
		Action:     "transfer",
		Attributes: policy.Attributes{"amount": 5000, "mfa_verified": false},
	}
	err = policySvc.Authorize(ctx, reqLarge)
	if !errors.Is(err, policy.ErrChallengeRequired) {
		t.Fatalf("expected ErrChallengeRequired, got: %v", err)
	}

	dec, err := policySvc.Evaluate(ctx, reqLarge)
	if err != nil || !dec.IsChallenge() {
		t.Fatalf("expected evaluate to return challenge effect, got: %+v, err: %v", dec, err)
	}
	if dec.Challenge == nil || dec.Challenge.Type != "step_up_mfa" {
		t.Fatalf("unexpected challenge payload: %+v", dec.Challenge)
	}

	// 3. Large transfer ($5000) WITH MFA verified -> Allowed
	reqLargeWithMFA := policy.Request{
		Principal:  principal,
		Resource:   bankRes,
		Action:     "transfer",
		Attributes: policy.Attributes{"amount": 5000, "mfa_verified": true},
	}
	if err := policySvc.Authorize(ctx, reqLargeWithMFA); err != nil {
		t.Fatalf("expected large transfer with MFA to succeed, got: %v", err)
	}
}

func TestPolicy_CompositionCombinators(t *testing.T) {
	ctx := context.Background()

	allowRule := policy.NewRule("rule:allow", "always allow", func(_ context.Context, _ policy.Request) (policy.Decision, error) {
		return policy.Allow("rule:allow", "ok"), nil
	})
	denyRule := policy.NewRule("rule:deny", "always deny", func(_ context.Context, _ policy.Request) (policy.Decision, error) {
		return policy.Deny("rule:deny", "blocked"), nil
	})

	req := policy.Request{
		Principal: auth.Principal{Subject: "u1", Type: auth.PrincipalUser},
		Resource:  policy.NewResource("item", "1"),
		Action:    "read",
	}

	// AllOf with one deny -> Deny
	allOf := policy.AllOf("test:all_of", "test", allowRule, denyRule)
	d, err := allOf.Evaluate(ctx, req)
	if err != nil || !d.IsDenied() {
		t.Fatalf("expected AllOf to Deny, got: %+v, err: %v", d, err)
	}

	// AnyOf with one allow -> Allow
	anyOf := policy.AnyOf("test:any_of", "test", denyRule, allowRule)
	d, err = anyOf.Evaluate(ctx, req)
	if err != nil || !d.IsAllowed() {
		t.Fatalf("expected AnyOf to Allow, got: %+v, err: %v", d, err)
	}

	// Not on allow -> Deny
	notAllow := policy.Not("test:not", "test", allowRule)
	d, err = notAllow.Evaluate(ctx, req)
	if err != nil || !d.IsDenied() {
		t.Fatalf("expected Not(allow) to Deny, got: %+v, err: %v", d, err)
	}
}

func TestPolicy_CacheInvalidation(t *testing.T) {
	ctx := context.Background()
	memCache := cache.NewMemoryCache(10 * time.Minute)

	dynamicState := true
	statePolicy := policy.NewRule("dynamic:policy", "evaluates dynamic state", func(_ context.Context, _ policy.Request) (policy.Decision, error) {
		if dynamicState {
			return policy.Allow("dynamic:policy", "granted"), nil
		}
		return policy.Deny("dynamic:policy", "denied"), nil
	})

	plugin := policy.New(
		policy.WithCache(memCache),
		policy.WithInitialPolicies(statePolicy),
	)

	a, err := auth.New(auth.Config{
		Store:   adaptermem.NewStore(),
		Plugins: []auth.PluginModule{plugin},
	})
	if err != nil {
		t.Fatalf("auth.New failed: %v", err)
	}

	policySvc, err := auth.Get[plugins.Policy](a)
	if err != nil {
		t.Fatalf("auth.Get failed: %v", err)
	}

	req := policy.Request{
		Principal: auth.Principal{Subject: "usr-cacher", Type: auth.PrincipalUser},
		Resource:  policy.NewResource("widget", "wid-1"),
		Action:    "read",
	}

	// 1. Authorize: allows and populates cache
	if err := policySvc.Authorize(ctx, req); err != nil {
		t.Fatalf("expected initial allow, got: %v", err)
	}

	// Mutate state
	dynamicState = false

	// Cached result is still allowed!
	if err := policySvc.Authorize(ctx, req); err != nil {
		t.Fatalf("expected cached allow hit, got: %v", err)
	}

	// Invalidate principal cache
	_ = policySvc.InvalidatePrincipalCache(ctx, "usr-cacher")

	// Now evaluation runs against modified state and denies!
	if err := policySvc.Authorize(ctx, req); !errors.Is(err, policy.ErrForbidden) {
		t.Fatalf("expected ErrForbidden after cache invalidation, got: %v", err)
	}
}
