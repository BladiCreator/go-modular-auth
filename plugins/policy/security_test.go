package policy_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	adaptermem "github.com/BladiCreator/go-modular-auth/adapters/memory"
	policy "github.com/BladiCreator/go-modular-auth-policy"
	"github.com/BladiCreator/go-modular-auth-policy/cache"
	"github.com/BladiCreator/go-modular-auth-policy/plugins"
)

func TestSecurity_AuthenticationBypassPrevention(t *testing.T) {
	ctx := context.Background()

	// Strict authenticated policy
	authPolicy := policy.RequireAuthenticated()
	plugin := policy.New(policy.WithInitialPolicies(authPolicy))

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

	// 1. Request with empty/anonymous principal must be strictly forbidden
	anonReq := policy.Request{
		Principal: auth.Principal{Subject: "", Type: ""},
		Resource:  policy.NewResource("record", "rec-1"),
		Action:    "read",
	}
	err = policySvc.Authorize(ctx, anonReq)
	if !errors.Is(err, policy.ErrForbidden) {
		t.Fatalf("expected ErrForbidden for unauthenticated principal, got: %v", err)
	}

	// 2. Request with valid principal passes
	validReq := policy.Request{
		Principal: auth.Principal{Subject: "usr-valid", Type: auth.PrincipalUser},
		Resource:  policy.NewResource("record", "rec-1"),
		Action:    "read",
	}
	if err := policySvc.Authorize(ctx, validReq); err != nil {
		t.Fatalf("expected authenticated principal to succeed, got: %v", err)
	}
}

func TestSecurity_TenantBoundaryEnforcement(t *testing.T) {
	ctx := context.Background()

	orgPolicy := policy.RequireOrganizationBoundary()
	plugin := policy.New(policy.WithInitialPolicies(orgPolicy))

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

	principal := auth.Principal{Subject: "usr-1", Type: auth.PrincipalUser}
	orgAlphaRes := policy.NewResource("report", "rep-1").WithOrg("org-alpha")

	// Same org -> Allowed
	reqSameOrg := policy.Request{
		Principal:    principal,
		Organization: "org-alpha",
		Resource:     orgAlphaRes,
		Action:       "export",
	}
	if err := policySvc.Authorize(ctx, reqSameOrg); err != nil {
		t.Fatalf("expected same org to be authorized, got: %v", err)
	}

	// Cross org attempt -> Denied
	reqCrossOrg := policy.Request{
		Principal:    principal,
		Organization: "org-beta",
		Resource:     orgAlphaRes,
		Action:       "export",
	}
	if err := policySvc.Authorize(ctx, reqCrossOrg); !errors.Is(err, policy.ErrForbidden) {
		t.Fatalf("expected ErrForbidden for cross-organization access, got: %v", err)
	}
}

func TestSecurity_ConcurrentEvaluationAndRuleMutations(t *testing.T) {
	ctx := context.Background()
	memCache := cache.NewMemoryCache(5 * time.Minute)

	baseRule := policy.RequireAuthenticated()
	plugin := policy.New(
		policy.WithCache(memCache),
		policy.WithInitialPolicies(baseRule),
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

	var wg sync.WaitGroup
	workers := 25

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			user := auth.Principal{
				Subject: fmt.Sprintf("usr-conc-%d", idx),
				Type:    auth.PrincipalUser,
			}
			req := policy.Request{
				Principal: user,
				Resource:  policy.NewResource("data", fmt.Sprintf("id-%d", idx)),
				Action:    "view",
			}

			// Concurrently evaluate
			_ = policySvc.Authorize(ctx, req)
			_, _ = policySvc.Evaluate(ctx, req)

			// Concurrently register & remove transient policies
			tempRule := policy.NewRule(fmt.Sprintf("temp:rule-%d", idx), "transient rule", func(_ context.Context, _ policy.Request) (policy.Decision, error) {
				return policy.Allow(fmt.Sprintf("temp:rule-%d", idx), "transient ok"), nil
			})

			_ = policySvc.RegisterPolicy(tempRule)
			_ = policySvc.InvalidatePrincipalCache(ctx, user.Subject)
			_ = policySvc.RemovePolicy(tempRule.ID())
		}(i)
	}

	wg.Wait()
}
