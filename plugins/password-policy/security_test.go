package passwordpolicy_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"

	passwordpolicy "github.com/BladiCreator/go-modular-auth/plugins/password-policy"
)

func TestSecurity_DetailedViolations(t *testing.T) {
	ctx := context.Background()
	policy := passwordpolicy.Policy{
		MinLength:         12,
		MaxLength:         30,
		RequireUppercase:  true,
		RequireLowercase:  true,
		RequireDigit:      true,
		RequireSymbol:     true,
		RejectCompromised: true,
	}

	_, policyPlugin, _ := setupTestAuth(t, passwordpolicy.WithPolicy(policy))

	// "weak" fails: min_length, complexity_uppercase, complexity_digit, complexity_symbol
	res, err := policyPlugin.ValidatePasswordDetailed(ctx, "weak", "")
	if err != nil {
		t.Fatalf("ValidatePasswordDetailed failed: %v", err)
	}
	if res.Valid {
		t.Fatalf("expected invalid result for 'weak'")
	}

	expectedViolations := []string{"min_length", "complexity_uppercase", "complexity_digit", "complexity_symbol"}
	for _, v := range expectedViolations {
		if !slices.Contains(res.Violations, v) {
			t.Errorf("expected violation %q in result, got: %v", v, res.Violations)
		}
	}
}

func TestSecurity_CompromisedPasswordsBlocklist(t *testing.T) {
	ctx := context.Background()
	policy := passwordpolicy.Policy{
		MinLength:         6,
		RejectCompromised: true,
	}

	_, policyPlugin, _ := setupTestAuth(t, passwordpolicy.WithPolicy(policy))

	knownCompromised := []string{
		"123456",
		"password",
		"qwerty",
		"admin123",
		"welcome1",
		"letmein",
	}

	for _, pwd := range knownCompromised {
		err := policyPlugin.ValidatePassword(ctx, pwd, "")
		if !errors.Is(err, passwordpolicy.ErrPasswordCompromised) {
			t.Errorf("expected ErrPasswordCompromised for %q, got: %v", pwd, err)
		}
	}
}

func TestSecurity_CustomCompromisedChecker(t *testing.T) {
	ctx := context.Background()
	policy := passwordpolicy.Policy{
		MinLength:         8,
		RejectCompromised: true,
	}

	// Custom checker banning any password containing "companycorp"
	customChecker := func(_ context.Context, pwd string) (bool, error) {
		return pwd == "CompanyCorp2026!", nil
	}

	_, policyPlugin, _ := setupTestAuth(t,
		passwordpolicy.WithPolicy(policy),
		passwordpolicy.WithCompromisedChecker(customChecker),
	)

	err := policyPlugin.ValidatePassword(ctx, "CompanyCorp2026!", "")
	if !errors.Is(err, passwordpolicy.ErrPasswordCompromised) {
		t.Errorf("expected ErrPasswordCompromised from custom checker, got: %v", err)
	}

	err = policyPlugin.ValidatePassword(ctx, "AcceptablePass123", "")
	if err != nil {
		t.Errorf("expected clean password to pass, got: %v", err)
	}
}

func TestSecurity_Concurrency_HistoryUpdates(t *testing.T) {
	ctx := context.Background()
	policy := passwordpolicy.Policy{
		HistoryCount: 5,
	}

	_, policyPlugin, _ := setupTestAuth(t, passwordpolicy.WithPolicy(policy))

	const numWorkers = 10
	const iterations = 10
	var wg sync.WaitGroup

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			userID := fmt.Sprintf("concurrent_user_%d", workerID)
			for j := 0; j < iterations; j++ {
				hash := fmt.Sprintf("hash_w%d_iter%d", workerID, j)
				if err := policyPlugin.RecordHistory(ctx, userID, hash); err != nil {
					t.Errorf("RecordHistory failed: %v", err)
				}
			}

			// Verify history was pruned to keepCount (5)
			hist, err := policyPlugin.GetHistory(ctx, userID, 20)
			if err != nil {
				t.Errorf("GetHistory failed: %v", err)
			}
			if len(hist) > 5 {
				t.Errorf("expected at most 5 historical entries, got %d", len(hist))
			}
		}(i)
	}

	wg.Wait()
}
