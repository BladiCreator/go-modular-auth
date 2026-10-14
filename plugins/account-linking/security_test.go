package accountlinking_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	auth "github.com/BladiCreator/go-modular-auth"
	accountlinking "github.com/BladiCreator/go-modular-auth/plugins/account-linking"
)

func TestSecurity_AccountConflict_NeverSilentMerge(t *testing.T) {
	ctx := context.Background()
	a, linking, _ := setupTestAuth(t)

	// User 1: Alice
	aliceRes, _ := a.SignUp(ctx, auth.SignUpInput{
		Email:    "alice_sec@example.com",
		Password: "Password123!",
	})
	aliceID := aliceRes.User.ID

	// User 2: Bob
	bobRes, _ := a.SignUp(ctx, auth.SignUpInput{
		Email:    "bob_sec@example.com",
		Password: "Password123!",
	})
	bobID := bobRes.User.ID

	// 1. Alice links Google account google_corp_999
	_, err := linking.LinkAccount(ctx, accountlinking.LinkAccountInput{
		UserID:     aliceID,
		Provider:   "google",
		ProviderID: "google_corp_999",
	})
	if err != nil {
		t.Fatalf("Alice LinkAccount failed: %v", err)
	}

	// 2. Bob attempts to link the exact same Google account
	_, err = linking.LinkAccount(ctx, accountlinking.LinkAccountInput{
		UserID:     bobID,
		Provider:   "google",
		ProviderID: "google_corp_999",
	})
	if err == nil {
		t.Fatalf("expected error on account collision, got nil (silent merge violation!)")
	}
	if !errors.Is(err, accountlinking.ErrAccountConflict) {
		t.Errorf("expected ErrAccountConflict, got: %v", err)
	}

	// 3. Verify Bob's accounts did not get the collision, Alice's account was not stolen
	aliceAccounts, _ := linking.ListLinkedAccounts(ctx, aliceID)
	if len(aliceAccounts) != 2 {
		t.Errorf("Alice should still have 2 accounts, got %d", len(aliceAccounts))
	}

	bobAccounts, _ := linking.ListLinkedAccounts(ctx, bobID)
	if len(bobAccounts) != 1 {
		t.Errorf("Bob should still have only 1 account, got %d", len(bobAccounts))
	}
}

func TestSecurity_DuplicateLinkToSameUser(t *testing.T) {
	ctx := context.Background()
	a, linking, _ := setupTestAuth(t)

	res, _ := a.SignUp(ctx, auth.SignUpInput{
		Email:    "charlie_dup@example.com",
		Password: "Password123!",
	})
	userID := res.User.ID

	_, err := linking.LinkAccount(ctx, accountlinking.LinkAccountInput{
		UserID:     userID,
		Provider:   "github",
		ProviderID: "gh_1234",
	})
	if err != nil {
		t.Fatalf("first link failed: %v", err)
	}

	// Duplicate link to same user
	_, err = linking.LinkAccount(ctx, accountlinking.LinkAccountInput{
		UserID:     userID,
		Provider:   "github",
		ProviderID: "gh_1234",
	})
	if err == nil || !errors.Is(err, accountlinking.ErrAccountAlreadyLinked) {
		t.Fatalf("expected ErrAccountAlreadyLinked, got: %v", err)
	}
}

func TestSecurity_Authorization_NonOwnerBlocked(t *testing.T) {
	ctx := context.Background()
	a, linking, _ := setupTestAuth(t)

	aliceRes, _ := a.SignUp(ctx, auth.SignUpInput{
		Email:    "alice_auth@example.com",
		Password: "Password123!",
	})
	aliceID := aliceRes.User.ID

	eveRes, _ := a.SignUp(ctx, auth.SignUpInput{
		Email:    "eve_attacker@example.com",
		Password: "Password123!",
	})
	eveID := eveRes.User.ID

	// Eve executes request with Eve's Principal
	eveCtx := auth.WithPrincipal(ctx, auth.Principal{
		Subject: eveID,
		Type:    auth.PrincipalUser,
	})

	// Eve tries to link an account into Alice's identity
	_, err := linking.LinkAccount(eveCtx, accountlinking.LinkAccountInput{
		UserID:     aliceID,
		Provider:   "apple",
		ProviderID: "apple_victim",
	})
	if err == nil || !errors.Is(err, accountlinking.ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized when Eve acts on Alice, got: %v", err)
	}

	// Eve tries to unlink Alice's account
	err = linking.UnlinkAccount(eveCtx, accountlinking.UnlinkAccountInput{
		UserID:     aliceID,
		Provider:   "password",
		ProviderID: aliceID,
	})
	if err == nil || !errors.Is(err, accountlinking.ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized when Eve tries to unlink Alice, got: %v", err)
	}

	// Service Account Principal is authorized
	saCtx := auth.WithPrincipal(ctx, auth.Principal{
		Subject: "system_provisioner",
		Type:    auth.PrincipalServiceAccount,
	})
	_, err = linking.LinkAccount(saCtx, accountlinking.LinkAccountInput{
		UserID:     aliceID,
		Provider:   "apple",
		ProviderID: "apple_alice",
	})
	if err != nil {
		t.Fatalf("expected service account to be authorized, got: %v", err)
	}
}

func TestSecurity_Concurrency_AccountCollision(t *testing.T) {
	ctx := context.Background()
	a, linking, _ := setupTestAuth(t)

	const numUsers = 10
	userIDs := make([]string, numUsers)
	for i := 0; i < numUsers; i++ {
		res, err := a.SignUp(ctx, auth.SignUpInput{
			Email:    fmt.Sprintf("concurrent_user_%d@example.com", i),
			Password: "Password123!",
		})
		if err != nil {
			t.Fatalf("SignUp failed: %v", err)
		}
		userIDs[i] = res.User.ID
	}

	// All users simultaneously try to claim the exact same Google account
	var wg sync.WaitGroup
	var successCount int64
	var conflictCount int64

	for i := 0; i < numUsers; i++ {
		wg.Add(1)
		go func(uID string) {
			defer wg.Done()
			_, err := linking.LinkAccount(ctx, accountlinking.LinkAccountInput{
				UserID:     uID,
				Provider:   "google",
				ProviderID: "shared_contested_google_id",
			})
			if err == nil {
				atomic.AddInt64(&successCount, 1)
			} else if errors.Is(err, accountlinking.ErrAccountConflict) {
				atomic.AddInt64(&conflictCount, 1)
			}
		}(userIDs[i])
	}

	wg.Wait()

	if successCount != 1 {
		t.Fatalf("expected exactly 1 successful claim, got %d", successCount)
	}
	if conflictCount != numUsers-1 {
		t.Fatalf("expected %d conflicts, got %d", numUsers-1, conflictCount)
	}
}

func TestSecurity_Concurrency_TicketDoubleRedemption(t *testing.T) {
	ctx := context.Background()
	a, linking, _ := setupTestAuth(t)

	res, _ := a.SignUp(ctx, auth.SignUpInput{
		Email:    "ticket_racer@example.com",
		Password: "Password123!",
	})
	userID := res.User.ID

	ticketRes, err := linking.CreateLinkingTicket(ctx, accountlinking.CreateTicketInput{
		UserID: userID,
	})
	if err != nil {
		t.Fatalf("CreateLinkingTicket failed: %v", err)
	}

	const racers = 10
	var wg sync.WaitGroup
	var successCount int64
	var consumedCount int64

	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_, err := linking.CompleteLinkingTicket(ctx, accountlinking.CompleteTicketInput{
				TicketToken: ticketRes.TicketToken,
				Provider:    "webauthn",
				ProviderID:  fmt.Sprintf("cred_racer_%d", idx),
			})
			if err == nil {
				atomic.AddInt64(&successCount, 1)
			} else if errors.Is(err, accountlinking.ErrTicketAlreadyUsed) {
				atomic.AddInt64(&consumedCount, 1)
			}
		}(i)
	}

	wg.Wait()

	if successCount != 1 {
		t.Fatalf("expected exactly 1 ticket redemption, got %d", successCount)
	}
	if consumedCount != racers-1 {
		t.Fatalf("expected %d racers to be rejected with ErrTicketAlreadyUsed, got %d", racers-1, consumedCount)
	}
}
