package accountlinking_test

import (
	"context"
	"errors"
	"testing"
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	accountlinking "github.com/BladiCreator/go-modular-auth-account-linking"
	"github.com/BladiCreator/go-modular-auth-account-linking/plugins"
	"github.com/BladiCreator/go-modular-auth-account-linking/store/memory"
	corecache "github.com/BladiCreator/go-modular-auth/cache/memory"
	corestore "github.com/BladiCreator/go-modular-auth/store/memory"
)

func setupTestAuth(t *testing.T) (*auth.Auth, plugins.AccountLinking, *memory.Store) {
	t.Helper()
	cStore := corestore.New()
	cCache := corecache.New()
	lStore := memory.New()

	linkingModule := accountlinking.New(
		accountlinking.WithStore(lStore),
	)

	a, err := auth.New(auth.Config{
		Store:   cStore,
		Cache:   cCache,
		Plugins: []auth.PluginModule{linkingModule},
	})
	if err != nil {
		t.Fatalf("auth.New failed: %v", err)
	}

	linking, err := auth.Get[plugins.AccountLinking](a)
	if err != nil {
		t.Fatalf("auth.Get[plugins.AccountLinking] failed: %v", err)
	}

	return a, linking, lStore
}

func TestAccountLinking_DirectLinkingAndQueries(t *testing.T) {
	ctx := context.Background()
	a, linking, _ := setupTestAuth(t)

	// 1. Create User with password
	signUpRes, err := a.SignUp(ctx, auth.SignUpInput{
		Email:    "alice@example.com",
		Password: "Password123!",
	})
	if err != nil {
		t.Fatalf("SignUp failed: %v", err)
	}
	userID := signUpRes.User.ID

	// 2. Link Google Account
	gAcc, err := linking.LinkAccount(ctx, accountlinking.LinkAccountInput{
		UserID:     userID,
		Provider:   "google",
		ProviderID: "google_102030",
	})
	if err != nil {
		t.Fatalf("LinkAccount google failed: %v", err)
	}
	if gAcc.UserID != userID || gAcc.Provider != "google" {
		t.Errorf("unexpected linked account: %+v", gAcc)
	}

	// 3. Link GitHub Account
	_, err = linking.LinkAccount(ctx, accountlinking.LinkAccountInput{
		UserID:     userID,
		Provider:   "github",
		ProviderID: "gh_554433",
	})
	if err != nil {
		t.Fatalf("LinkAccount github failed: %v", err)
	}

	// 4. List Accounts
	accounts, err := linking.ListLinkedAccounts(ctx, userID)
	if err != nil {
		t.Fatalf("ListLinkedAccounts failed: %v", err)
	}
	// Alice has 3 accounts: password, google, github
	if len(accounts) != 3 {
		t.Errorf("expected 3 accounts, got %d", len(accounts))
	}

	// 5. Get Account
	got, err := linking.GetAccount(ctx, "google", "google_102030")
	if err != nil || got == nil {
		t.Fatalf("GetAccount failed: %v", err)
	}
	if got.ID != gAcc.ID {
		t.Errorf("expected account ID %s, got %s", gAcc.ID, got.ID)
	}

	// 6. Unlink Google Account
	if err := linking.UnlinkAccount(ctx, accountlinking.UnlinkAccountInput{
		UserID:     userID,
		Provider:   "google",
		ProviderID: "google_102030",
	}); err != nil {
		t.Fatalf("UnlinkAccount failed: %v", err)
	}

	accountsAfter, _ := linking.ListLinkedAccounts(ctx, userID)
	if len(accountsAfter) != 2 {
		t.Errorf("expected 2 accounts after unlink, got %d", len(accountsAfter))
	}

	// 7. Unlink GitHub Account by ID
	if err := linking.UnlinkAccountByID(ctx, accountlinking.UnlinkAccountByIDInput{
		UserID:    userID,
		AccountID: accountsAfter[1].ID,
	}); err != nil {
		t.Fatalf("UnlinkAccountByID failed: %v", err)
	}

	accountsFinal, _ := linking.ListLinkedAccounts(ctx, userID)
	if len(accountsFinal) != 1 {
		t.Errorf("expected 1 remaining account, got %d", len(accountsFinal))
	}
}

func TestAccountLinking_PreventRemovalOfFinalAuthMethod(t *testing.T) {
	ctx := context.Background()
	a, linking, _ := setupTestAuth(t)

	// Create user with only 1 account (password)
	signUpRes, err := a.SignUp(ctx, auth.SignUpInput{
		Email:    "bob@example.com",
		Password: "Password123!",
	})
	if err != nil {
		t.Fatalf("SignUp failed: %v", err)
	}
	userID := signUpRes.User.ID

	accounts, err := linking.ListLinkedAccounts(ctx, userID)
	if err != nil || len(accounts) != 1 {
		t.Fatalf("expected 1 initial account, got %d", len(accounts))
	}
	soleAccountID := accounts[0].ID

	// Check CanUnlinkAccount
	canUnlink, err := linking.CanUnlinkAccount(ctx, userID, soleAccountID)
	if err != nil {
		t.Fatalf("CanUnlinkAccount failed: %v", err)
	}
	if canUnlink {
		t.Errorf("expected CanUnlinkAccount to be false for sole auth method")
	}

	// Attempt to unlink without AllowOrphan: must fail
	err = linking.UnlinkAccount(ctx, accountlinking.UnlinkAccountInput{
		UserID:     userID,
		Provider:   "password",
		ProviderID: accounts[0].ProviderID,
	})
	if err == nil {
		t.Fatalf("expected error unlinking final auth method, got nil")
	}
	if !errors.Is(err, accountlinking.ErrCannotUnlinkFinalAuthMethod) {
		t.Errorf("expected ErrCannotUnlinkFinalAuthMethod, got: %v", err)
	}

	// Attempt with AllowOrphan = true: must succeed
	err = linking.UnlinkAccount(ctx, accountlinking.UnlinkAccountInput{
		UserID:      userID,
		Provider:    "password",
		ProviderID:  accounts[0].ProviderID,
		AllowOrphan: true,
	})
	if err != nil {
		t.Fatalf("expected unlinking with AllowOrphan to succeed, got: %v", err)
	}

	accountsAfter, _ := linking.ListLinkedAccounts(ctx, userID)
	if len(accountsAfter) != 0 {
		t.Errorf("expected 0 accounts after orphan unlinking, got %d", len(accountsAfter))
	}
}

func TestAccountLinking_TicketBasedFlow(t *testing.T) {
	ctx := context.Background()
	a, linking, _ := setupTestAuth(t)

	signUpRes, err := a.SignUp(ctx, auth.SignUpInput{
		Email:    "charlie@example.com",
		Password: "Password123!",
	})
	if err != nil {
		t.Fatalf("SignUp failed: %v", err)
	}
	userID := signUpRes.User.ID

	// 1. Create Linking Ticket restricted to 'okta'
	ticketRes, err := linking.CreateLinkingTicket(ctx, accountlinking.CreateTicketInput{
		UserID:         userID,
		TargetProvider: "okta",
		TTL:            5 * time.Minute,
	})
	if err != nil {
		t.Fatalf("CreateLinkingTicket failed: %v", err)
	}
	if ticketRes.TicketToken == "" || ticketRes.UserID != userID {
		t.Fatalf("invalid ticket result: %+v", ticketRes)
	}

	// 2. Inspect ticket
	tkt, err := linking.GetLinkingTicket(ctx, ticketRes.TicketToken)
	if err != nil || tkt == nil {
		t.Fatalf("GetLinkingTicket failed: %v", err)
	}
	if tkt.TargetProvider != "okta" {
		t.Errorf("expected okta target provider, got: %s", tkt.TargetProvider)
	}

	// 3. Attempt completion with mismatched provider -> must fail
	mismatchTicket, err := linking.CreateLinkingTicket(ctx, accountlinking.CreateTicketInput{
		UserID:         userID,
		TargetProvider: "okta",
	})
	if err != nil {
		t.Fatalf("CreateLinkingTicket for mismatch test failed: %v", err)
	}

	_, err = linking.CompleteLinkingTicket(ctx, accountlinking.CompleteTicketInput{
		TicketToken: mismatchTicket.TicketToken,
		Provider:    "google",
		ProviderID:  "google_wrong",
	})
	if err == nil || !errors.Is(err, accountlinking.ErrProviderMismatch) {
		t.Fatalf("expected ErrProviderMismatch, got: %v", err)
	}

	// 4. Complete with correct provider -> must succeed
	linkedAcc, err := linking.CompleteLinkingTicket(ctx, accountlinking.CompleteTicketInput{
		TicketToken: ticketRes.TicketToken,
		Provider:    "okta",
		ProviderID:  "okta_sub_123",
	})
	if err != nil {
		t.Fatalf("CompleteLinkingTicket failed: %v", err)
	}
	if linkedAcc.UserID != userID || linkedAcc.Provider != "okta" {
		t.Errorf("unexpected linked account: %+v", linkedAcc)
	}

	// 5. Replaying ticket -> must fail with ErrTicketAlreadyUsed
	_, err = linking.CompleteLinkingTicket(ctx, accountlinking.CompleteTicketInput{
		TicketToken: ticketRes.TicketToken,
		Provider:    "okta",
		ProviderID:  "okta_sub_456",
	})
	if err == nil || !errors.Is(err, accountlinking.ErrTicketAlreadyUsed) {
		t.Fatalf("expected ErrTicketAlreadyUsed on replay, got: %v", err)
	}
}

func TestAccountLinking_TicketRevocationAndExpiration(t *testing.T) {
	ctx := context.Background()
	a, linking, _ := setupTestAuth(t)

	signUpRes, _ := a.SignUp(ctx, auth.SignUpInput{
		Email:    "dave@example.com",
		Password: "Password123!",
	})
	userID := signUpRes.User.ID

	// 1. Revocation
	ticketRes, err := linking.CreateLinkingTicket(ctx, accountlinking.CreateTicketInput{
		UserID: userID,
	})
	if err != nil {
		t.Fatalf("CreateLinkingTicket failed: %v", err)
	}

	if err := linking.RevokeLinkingTicket(ctx, ticketRes.TicketToken); err != nil {
		t.Fatalf("RevokeLinkingTicket failed: %v", err)
	}

	_, err = linking.CompleteLinkingTicket(ctx, accountlinking.CompleteTicketInput{
		TicketToken: ticketRes.TicketToken,
		Provider:    "github",
		ProviderID:  "gh_dave",
	})
	if !errors.Is(err, accountlinking.ErrTicketNotFound) {
		t.Errorf("expected ErrTicketNotFound after revocation, got: %v", err)
	}
}
