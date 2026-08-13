package passkey_test

import (
	"context"
	"encoding/base64"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/BladiCreator/go-modular-auth/domain/dto"
	"github.com/BladiCreator/go-modular-auth/domain/entity"
	"github.com/BladiCreator/go-modular-auth/internal/mock"
	"github.com/BladiCreator/go-modular-auth/plugin"
	"github.com/BladiCreator/go-modular-auth/plugins/passkey"
	"github.com/asaskevich/EventBus"
	"github.com/go-webauthn/webauthn/protocol"
)

func setupTestPlugin(t *testing.T, opts ...passkey.Option) (*passkey.Plugin, *mock.MockRepo, *plugin.Context) {
	t.Helper()
	repo := mock.NewMockRepo()
	bus := EventBus.New()
	pCtx := plugin.NewContext(nil, bus)

	p := passkey.New(repo, opts...)
	if err := p.Init(pCtx); err != nil {
		t.Fatalf("Failed to init passkey plugin: %v", err)
	}

	return p, repo, pCtx
}

func TestPlugin_Lifecycle(t *testing.T) {
	p, _, pCtx := setupTestPlugin(t,
		passkey.WithRPDisplayName("Test RP"),
		passkey.WithRPID("localhost"),
		passkey.WithRPOrigins("http://localhost:3000"),
	)

	if p.ID() != "passkey" {
		t.Errorf("Expected ID 'passkey', got '%s'", p.ID())
	}

	cfg := p.Config()
	if cfg.RPDisplayName != "Test RP" {
		t.Errorf("Expected RPDisplayName 'Test RP', got '%s'", cfg.RPDisplayName)
	}
	if cfg.RPID != "localhost" {
		t.Errorf("Expected RPID 'localhost', got '%s'", cfg.RPID)
	}

	val, ok := pCtx.Get(passkey.StoreKeyRPID)
	if !ok || val != "localhost" {
		t.Errorf("Context StoreKeyRPID mismatch: %v", val)
	}
}

func TestPlugin_FunctionalOptions(t *testing.T) {
	attachment := protocol.Platform
	afterRegCalled := false
	afterAuthCalled := false
	resolveCalled := false

	p, _, _ := setupTestPlugin(t,
		passkey.WithRPDisplayName("Custom App"),
		passkey.WithRPID("auth.example.com"),
		passkey.WithRPOrigins("https://auth.example.com", "https://app.example.com"),
		passkey.WithChallengeTimeout(10*time.Minute),
		passkey.WithRequireSessionOnRegistration(false),
		passkey.WithUserVerification(protocol.VerificationRequired),
		passkey.WithResidentKey(protocol.ResidentKeyRequirementRequired),
		passkey.WithAttestation(protocol.PreferDirectAttestation),
		passkey.WithAuthenticatorAttachment(attachment),
		passkey.WithSessionDuration(24*time.Hour),
		passkey.WithResolveUser(func(ctx context.Context, q *string, extra map[string]any) (*passkey.PasskeyRegistrationUser, error) {
			resolveCalled = true
			return &passkey.PasskeyRegistrationUser{ID: "res_1", Name: "res@ex.com", DisplayName: "Resolved"}, nil
		}),
		passkey.WithAfterRegistration(func(ctx context.Context, pk *entity.Passkey, user *entity.User) error {
			afterRegCalled = true
			return nil
		}),
		passkey.WithAfterAuthentication(func(ctx context.Context, pk *entity.Passkey, user *entity.User, session *entity.Session) error {
			afterAuthCalled = true
			return nil
		}),
	)

	cfg := p.Config()
	if cfg.RPDisplayName != "Custom App" {
		t.Errorf("Expected RPDisplayName Custom App, got %s", cfg.RPDisplayName)
	}
	if cfg.RPID != "auth.example.com" {
		t.Errorf("Expected RPID auth.example.com, got %s", cfg.RPID)
	}
	if len(cfg.RPOrigins) != 2 {
		t.Errorf("Expected 2 origins, got %d", len(cfg.RPOrigins))
	}
	if cfg.ChallengeTimeout != 10*time.Minute {
		t.Errorf("Expected timeout 10m, got %v", cfg.ChallengeTimeout)
	}
	if cfg.RequireSessionOnRegistration != false {
		t.Errorf("Expected RequireSessionOnRegistration false")
	}
	if cfg.UserVerification != protocol.VerificationRequired {
		t.Errorf("Expected UserVerification required")
	}
	if cfg.ResidentKey != protocol.ResidentKeyRequirementRequired {
		t.Errorf("Expected ResidentKey required")
	}
	if cfg.Attestation != protocol.PreferDirectAttestation {
		t.Errorf("Expected Attestation direct")
	}
	if cfg.AuthenticatorAttachment == nil || *cfg.AuthenticatorAttachment != protocol.Platform {
		t.Errorf("Expected platform attachment")
	}
	if cfg.SessionDuration != 24*time.Hour {
		t.Errorf("Expected session duration 24h, got %v", cfg.SessionDuration)
	}

	_, _ = cfg.ResolveUser(context.Background(), nil, nil)
	if !resolveCalled {
		t.Errorf("ResolveUser hook was not assigned properly")
	}
	_ = cfg.AfterRegistration(context.Background(), nil, nil)
	if !afterRegCalled {
		t.Errorf("AfterRegistration hook was not assigned properly")
	}
	_ = cfg.AfterAuthentication(context.Background(), nil, nil, nil)
	if !afterAuthCalled {
		t.Errorf("AfterAuthentication hook was not assigned properly")
	}
}

func TestPlugin_GenerateRegistrationOptions_WithSession(t *testing.T) {
	p, repo, pCtx := setupTestPlugin(t)
	ctx := context.Background()

	// Seed user
	u, err := repo.CreateUser(ctx, &dto.CreateUserParams{
		Email: "alice@example.com",
		Name:  "Alice Example",
	})
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	var eventReceived bool
	var mu sync.Mutex
	_ = pCtx.Events().Subscribe(passkey.EventRegistrationOptionsCreated, func(payload passkey.RegistrationOptionsCreatedPayload) {
		mu.Lock()
		defer mu.Unlock()
		if payload.UserID == u.ID {
			eventReceived = true
		}
	})

	res, err := p.GenerateRegistrationOptions(ctx, &passkey.GenerateRegistrationOptionsParams{
		UserID: u.ID,
	})
	if err != nil {
		t.Fatalf("GenerateRegistrationOptions failed: %v", err)
	}

	if res.Options == nil {
		t.Fatal("Expected CredentialCreation options, got nil")
	}
	if res.ChallengeToken == "" {
		t.Fatal("Expected challenge token, got empty")
	}
	if res.ExpiresAt.Before(time.Now()) {
		t.Fatal("Expected expiration in future")
	}

	// Verify challenge in repo
	challenge, err := repo.GetPasskeyChallenge(ctx, res.ChallengeToken)
	if err != nil || challenge == nil {
		t.Fatalf("Challenge not saved in repo: %v", err)
	}
	if *challenge.UserID != u.ID {
		t.Errorf("Challenge UserID mismatch: got %v, want %v", *challenge.UserID, u.ID)
	}
	if challenge.Type != passkey.CeremonyRegistration {
		t.Errorf("Challenge type mismatch: got %v, want %v", challenge.Type, passkey.CeremonyRegistration)
	}

	mu.Lock()
	if !eventReceived {
		t.Error("EventRegistrationOptionsCreated was not published")
	}
	mu.Unlock()
}

func TestPlugin_GenerateRegistrationOptions_ResolveUser(t *testing.T) {
	ctx := context.Background()
	p, repo, _ := setupTestPlugin(t,
		passkey.WithRequireSessionOnRegistration(false),
		passkey.WithResolveUser(func(ctx context.Context, q *string, extra map[string]any) (*passkey.PasskeyRegistrationUser, error) {
			return &passkey.PasskeyRegistrationUser{
				ID:          "resolved_usr_99",
				Name:        "bob@example.com",
				DisplayName: "Bob Ross",
			}, nil
		}),
	)

	res, err := p.GenerateRegistrationOptions(ctx, &passkey.GenerateRegistrationOptionsParams{})
	if err != nil {
		t.Fatalf("GenerateRegistrationOptions with resolveUser failed: %v", err)
	}

	challenge, err := repo.GetPasskeyChallenge(ctx, res.ChallengeToken)
	if err != nil || challenge == nil {
		t.Fatalf("Challenge not found: %v", err)
	}
	if *challenge.UserID != "resolved_usr_99" {
		t.Errorf("Expected resolved UserID 'resolved_usr_99', got '%s'", *challenge.UserID)
	}
	if *challenge.UserName != "bob@example.com" {
		t.Errorf("Expected resolved UserName 'bob@example.com', got '%s'", *challenge.UserName)
	}
}

func TestPlugin_GenerateRegistrationOptions_Errors(t *testing.T) {
	ctx := context.Background()

	// 1. Session required by default
	p1, _, _ := setupTestPlugin(t)
	_, err := p1.GenerateRegistrationOptions(ctx, &passkey.GenerateRegistrationOptionsParams{})
	if !errors.Is(err, passkey.ErrSessionRequired) {
		t.Errorf("Expected ErrSessionRequired, got %v", err)
	}

	// 2. RequireSession=false but ResolveUser is nil
	p2, _, _ := setupTestPlugin(t, passkey.WithRequireSessionOnRegistration(false))
	_, err = p2.GenerateRegistrationOptions(ctx, &passkey.GenerateRegistrationOptionsParams{})
	if !errors.Is(err, passkey.ErrResolveUserRequired) {
		t.Errorf("Expected ErrResolveUserRequired, got %v", err)
	}

	// 3. ResolveUser returns error
	p3, _, _ := setupTestPlugin(t,
		passkey.WithRequireSessionOnRegistration(false),
		passkey.WithResolveUser(func(ctx context.Context, q *string, extra map[string]any) (*passkey.PasskeyRegistrationUser, error) {
			return nil, errors.New("db error")
		}),
	)
	_, err = p3.GenerateRegistrationOptions(ctx, &passkey.GenerateRegistrationOptionsParams{})
	if !errors.Is(err, passkey.ErrInvalidResolvedUser) {
		t.Errorf("Expected ErrInvalidResolvedUser, got %v", err)
	}
}

func TestPlugin_VerifyRegistration_ValidationErrors(t *testing.T) {
	p, repo, pCtx := setupTestPlugin(t)
	ctx := context.Background()

	// 1. Invalid params
	_, err := p.VerifyRegistration(ctx, nil)
	if !errors.Is(err, passkey.ErrInvalidParameter) {
		t.Errorf("Expected ErrInvalidParameter, got %v", err)
	}

	_, err = p.VerifyRegistration(ctx, &passkey.VerifyRegistrationParams{ChallengeToken: ""})
	if !errors.Is(err, passkey.ErrInvalidParameter) {
		t.Errorf("Expected ErrInvalidParameter, got %v", err)
	}

	// 2. Challenge not found
	_, err = p.VerifyRegistration(ctx, &passkey.VerifyRegistrationParams{
		ChallengeToken: "non_existent_token",
		Response:       &protocol.CredentialCreationResponse{},
	})
	if !errors.Is(err, passkey.ErrChallengeNotFound) {
		t.Errorf("Expected ErrChallengeNotFound, got %v", err)
	}

	// 3. Challenge expired
	expiredToken := "expired_token_123"
	_ = repo.SavePasskeyChallenge(ctx, &passkey.PasskeyChallenge{
		Token:       expiredToken,
		Type:        passkey.CeremonyRegistration,
		ExpiresAt:   time.Now().Add(-10 * time.Minute),
		SessionData: "{}",
	})

	var failedEventReceived bool
	_ = pCtx.Events().Subscribe(passkey.EventRegistrationFailed, func(payload passkey.RegistrationFailedPayload) {
		if payload.ChallengeToken == expiredToken {
			failedEventReceived = true
		}
	})

	_, err = p.VerifyRegistration(ctx, &passkey.VerifyRegistrationParams{
		ChallengeToken: expiredToken,
		Response:       &protocol.CredentialCreationResponse{},
	})
	if !errors.Is(err, passkey.ErrChallengeExpired) {
		t.Errorf("Expected ErrChallengeExpired, got %v", err)
	}
	if !failedEventReceived {
		t.Error("Expected EventRegistrationFailed on expired challenge")
	}

	// 4. Invalid ceremony type
	authTypeToken := "auth_token_456"
	_ = repo.SavePasskeyChallenge(ctx, &passkey.PasskeyChallenge{
		Token:       authTypeToken,
		Type:        passkey.CeremonyAuthentication,
		ExpiresAt:   time.Now().Add(10 * time.Minute),
		SessionData: "{}",
	})

	_, err = p.VerifyRegistration(ctx, &passkey.VerifyRegistrationParams{
		ChallengeToken: authTypeToken,
		Response:       &protocol.CredentialCreationResponse{},
	})
	if !errors.Is(err, passkey.ErrInvalidCeremonyType) {
		t.Errorf("Expected ErrInvalidCeremonyType, got %v", err)
	}

	// 5. Caller user mismatch
	mismatchToken := "mismatch_token_789"
	usrA := "user_a"
	usrB := "user_b"
	_ = repo.SavePasskeyChallenge(ctx, &passkey.PasskeyChallenge{
		Token:       mismatchToken,
		Type:        passkey.CeremonyRegistration,
		UserID:      &usrA,
		ExpiresAt:   time.Now().Add(10 * time.Minute),
		SessionData: `{"challenge":"xyz"}`,
	})

	_, err = p.VerifyRegistration(ctx, &passkey.VerifyRegistrationParams{
		ChallengeToken: mismatchToken,
		CallerUserID:   &usrB,
		Response:       &protocol.CredentialCreationResponse{},
	})
	if !errors.Is(err, passkey.ErrUnauthorized) {
		t.Errorf("Expected ErrUnauthorized, got %v", err)
	}
}

func TestPlugin_GenerateAuthenticationOptions(t *testing.T) {
	p, repo, pCtx := setupTestPlugin(t)
	ctx := context.Background()

	// 1. Discoverable login (nil UserID)
	var eventFired bool
	_ = pCtx.Events().Subscribe(passkey.EventAuthenticationOptionsCreated, func(payload passkey.AuthenticationOptionsCreatedPayload) {
		if payload.UserID == nil {
			eventFired = true
		}
	})

	res, err := p.GenerateAuthenticationOptions(ctx, &passkey.GenerateAuthenticationOptionsParams{})
	if err != nil {
		t.Fatalf("GenerateAuthenticationOptions discoverable failed: %v", err)
	}

	if res.Options == nil || res.ChallengeToken == "" {
		t.Fatal("Expected valid options and challenge token")
	}

	c, err := repo.GetPasskeyChallenge(ctx, res.ChallengeToken)
	if err != nil || c == nil {
		t.Fatalf("Challenge was not persisted: %v", err)
	}
	if c.Type != passkey.CeremonyAuthentication {
		t.Errorf("Expected ceremony authentication, got %v", c.Type)
	}
	if c.UserID != nil {
		t.Errorf("Expected nil UserID in discoverable challenge, got %v", c.UserID)
	}
	if !eventFired {
		t.Error("Expected EventAuthenticationOptionsCreated")
	}

	// 2. User-specific login
	u, _ := repo.CreateUser(ctx, &dto.CreateUserParams{Email: "charlie@example.com", Name: "Charlie"})
	_ = repo.CreatePasskey(ctx, &entity.Passkey{
		ID:           "pk_c1",
		UserID:       u.ID,
		CredentialID: "test_cred_id_123",
		PublicKey:    base64.StdEncoding.EncodeToString([]byte("fake_pub_key")),
		Counter:      10,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	})

	res2, err := p.GenerateAuthenticationOptions(ctx, &passkey.GenerateAuthenticationOptionsParams{
		UserID: &u.ID,
	})
	if err != nil {
		t.Fatalf("GenerateAuthenticationOptions user-specific failed: %v", err)
	}
	if res2.ChallengeToken == "" {
		t.Fatal("Expected challenge token")
	}
}

func TestPlugin_VerifyAuthentication_ValidationErrors(t *testing.T) {
	p, repo, pCtx := setupTestPlugin(t)
	ctx := context.Background()

	// 1. Invalid params
	_, err := p.VerifyAuthentication(ctx, nil)
	if !errors.Is(err, passkey.ErrInvalidParameter) {
		t.Errorf("Expected ErrInvalidParameter, got %v", err)
	}

	// 2. Challenge not found
	_, err = p.VerifyAuthentication(ctx, &passkey.VerifyAuthenticationParams{
		ChallengeToken: "missing_token",
		Response:       &protocol.CredentialAssertionResponse{},
	})
	if !errors.Is(err, passkey.ErrChallengeNotFound) {
		t.Errorf("Expected ErrChallengeNotFound, got %v", err)
	}

	// 3. Challenge expired
	expToken := "expired_auth_token"
	_ = repo.SavePasskeyChallenge(ctx, &passkey.PasskeyChallenge{
		Token:       expToken,
		Type:        passkey.CeremonyAuthentication,
		ExpiresAt:   time.Now().Add(-5 * time.Minute),
		SessionData: "{}",
	})

	var authFailedEvent bool
	_ = pCtx.Events().Subscribe(passkey.EventAuthenticationFailed, func(payload passkey.AuthenticationFailedPayload) {
		if payload.ChallengeToken == expToken {
			authFailedEvent = true
		}
	})

	_, err = p.VerifyAuthentication(ctx, &passkey.VerifyAuthenticationParams{
		ChallengeToken: expToken,
		Response:       &protocol.CredentialAssertionResponse{},
	})
	if !errors.Is(err, passkey.ErrChallengeExpired) {
		t.Errorf("Expected ErrChallengeExpired, got %v", err)
	}
	if !authFailedEvent {
		t.Error("Expected EventAuthenticationFailed on expired challenge")
	}

	// 4. Invalid ceremony type
	regToken := "reg_type_token"
	_ = repo.SavePasskeyChallenge(ctx, &passkey.PasskeyChallenge{
		Token:       regToken,
		Type:        passkey.CeremonyRegistration,
		ExpiresAt:   time.Now().Add(5 * time.Minute),
		SessionData: "{}",
	})

	_, err = p.VerifyAuthentication(ctx, &passkey.VerifyAuthenticationParams{
		ChallengeToken: regToken,
		Response:       &protocol.CredentialAssertionResponse{},
	})
	if !errors.Is(err, passkey.ErrInvalidCeremonyType) {
		t.Errorf("Expected ErrInvalidCeremonyType, got %v", err)
	}
}

func TestPlugin_PasskeyManagement_CRUD(t *testing.T) {
	p, repo, pCtx := setupTestPlugin(t)
	ctx := context.Background()

	u1, _ := repo.CreateUser(ctx, &dto.CreateUserParams{Email: "u1@ex.com", Name: "User 1"})
	u2, _ := repo.CreateUser(ctx, &dto.CreateUserParams{Email: "u2@ex.com", Name: "User 2"})

	// Seed passkeys
	pk1 := &entity.Passkey{
		ID:           "pk_101",
		Name:         ptr("My YubiKey"),
		UserID:       u1.ID,
		CredentialID: "cred_101",
		PublicKey:    base64.StdEncoding.EncodeToString([]byte("pub1")),
		Counter:      5,
		CreatedAt:    time.Now().Add(-2 * time.Hour),
		UpdatedAt:    time.Now().Add(-2 * time.Hour),
	}
	pk2 := &entity.Passkey{
		ID:           "pk_102",
		Name:         ptr("Work MacBook"),
		UserID:       u1.ID,
		CredentialID: "cred_102",
		PublicKey:    base64.StdEncoding.EncodeToString([]byte("pub2")),
		Counter:      12,
		CreatedAt:    time.Now().Add(-1 * time.Hour),
		UpdatedAt:    time.Now().Add(-1 * time.Hour),
	}
	_ = repo.CreatePasskey(ctx, pk1)
	_ = repo.CreatePasskey(ctx, pk2)

	// 1. ListPasskeys
	list, err := p.ListPasskeys(ctx, &passkey.ListPasskeysParams{UserID: u1.ID})
	if err != nil {
		t.Fatalf("ListPasskeys failed: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("Expected 2 passkeys, got %d", len(list))
	}

	_, err = p.ListPasskeys(ctx, &passkey.ListPasskeysParams{UserID: ""})
	if !errors.Is(err, passkey.ErrInvalidParameter) {
		t.Errorf("Expected ErrInvalidParameter for empty UserID, got %v", err)
	}

	// 2. GetPasskey
	fetched, err := p.GetPasskey(ctx, "pk_101")
	if err != nil || fetched == nil {
		t.Fatalf("GetPasskey failed: %v", err)
	}
	if *fetched.Name != "My YubiKey" {
		t.Errorf("Expected name 'My YubiKey', got '%s'", *fetched.Name)
	}

	_, err = p.GetPasskey(ctx, "pk_999")
	if !errors.Is(err, passkey.ErrPasskeyNotFound) {
		t.Errorf("Expected ErrPasskeyNotFound, got %v", err)
	}

	// 3. UpdatePasskey
	var updateEventReceived bool
	_ = pCtx.Events().Subscribe(passkey.EventPasskeyUpdated, func(payload passkey.PasskeyUpdatedPayload) {
		if payload.Passkey.ID == "pk_101" && payload.NewName == "Personal YubiKey 5" {
			updateEventReceived = true
		}
	})

	// Unauthorized update (different user)
	_, err = p.UpdatePasskey(ctx, &passkey.UpdatePasskeyParams{
		ID:           "pk_101",
		CallerUserID: u2.ID,
		Name:         "Hacked Name",
	})
	if !errors.Is(err, passkey.ErrUnauthorized) {
		t.Errorf("Expected ErrUnauthorized, got %v", err)
	}

	// Authorized update
	updated, err := p.UpdatePasskey(ctx, &passkey.UpdatePasskeyParams{
		ID:           "pk_101",
		CallerUserID: u1.ID,
		Name:         "Personal YubiKey 5",
	})
	if err != nil {
		t.Fatalf("UpdatePasskey failed: %v", err)
	}
	if *updated.Name != "Personal YubiKey 5" {
		t.Errorf("Expected updated name 'Personal YubiKey 5', got '%s'", *updated.Name)
	}
	if !updateEventReceived {
		t.Error("Expected EventPasskeyUpdated to be dispatched")
	}

	// 4. DeletePasskey
	var deleteEventReceived bool
	_ = pCtx.Events().Subscribe(passkey.EventPasskeyDeleted, func(payload passkey.PasskeyDeletedPayload) {
		if payload.PasskeyID == "pk_102" && payload.UserID == u1.ID {
			deleteEventReceived = true
		}
	})

	// Unauthorized delete
	err = p.DeletePasskey(ctx, &passkey.DeletePasskeyParams{
		ID:           "pk_102",
		CallerUserID: u2.ID,
	})
	if !errors.Is(err, passkey.ErrUnauthorized) {
		t.Errorf("Expected ErrUnauthorized on delete, got %v", err)
	}

	// Authorized delete
	err = p.DeletePasskey(ctx, &passkey.DeletePasskeyParams{
		ID:           "pk_102",
		CallerUserID: u1.ID,
	})
	if err != nil {
		t.Fatalf("DeletePasskey failed: %v", err)
	}
	if !deleteEventReceived {
		t.Error("Expected EventPasskeyDeleted to be dispatched")
	}

	// Verify deleted from repo
	_, err = p.GetPasskey(ctx, "pk_102")
	if !errors.Is(err, passkey.ErrPasskeyNotFound) {
		t.Errorf("Expected ErrPasskeyNotFound after delete, got %v", err)
	}
}
