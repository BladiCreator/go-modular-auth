package passkey_test

import (
	"context"
	"testing"
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	passkey "github.com/BladiCreator/go-modular-auth-passkeys"
	"github.com/BladiCreator/go-modular-auth-passkeys/challenge"
	"github.com/BladiCreator/go-modular-auth-passkeys/plugins"
	passkeystore "github.com/BladiCreator/go-modular-auth-passkeys/store"
	"github.com/BladiCreator/go-modular-auth/account"
	corestore "github.com/BladiCreator/go-modular-auth/store/memory"
	"github.com/BladiCreator/go-modular-auth/user"
	"github.com/go-webauthn/webauthn/protocol"
)

func setupTestAuth(t *testing.T, opts ...passkey.Option) (*auth.Auth, passkey.Passkeys) {
	t.Helper()
	storeAdapter := corestore.New()

	defaultOpts := []passkey.Option{
		passkey.WithRP("localhost", "Test App", []string{"http://localhost:3000"}),
		passkey.WithTimeout(60 * time.Second),
	}
	allOpts := append(defaultOpts, opts...)

	mod := passkey.New(allOpts...)

	a, err := auth.New(auth.Config{
		Store:   storeAdapter,
		Plugins: []auth.PluginModule{mod},
	})
	if err != nil {
		t.Fatalf("failed to initialize auth engine: %v", err)
	}

	pk, err := auth.Get[plugins.Passkeys](a)
	if err != nil {
		t.Fatalf("failed to lookup plugins.Passkeys capability: %v", err)
	}

	return a, pk
}

func createTestUser(t *testing.T, a *auth.Auth, email string) *user.User {
	t.Helper()
	ctx := context.Background()
	u := &user.User{
		ID:            "user_" + email,
		Email:         email,
		EmailVerified: true,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
	if err := a.Store().Users().Create(ctx, u); err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}
	return u
}

func TestCapabilityLookup(t *testing.T) {
	a, pk1 := setupTestAuth(t)

	pk2, err := auth.Get[passkey.Passkeys](a)
	if err != nil {
		t.Fatalf("failed to lookup passkey.Passkeys: %v", err)
	}

	if pk1 != pk2 {
		t.Fatal("expected plugins.Passkeys and passkey.Passkeys to resolve to the same instance")
	}
}

func TestBeginRegistration(t *testing.T) {
	ctx := context.Background()
	a, pk := setupTestAuth(t)
	u := createTestUser(t, a, "alice@example.com")

	// 1. Missing user ID
	_, err := pk.BeginRegistration(ctx, passkey.BeginRegistrationInput{})
	if err != passkey.ErrUserIDRequired {
		t.Fatalf("expected ErrUserIDRequired, got %v", err)
	}

	// 2. Non-existent user
	_, err = pk.BeginRegistration(ctx, passkey.BeginRegistrationInput{UserID: "unknown_id"})
	if err != passkey.ErrUserNotFound {
		t.Fatalf("expected ErrUserNotFound, got %v", err)
	}

	// 3. Valid registration initiation
	opts, err := pk.BeginRegistration(ctx, passkey.BeginRegistrationInput{
		UserID:           u.ID,
		FriendlyName:     "MacBook Pro",
		UserVerification: protocol.VerificationPreferred,
		ResidentKey:      protocol.ResidentKeyRequirementPreferred,
	})
	if err != nil {
		t.Fatalf("unexpected error in BeginRegistration: %v", err)
	}

	if opts.SessionID == "" {
		t.Fatal("expected non-empty SessionID")
	}
	if opts.Options == nil {
		t.Fatal("expected non-nil CredentialCreation options")
	}
	if opts.Options.Response.RelyingParty.ID != "localhost" {
		t.Fatalf("expected RP ID localhost, got %s", opts.Options.Response.RelyingParty.ID)
	}
	if opts.Options.Response.User.Name != "alice@example.com" {
		t.Fatalf("expected user name alice@example.com, got %s", opts.Options.Response.User.Name)
	}
	if opts.ExpiresAt.Before(time.Now()) {
		t.Fatal("expected expiration in the future")
	}
}

func TestFinishRegistrationValidation(t *testing.T) {
	ctx := context.Background()
	_, pk := setupTestAuth(t)

	// 1. Missing session ID
	_, err := pk.FinishRegistration(ctx, passkey.FinishRegistrationInput{})
	if err != passkey.ErrSessionIDRequired {
		t.Fatalf("expected ErrSessionIDRequired, got %v", err)
	}

	// 2. Non-existent session ID
	_, err = pk.FinishRegistration(ctx, passkey.FinishRegistrationInput{
		SessionID: "non_existent_session",
		Response:  []byte("{}"),
	})
	if err != passkey.ErrChallengeNotFound {
		t.Fatalf("expected ErrChallengeNotFound, got %v", err)
	}

	// 3. Invalid / missing client response data
	cStore := challenge.NewMemoryStore()
	_, pkWithCStore := setupTestAuth(t, passkey.WithChallengeStore(cStore))
	_ = cStore.Save(ctx, &challenge.Session{
		ID:        "valid_session",
		Type:      challenge.CeremonyRegistration,
		UserID:    "user_123",
		ExpiresAt: time.Now().Add(10 * time.Minute),
	})

	_, err = pkWithCStore.FinishRegistration(ctx, passkey.FinishRegistrationInput{
		SessionID: "valid_session",
	})
	if err != passkey.ErrInvalidClientResponse {
		t.Fatalf("expected ErrInvalidClientResponse, got %v", err)
	}

	// 4. Replay of session ID must be prevented
	_, err = pkWithCStore.FinishRegistration(ctx, passkey.FinishRegistrationInput{
		SessionID: "valid_session",
		Response:  []byte("{}"),
	})
	if err != passkey.ErrChallengeAlreadyUsed {
		t.Fatalf("expected ErrChallengeAlreadyUsed on replay, got %v", err)
	}
}

func TestBeginAuthentication(t *testing.T) {
	ctx := context.Background()
	a, pk := setupTestAuth(t)
	u := createTestUser(t, a, "bob@example.com")

	// 1. Discoverable login (empty UserID)
	discOpts, err := pk.BeginAuthentication(ctx, passkey.BeginAuthenticationInput{})
	if err != nil {
		t.Fatalf("unexpected error in discoverable BeginAuthentication: %v", err)
	}
	if discOpts.SessionID == "" {
		t.Fatal("expected non-empty SessionID")
	}
	if len(discOpts.Options.Response.AllowedCredentials) != 0 {
		t.Fatalf("expected no allowed credentials for discoverable login, got %d", len(discOpts.Options.Response.AllowedCredentials))
	}

	// 2. User-specific login without any registered credentials
	_, err = pk.BeginAuthentication(ctx, passkey.BeginAuthenticationInput{UserID: u.ID})
	if err != passkey.ErrCredentialNotFound {
		t.Fatalf("expected ErrCredentialNotFound when user has no passkeys, got %v", err)
	}
}

func TestCredentialManagementAndOwnership(t *testing.T) {
	ctx := context.Background()
	pStore := passkeystore.Store(nil)
	memStore := passkey.WithStore(nil) // default in-memory store
	a, pk := setupTestAuth(t, memStore)

	u1 := createTestUser(t, a, "user1@example.com")
	u2 := createTestUser(t, a, "user2@example.com")

	// Directly register a credential for u1 to test management APIs
	cred1 := &passkey.Passkey{
		ID:           "cred_u1_base64",
		CredentialID: []byte("cred_u1_binary"),
		UserID:       u1.ID,
		FriendlyName: "MacBook TouchID",
		PublicKey:    []byte("cose_pub_key_1"),
		SignCount:    10,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	// Save to plugin store
	cfgField, ok := pk.(interface {
		ListCredentials(ctx context.Context, userID string) ([]*passkey.Passkey, error)
	})
	if !ok {
		t.Fatal("pk does not implement ListCredentials")
	}
	_ = cfgField
	_ = pStore

	// We can link account to core store
	_ = a.Store().Accounts().Create(ctx, &account.Account{
		ID:         "acc_u1",
		UserID:     u1.ID,
		Provider:   passkey.ProviderPasskey,
		ProviderID: cred1.ID,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	})

	// Inject credential through BeginRegistration + test store
	customStore := &testCustomStore{credentials: make(map[string]*passkey.Passkey)}
	customStore.credentials[string(cred1.CredentialID)] = cred1

	_, pkCustom := setupTestAuth(t, passkey.WithStore(customStore))

	// 1. List credentials
	list, err := pkCustom.ListCredentials(ctx, u1.ID)
	if err != nil {
		t.Fatalf("unexpected error listing: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 credential, got %d", len(list))
	}

	// 2. Get credential with valid owner
	got, err := pkCustom.GetCredential(ctx, u1.ID, cred1.CredentialID)
	if err != nil {
		t.Fatalf("unexpected error getting: %v", err)
	}
	if got.FriendlyName != "MacBook TouchID" {
		t.Fatalf("unexpected friendly name: %s", got.FriendlyName)
	}

	// 3. Get credential with wrong owner (horizontal privilege escalation prevention)
	_, err = pkCustom.GetCredential(ctx, u2.ID, cred1.CredentialID)
	if err != passkey.ErrCredentialNotFound {
		t.Fatalf("expected ErrCredentialNotFound when accessed by different user, got %v", err)
	}

	// 4. Update credential friendly name
	updated, err := pkCustom.UpdateCredential(ctx, passkey.UpdateCredentialInput{
		UserID:       u1.ID,
		CredentialID: cred1.CredentialID,
		FriendlyName: "Work Laptop",
	})
	if err != nil {
		t.Fatalf("unexpected update error: %v", err)
	}
	if updated.FriendlyName != "Work Laptop" {
		t.Fatalf("expected Work Laptop, got %s", updated.FriendlyName)
	}

	// 5. Update credential by wrong user
	_, err = pkCustom.UpdateCredential(ctx, passkey.UpdateCredentialInput{
		UserID:       u2.ID,
		CredentialID: cred1.CredentialID,
		FriendlyName: "Hacked",
	})
	if err != passkey.ErrCredentialNotFound {
		t.Fatalf("expected ErrCredentialNotFound, got %v", err)
	}

	// 6. Delete credential
	if err := pkCustom.DeleteCredential(ctx, passkey.DeleteCredentialInput{
		UserID:       u1.ID,
		CredentialID: cred1.CredentialID,
	}); err != nil {
		t.Fatalf("unexpected error deleting: %v", err)
	}

	listAfter, _ := pkCustom.ListCredentials(ctx, u1.ID)
	if len(listAfter) != 0 {
		t.Fatalf("expected 0 credentials after deletion, got %d", len(listAfter))
	}
}

func TestEventEmissions(t *testing.T) {
	ctx := context.Background()
	customStore := &testCustomStore{credentials: make(map[string]*passkey.Passkey)}
	a, pk := setupTestAuth(t, passkey.WithStore(customStore))

	u := createTestUser(t, a, "events@example.com")

	cred := &passkey.Passkey{
		ID:           "test_event_cred",
		CredentialID: []byte("event_cred_bin"),
		UserID:       u.ID,
		FriendlyName: "Security Key",
		SignCount:    1,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	customStore.credentials[string(cred.CredentialID)] = cred

	revokedReceived := false
	a.Events().Subscribe(passkey.EventPasskeyRevoked, func(ctx context.Context, e auth.Event) {
		if e.Subject == u.ID {
			revokedReceived = true
			payload, ok := e.Payload.(passkey.PasskeyRevokedPayload)
			if !ok {
				t.Fatalf("invalid payload type: %T", e.Payload)
			}
			if payload.CredentialID != "test_event_cred" {
				t.Fatalf("mismatched payload credential ID: %s", payload.CredentialID)
			}
		}
	})

	err := pk.DeleteCredential(ctx, passkey.DeleteCredentialInput{
		UserID:       u.ID,
		CredentialID: cred.CredentialID,
	})
	if err != nil {
		t.Fatalf("failed deleting credential: %v", err)
	}

	if !revokedReceived {
		t.Fatal("expected EventPasskeyRevoked to be emitted")
	}
}

func TestHooksIntervention(t *testing.T) {
	ctx := context.Background()
	hookCalled := false

	hooks := passkey.NewHooks()
	hooks.BeforeBeginRegistration = func(ctx context.Context, in *passkey.BeginRegistrationInput) error {
		hookCalled = true
		return nil
	}

	a, pk := setupTestAuth(t, passkey.WithHooks(hooks))
	u := createTestUser(t, a, "hooks@example.com")

	_, err := pk.BeginRegistration(ctx, passkey.BeginRegistrationInput{UserID: u.ID})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !hookCalled {
		t.Fatal("expected BeforeBeginRegistration hook to execute")
	}
}

// testCustomStore satisfies passkeystore.Store for isolated mock testing.
type testCustomStore struct {
	credentials map[string]*passkey.Passkey
}

func (s *testCustomStore) SaveCredential(ctx context.Context, c *passkeystore.Credential) error {
	if _, ok := s.credentials[string(c.CredentialID)]; ok {
		return passkeystore.ErrConflict
	}
	cp := *c
	s.credentials[string(c.CredentialID)] = &cp
	return nil
}

func (s *testCustomStore) GetCredentialByID(ctx context.Context, id []byte) (*passkeystore.Credential, error) {
	c, ok := s.credentials[string(id)]
	if !ok || !c.Active() {
		return nil, passkeystore.ErrNotFound
	}
	cp := *c
	return &cp, nil
}

func (s *testCustomStore) ListCredentialsByUser(ctx context.Context, userID string) ([]*passkeystore.Credential, error) {
	var res []*passkeystore.Credential
	for _, c := range s.credentials {
		if c.UserID == userID && c.Active() {
			cp := *c
			res = append(res, &cp)
		}
	}
	return res, nil
}

func (s *testCustomStore) UpdateCredential(ctx context.Context, c *passkeystore.Credential) error {
	if _, ok := s.credentials[string(c.CredentialID)]; !ok {
		return passkeystore.ErrNotFound
	}
	cp := *c
	s.credentials[string(c.CredentialID)] = &cp
	return nil
}

func (s *testCustomStore) DeleteCredential(ctx context.Context, id []byte) error {
	c, ok := s.credentials[string(id)]
	if !ok {
		return passkeystore.ErrNotFound
	}
	now := time.Now()
	c.RevokedAt = &now
	delete(s.credentials, string(id))
	return nil
}
