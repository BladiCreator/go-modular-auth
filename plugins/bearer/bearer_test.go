package bearer_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	bearer "github.com/BladiCreator/go-modular-auth-bearer"
	"github.com/BladiCreator/go-modular-auth-bearer/plugins"
	adaptermem "github.com/BladiCreator/go-modular-auth/adapter/memory"
	corecpmem "github.com/BladiCreator/go-modular-auth/cache/memory"
)

func setupTestAuth(t *testing.T, opts ...bearer.Option) (*auth.Auth, bearer.Bearer) {
	t.Helper()

	cacheAdapter := corecpmem.New()
	adapterInstance := adaptermem.New()

	app, err := auth.New(auth.Config{
		Adapter: adapterInstance,
		Cache:   cacheAdapter,
		Plugins: []auth.PluginModule{bearer.New(opts...)},
	})
	if err != nil {
		t.Fatalf("failed to initialize auth core: %v", err)
	}

	plugin, err := auth.Get[plugins.Bearer](app)
	if err != nil {
		t.Fatalf("failed to retrieve plugins.Bearer: %v", err)
	}

	return app, plugin
}

func TestBearer_RegistrationAndLookup(t *testing.T) {
	app, plugin := setupTestAuth(t)

	if plugin == nil {
		t.Fatal("expected non-nil Bearer capability")
	}

	mustPlugin := auth.MustGet[plugins.Bearer](app)
	if mustPlugin == nil {
		t.Fatal("expected non-nil MustGet Bearer capability")
	}
}

func TestBearer_IssueAndAuthenticate(t *testing.T) {
	ctx := context.Background()
	_, plugin := setupTestAuth(t)

	// 1. Issue token
	issueRes, err := plugin.Issue(ctx, bearer.IssueInput{
		Subject:       "user-42",
		PrincipalType: auth.PrincipalUser,
		Scopes:        []string{"profile", "orders:read"},
		TTL:           time.Hour,
		Metadata:      map[string]string{"client_id": "mobile-app"},
	})
	if err != nil {
		t.Fatalf("unexpected issue error: %v", err)
	}

	if issueRes.Token == "" {
		t.Fatal("expected non-empty plaintext token")
	}
	if !strings.HasPrefix(issueRes.Token, bearer.DefaultTokenPrefix) {
		t.Fatalf("expected token prefix %q, got %q", bearer.DefaultTokenPrefix, issueRes.Token)
	}
	if issueRes.Info.Subject != "user-42" {
		t.Fatalf("expected subject user-42, got %q", issueRes.Info.Subject)
	}
	if !issueRes.Info.HasScope("profile") || !issueRes.Info.HasScope("orders:read") {
		t.Fatal("missing expected scopes in TokenInfo")
	}

	// 2. Authenticate successfully
	authRes, err := plugin.Authenticate(ctx, bearer.AuthenticateInput{
		Token:          issueRes.Token,
		RequiredScopes: []string{"profile"},
	})
	if err != nil {
		t.Fatalf("unexpected authenticate error: %v", err)
	}

	if authRes.Principal.Subject != "user-42" {
		t.Fatalf("expected principal subject user-42, got %q", authRes.Principal.Subject)
	}
	if authRes.Principal.Type != auth.PrincipalUser {
		t.Fatalf("expected principal type user, got %q", authRes.Principal.Type)
	}
	if authRes.Token.ID != issueRes.Info.ID {
		t.Fatalf("expected matching token ID %q, got %q", issueRes.Info.ID, authRes.Token.ID)
	}

	// 3. Authenticate with invalid token
	_, err = plugin.Authenticate(ctx, bearer.AuthenticateInput{
		Token: "invalid-token-credential-xyz",
	})
	if !errors.Is(err, bearer.ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken for nonexistent token, got %v", err)
	}

	// 4. Authenticate with empty token
	_, err = plugin.Authenticate(ctx, bearer.AuthenticateInput{
		Token: "",
	})
	if !errors.Is(err, bearer.ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken for empty token, got %v", err)
	}
}

func TestBearer_ScopesValidation(t *testing.T) {
	ctx := context.Background()
	_, plugin := setupTestAuth(t)

	issueRes, err := plugin.Issue(ctx, bearer.IssueInput{
		Subject: "admin-user",
		Scopes:  []string{"read", "write"},
	})
	if err != nil {
		t.Fatalf("issue error: %v", err)
	}

	// Sufficient scopes
	_, err = plugin.Authenticate(ctx, bearer.AuthenticateInput{
		Token:          issueRes.Token,
		RequiredScopes: []string{"read"},
	})
	if err != nil {
		t.Fatalf("expected success with scope read: %v", err)
	}

	_, err = plugin.Authenticate(ctx, bearer.AuthenticateInput{
		Token:          issueRes.Token,
		RequiredScopes: []string{"read", "write"},
	})
	if err != nil {
		t.Fatalf("expected success with both scopes: %v", err)
	}

	// Insufficient scope
	_, err = plugin.Authenticate(ctx, bearer.AuthenticateInput{
		Token:          issueRes.Token,
		RequiredScopes: []string{"read", "delete"},
	})
	if !errors.Is(err, bearer.ErrInsufficientScope) {
		t.Fatalf("expected ErrInsufficientScope, got %v", err)
	}
}

func TestBearer_Expiration(t *testing.T) {
	ctx := context.Background()
	_, plugin := setupTestAuth(t)

	// Issue token with immediate expiration
	issueRes, err := plugin.Issue(ctx, bearer.IssueInput{
		Subject: "expiring-user",
		TTL:     10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("issue error: %v", err)
	}

	time.Sleep(20 * time.Millisecond)

	_, err = plugin.Authenticate(ctx, bearer.AuthenticateInput{
		Token: issueRes.Token,
	})
	if !errors.Is(err, bearer.ErrTokenExpired) {
		t.Fatalf("expected ErrTokenExpired, got %v", err)
	}
}

func TestBearer_Revocation(t *testing.T) {
	ctx := context.Background()
	_, plugin := setupTestAuth(t)

	issueRes, err := plugin.Issue(ctx, bearer.IssueInput{
		Subject: "revokable-user",
		TTL:     time.Hour,
	})
	if err != nil {
		t.Fatalf("issue error: %v", err)
	}

	// Authenticate works initially
	_, err = plugin.Authenticate(ctx, bearer.AuthenticateInput{Token: issueRes.Token})
	if err != nil {
		t.Fatalf("initial auth failed: %v", err)
	}

	// Revoke by ID
	if err := plugin.Revoke(ctx, issueRes.Info.ID); err != nil {
		t.Fatalf("unexpected revoke error: %v", err)
	}

	// Authenticate should now fail with ErrTokenRevoked
	_, err = plugin.Authenticate(ctx, bearer.AuthenticateInput{Token: issueRes.Token})
	if !errors.Is(err, bearer.ErrTokenRevoked) {
		t.Fatalf("expected ErrTokenRevoked, got %v", err)
	}
}

func TestBearer_RevokeBySubject(t *testing.T) {
	ctx := context.Background()
	_, plugin := setupTestAuth(t)

	t1, _ := plugin.Issue(ctx, bearer.IssueInput{Subject: "subject-a", TTL: time.Hour})
	t2, _ := plugin.Issue(ctx, bearer.IssueInput{Subject: "subject-a", TTL: time.Hour})
	t3, _ := plugin.Issue(ctx, bearer.IssueInput{Subject: "subject-b", TTL: time.Hour})

	if err := plugin.RevokeBySubject(ctx, "subject-a"); err != nil {
		t.Fatalf("unexpected RevokeBySubject error: %v", err)
	}

	// Subject A tokens revoked
	if _, err := plugin.Authenticate(ctx, bearer.AuthenticateInput{Token: t1.Token}); !errors.Is(err, bearer.ErrTokenRevoked) {
		t.Fatalf("expected ErrTokenRevoked for t1, got %v", err)
	}
	if _, err := plugin.Authenticate(ctx, bearer.AuthenticateInput{Token: t2.Token}); !errors.Is(err, bearer.ErrTokenRevoked) {
		t.Fatalf("expected ErrTokenRevoked for t2, got %v", err)
	}

	// Subject B token remains valid
	if _, err := plugin.Authenticate(ctx, bearer.AuthenticateInput{Token: t3.Token}); err != nil {
		t.Fatalf("expected t3 to remain valid, got %v", err)
	}
}

func TestBearer_TransportContractAndExtraction(t *testing.T) {
	// 1. Test ExtractBearerToken helper
	tests := []struct {
		name      string
		header    string
		wantToken string
		wantErr   error
	}{
		{"valid standard", "Bearer my-secret-token", "my-secret-token", nil},
		{"valid lowercase", "bearer my-secret-token", "my-secret-token", nil},
		{"valid extra spaces", "  Bearer   my-secret-token   ", "my-secret-token", nil},
		{"empty header", "", "", bearer.ErrMissingBearerToken},
		{"whitespace header", "   ", "", bearer.ErrMissingBearerToken},
		{"basic auth prefix", "Basic dXNlcjpwYXNz", "", bearer.ErrMalformedBearerHeader},
		{"bearer with empty token", "Bearer ", "", bearer.ErrMissingBearerToken},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := bearer.ExtractBearerToken(tt.header)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("expected error %v, got %v", tt.wantErr, err)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if got != tt.wantToken {
					t.Fatalf("expected token %q, got %q", tt.wantToken, got)
				}
			}
		})
	}

	// 2. Context helpers
	info := &bearer.TokenInfo{ID: "tok-1", Subject: "user-ctx"}
	ctx := bearer.WithTokenInfo(context.Background(), info)
	extracted, ok := bearer.TokenInfoFrom(ctx)
	if !ok || extracted.ID != "tok-1" {
		t.Fatalf("context extraction failed: got %+v", extracted)
	}

	_, ok = bearer.TokenInfoFrom(context.Background())
	if ok {
		t.Fatal("expected false for context without TokenInfo")
	}
}

func TestBearer_Security_NoSecretLeakage(t *testing.T) {
	ctx := context.Background()
	_, plugin := setupTestAuth(t)

	secretToken := "gmb_extremely_confidential_secret_value_1234567890"

	// 1. Error messages MUST NOT leak secret credential
	_, err := plugin.Authenticate(ctx, bearer.AuthenticateInput{Token: secretToken})
	if err == nil {
		t.Fatal("expected authentication error")
	}
	if strings.Contains(err.Error(), secretToken) {
		t.Fatalf("CRITICAL SECURITY VIOLATION: error exposes secret token: %v", err)
	}

	// 2. TokenInfo returned does NOT contain secret or hash
	res, err := plugin.Issue(ctx, bearer.IssueInput{Subject: "user-sec"})
	if err != nil {
		t.Fatalf("issue error: %v", err)
	}
	getRes, err := plugin.Get(ctx, res.Info.ID)
	if err != nil {
		t.Fatalf("get error: %v", err)
	}
	if getRes.ID != res.Info.ID || getRes.Subject != "user-sec" {
		t.Fatalf("unexpected TokenInfo content: %+v", getRes)
	}
}

func TestBearer_LifecycleHooks(t *testing.T) {
	ctx := context.Background()
	hooks := bearer.NewHooks()

	var beforeIssueCalled, afterIssueCalled int32
	var beforeAuthCalled, afterAuthCalled int32
	var beforeRevokeCalled int32

	hooks.BeforeIssue(func(_ context.Context, in *bearer.IssueInput) error {
		atomic.AddInt32(&beforeIssueCalled, 1)
		in.Scopes = append(in.Scopes, "injected-scope")
		return nil
	})
	hooks.AfterIssue(func(_ context.Context, res *bearer.IssueResult) error {
		atomic.AddInt32(&afterIssueCalled, 1)
		return nil
	})
	hooks.BeforeAuthenticate(func(_ context.Context, _ *bearer.AuthenticateInput) error {
		atomic.AddInt32(&beforeAuthCalled, 1)
		return nil
	})
	hooks.AfterAuthenticate(func(_ context.Context, _ *bearer.AuthResult) error {
		atomic.AddInt32(&afterAuthCalled, 1)
		return nil
	})
	hooks.BeforeRevoke(func(_ context.Context, _ string) error {
		atomic.AddInt32(&beforeRevokeCalled, 1)
		return nil
	})

	_, plugin := setupTestAuth(t, bearer.WithHooks(hooks))

	// Issue token
	res, err := plugin.Issue(ctx, bearer.IssueInput{Subject: "hook-user"})
	if err != nil {
		t.Fatalf("issue error: %v", err)
	}
	if atomic.LoadInt32(&beforeIssueCalled) != 1 || atomic.LoadInt32(&afterIssueCalled) != 1 {
		t.Fatal("issue hooks were not invoked")
	}
	if !res.Info.HasScope("injected-scope") {
		t.Fatal("expected hook to inject scope")
	}

	// Authenticate
	_, err = plugin.Authenticate(ctx, bearer.AuthenticateInput{Token: res.Token})
	if err != nil {
		t.Fatalf("auth error: %v", err)
	}
	if atomic.LoadInt32(&beforeAuthCalled) != 1 || atomic.LoadInt32(&afterAuthCalled) != 1 {
		t.Fatal("auth hooks were not invoked")
	}

	// Revoke
	if err := plugin.Revoke(ctx, res.Info.ID); err != nil {
		t.Fatalf("revoke error: %v", err)
	}
	if atomic.LoadInt32(&beforeRevokeCalled) != 1 {
		t.Fatal("revoke hook was not invoked")
	}
}

func TestBearer_Events(t *testing.T) {
	ctx := context.Background()
	var (
		mu           sync.Mutex
		eventsCaught []auth.EventName
	)

	app, err := auth.New(auth.Config{
		Adapter: adaptermem.New(),
		Plugins: []auth.PluginModule{bearer.New()},
	})
	if err != nil {
		t.Fatalf("auth new error: %v", err)
	}

	app.Events().Subscribe(bearer.EventBearerTokenIssued, func(_ context.Context, e auth.Event) {
		mu.Lock()
		eventsCaught = append(eventsCaught, e.Name)
		mu.Unlock()
	})
	app.Events().Subscribe(bearer.EventBearerAuthenticated, func(_ context.Context, e auth.Event) {
		mu.Lock()
		eventsCaught = append(eventsCaught, e.Name)
		mu.Unlock()
	})
	app.Events().Subscribe(bearer.EventBearerTokenRevoked, func(_ context.Context, e auth.Event) {
		mu.Lock()
		eventsCaught = append(eventsCaught, e.Name)
		mu.Unlock()
	})

	plugin := auth.MustGet[plugins.Bearer](app)
	res, err := plugin.Issue(ctx, bearer.IssueInput{Subject: "events-user"})
	if err != nil {
		t.Fatalf("issue error: %v", err)
	}

	_, err = plugin.Authenticate(ctx, bearer.AuthenticateInput{Token: res.Token})
	if err != nil {
		t.Fatalf("auth error: %v", err)
	}

	_ = plugin.Revoke(ctx, res.Info.ID)

	mu.Lock()
	defer mu.Unlock()
	if len(eventsCaught) != 3 {
		t.Fatalf("expected 3 events, caught %d: %v", len(eventsCaught), eventsCaught)
	}
}

func TestBearer_Concurrency(t *testing.T) {
	ctx := context.Background()
	_, plugin := setupTestAuth(t)

	const workers = 30
	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			subject := "concurrent-user"
			res, err := plugin.Issue(ctx, bearer.IssueInput{
				Subject: subject,
				Scopes:  []string{"read"},
				TTL:     time.Hour,
			})
			if err != nil {
				t.Errorf("worker %d issue failed: %v", workerID, err)
				return
			}

			authRes, err := plugin.Authenticate(ctx, bearer.AuthenticateInput{
				Token:          res.Token,
				RequiredScopes: []string{"read"},
			})
			if err != nil {
				t.Errorf("worker %d auth failed: %v", workerID, err)
				return
			}
			if authRes.Principal.Subject != subject {
				t.Errorf("worker %d unexpected subject: %s", workerID, authRes.Principal.Subject)
			}

			if err := plugin.Revoke(ctx, res.Info.ID); err != nil {
				t.Errorf("worker %d revoke failed: %v", workerID, err)
			}
		}(i)
	}

	wg.Wait()
}

func TestBearer_PurgeExpired(t *testing.T) {
	ctx := context.Background()
	_, plugin := setupTestAuth(t)

	// Issue token that expired in the past
	t1, err := plugin.Issue(ctx, bearer.IssueInput{
		Subject: "expired-user",
		TTL:     time.Millisecond,
	})
	if err != nil {
		t.Fatalf("issue error: %v", err)
	}

	time.Sleep(10 * time.Millisecond)

	count, err := plugin.PurgeExpired(ctx)
	if err != nil {
		t.Fatalf("unexpected PurgeExpired error: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 purged token, got %d", count)
	}

	_, err = plugin.Get(ctx, t1.Info.ID)
	if !errors.Is(err, bearer.ErrTokenNotFound) {
		t.Fatalf("expected ErrTokenNotFound after purge, got %v", err)
	}
}
