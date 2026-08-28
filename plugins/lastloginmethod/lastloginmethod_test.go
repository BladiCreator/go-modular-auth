package lastloginmethod_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/BladiCreator/go-modular-auth/adapters/memory"
	"github.com/BladiCreator/go-modular-auth/auth"
	"github.com/BladiCreator/go-modular-auth/config"
	"github.com/BladiCreator/go-modular-auth/domain/dto"
	"github.com/BladiCreator/go-modular-auth/plugins"
	"github.com/BladiCreator/go-modular-auth/plugins/lastloginmethod"
)

func TestResolver(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name           string
		path           string
		query          string
		customResolver lastloginmethod.ResolveMethodFunc
		expected       string
		expectedOK     bool
	}{
		{
			name:       "Email sign in",
			path:       "/api/auth/sign-in/email",
			expected:   "email",
			expectedOK: true,
		},
		{
			name:       "Email sign up",
			path:       "/api/auth/sign-up/email",
			expected:   "email",
			expectedOK: true,
		},
		{
			name:       "Username sign in",
			path:       "/api/auth/sign-in/username",
			expected:   "username",
			expectedOK: true,
		},
		{
			name:       "Phone number verification",
			path:       "/api/auth/phone-number/verify",
			expected:   "phone-number",
			expectedOK: true,
		},
		{
			name:       "Passkey verification",
			path:       "/api/auth/passkey/verify-authentication",
			expected:   "passkey",
			expectedOK: true,
		},
		{
			name:       "Magic link verification",
			path:       "/api/auth/magic-link/verify",
			expected:   "magic-link",
			expectedOK: true,
		},
		{
			name:       "SIWE verification",
			path:       "/api/auth/siwe/verify",
			expected:   "siwe",
			expectedOK: true,
		},
		{
			name:       "Email OTP verification",
			path:       "/api/auth/email-otp/verify",
			expected:   "email-otp",
			expectedOK: true,
		},
		{
			name:       "OAuth callback with provider in path",
			path:       "/api/auth/callback/google",
			expected:   "google",
			expectedOK: true,
		},
		{
			name:       "OAuth2 callback with provider in path",
			path:       "/api/auth/oauth2/callback/github",
			expected:   "github",
			expectedOK: true,
		},
		{
			name:       "OAuth callback with provider in query",
			path:       "/api/auth/oauth/callback",
			query:      "provider=facebook",
			expected:   "facebook",
			expectedOK: true,
		},
		{
			name:       "Unknown path",
			path:       "/api/auth/random/endpoint",
			expected:   "",
			expectedOK: false,
		},
		{
			name: "Custom resolver override",
			path: "/api/auth/custom/path",
			customResolver: func(ctx context.Context, r *http.Request) (string, bool) {
				return "saml", true
			},
			expected:   "saml",
			expectedOK: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			urlStr := tt.path
			if tt.query != "" {
				urlStr += "?" + tt.query
			}
			req := httptest.NewRequest(http.MethodPost, urlStr, nil)
			cfg := lastloginmethod.DefaultConfig()
			cfg.CustomResolver = tt.customResolver

			method, ok := lastloginmethod.ResolveMethod(ctx, req, cfg)
			if ok != tt.expectedOK {
				t.Fatalf("expected ok=%v, got %v", tt.expectedOK, ok)
			}
			if method != tt.expected {
				t.Fatalf("expected method=%q, got %q", tt.expected, method)
			}
		})
	}
}

func TestCustomRouteMappings(t *testing.T) {
	ctx := context.Background()

	cfg := lastloginmethod.DefaultConfig()
	opt1 := lastloginmethod.WithRouteMapping("/custom/sso/login", "custom-sso")
	opt2 := lastloginmethod.WithRouteMappings(map[string]string{
		"/enterprise/login": "enterprise-idp",
	})
	opt1(&cfg)
	opt2(&cfg)

	t.Run("Custom Route 1", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/custom/sso/login", nil)
		method, ok := lastloginmethod.ResolveMethod(ctx, req, cfg)
		if !ok || method != "custom-sso" {
			t.Fatalf("expected custom-sso, got %q (ok=%v)", method, ok)
		}
	})

	t.Run("Custom Route 2", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/enterprise/login", nil)
		method, ok := lastloginmethod.ResolveMethod(ctx, req, cfg)
		if !ok || method != "enterprise-idp" {
			t.Fatalf("expected enterprise-idp, got %q (ok=%v)", method, ok)
		}
	})

	t.Run("Disabled Default Routes", func(t *testing.T) {
		cfgDisabled := cfg
		optDisabled := lastloginmethod.WithDisableDefaultRoutes(true)
		optDisabled(&cfgDisabled)

		// Default route should be ignored
		req := httptest.NewRequest(http.MethodPost, "/api/auth/sign-in/email", nil)
		_, ok := lastloginmethod.ResolveMethod(ctx, req, cfgDisabled)
		if ok {
			t.Fatal("expected resolve to fail when default routes are disabled")
		}

		// Configured custom route should still work
		reqCustom := httptest.NewRequest(http.MethodPost, "/custom/sso/login", nil)
		method, ok := lastloginmethod.ResolveMethod(ctx, reqCustom, cfgDisabled)
		if !ok || method != "custom-sso" {
			t.Fatalf("expected custom-sso to work, got %q (ok=%v)", method, ok)
		}
	})
}

func TestMiddlewareAutoTracking(t *testing.T) {
	p := lastloginmethod.New(
		lastloginmethod.WithRouteMapping("/my/custom/login", "my-login-method"),
	)

	middleware := p.Middleware()

	t.Run("Successful Response 200 OK", func(t *testing.T) {
		handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		}))

		req := httptest.NewRequest(http.MethodPost, "/my/custom/login", nil)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		cookies := w.Result().Cookies()
		if len(cookies) == 0 {
			t.Fatal("expected set-cookie header on 200 OK response")
		}
		if cookies[0].Value != "my-login-method" {
			t.Fatalf("expected cookie value 'my-login-method', got %q", cookies[0].Value)
		}
	})

	t.Run("Failed Response 401 Unauthorized", func(t *testing.T) {
		handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
		}))

		req := httptest.NewRequest(http.MethodPost, "/my/custom/login", nil)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		cookies := w.Result().Cookies()
		if len(cookies) > 0 {
			t.Fatal("expected no cookie header on 401 Unauthorized response")
		}
	})
}

func TestCookieHelpers(t *testing.T) {
	cfg := lastloginmethod.DefaultConfig()
	w := httptest.NewRecorder()

	lastloginmethod.SetLastLoginMethodCookie(w, "google", cfg)
	resp := w.Result()

	cookies := resp.Cookies()
	if len(cookies) == 0 {
		t.Fatal("expected set-cookie header in response")
	}

	c := cookies[0]
	if c.Name != cfg.CookieName {
		t.Fatalf("expected cookie name %q, got %q", cfg.CookieName, c.Name)
	}
	if c.Value != "google" {
		t.Fatalf("expected cookie value %q, got %q", "google", c.Value)
	}
	if c.HttpOnly != false {
		t.Fatalf("expected HttpOnly=false for JS accessibility, got %v", c.HttpOnly)
	}

	// Verify reading cookie from request
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(c)

	extracted := lastloginmethod.GetLastUsedLoginMethod(req, cfg.CookieName)
	if extracted != "google" {
		t.Fatalf("expected extracted cookie value %q, got %q", "google", extracted)
	}

	// Verify clearing cookie
	wClear := httptest.NewRecorder()
	lastloginmethod.ClearLastUsedLoginMethod(wClear, cfg)
	clearResp := wClear.Result()
	clearCookies := clearResp.Cookies()
	if len(clearCookies) == 0 {
		t.Fatal("expected cleared cookie header")
	}
	if clearCookies[0].MaxAge >= 0 {
		t.Fatalf("expected negative MaxAge for deletion, got %d", clearCookies[0].MaxAge)
	}
}

func TestGDPRConsentBeforeStoreCookie(t *testing.T) {
	ctx := context.Background()

	t.Run("Consent Accepted", func(t *testing.T) {
		p := lastloginmethod.New(
			lastloginmethod.WithBeforeStoreCookie(func(ctx context.Context, r *http.Request, method string) (bool, error) {
				return true, nil
			}),
		)

		req := httptest.NewRequest(http.MethodPost, "/api/auth/sign-in/email", nil)
		w := httptest.NewRecorder()

		method, err := p.SetLastLoginMethod(ctx, w, req, "", "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if method != "email" {
			t.Fatalf("expected method 'email', got %q", method)
		}

		cookies := w.Result().Cookies()
		if len(cookies) == 0 {
			t.Fatal("expected cookie to be stored when consent is accepted")
		}
	})

	t.Run("Consent Rejected", func(t *testing.T) {
		p := lastloginmethod.New(
			lastloginmethod.WithBeforeStoreCookie(func(ctx context.Context, r *http.Request, method string) (bool, error) {
				return false, nil
			}),
		)

		req := httptest.NewRequest(http.MethodPost, "/api/auth/sign-in/email", nil)
		w := httptest.NewRecorder()

		method, err := p.SetLastLoginMethod(ctx, w, req, "", "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if method != "email" {
			t.Fatalf("expected method 'email', got %q", method)
		}

		cookies := w.Result().Cookies()
		if len(cookies) > 0 {
			t.Fatal("expected no cookie when consent is rejected")
		}
	})
}

func TestDatabasePersistence(t *testing.T) {
	ctx := context.Background()
	store := memory.New()

	user, err := store.CreateUser(ctx, &dto.CreateUserParams{
		Name:  "Test User",
		Email: "test@example.com",
	})
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	p := lastloginmethod.NewWithRepository(store, lastloginmethod.WithStoreInDatabase(true))

	app, err := auth.New(config.WithPlugins(p))
	if err != nil {
		t.Fatalf("failed to initialize auth engine: %v", err)
	}
	_ = app

	req := httptest.NewRequest(http.MethodPost, "/api/auth/callback/github", nil)
	w := httptest.NewRecorder()

	method, err := p.SetLastLoginMethod(ctx, w, req, user.ID, "")
	if err != nil {
		t.Fatalf("failed to set last login method: %v", err)
	}
	if method != "github" {
		t.Fatalf("expected method 'github', got %q", method)
	}

	// Verify DB record update
	updatedUser, err := store.GetUserByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("failed to get updated user: %v", err)
	}
	if updatedUser.LastLoginMethod == nil || *updatedUser.LastLoginMethod != "github" {
		t.Fatalf("expected DB LastLoginMethod 'github', got %v", updatedUser.LastLoginMethod)
	}

	// Test GetLastLoginMethod retrieval
	dbMethod, err := p.GetLastLoginMethod(ctx, httptest.NewRequest(http.MethodGet, "/", nil), user.ID)
	if err != nil {
		t.Fatalf("failed to retrieve last login method: %v", err)
	}
	if dbMethod != "github" {
		t.Fatalf("expected retrieved method 'github', got %q", dbMethod)
	}
}

func TestInitErrorWithoutRepository(t *testing.T) {
	p := lastloginmethod.New(lastloginmethod.WithStoreInDatabase(true))
	_, err := auth.New(config.WithPlugins(p))
	if err == nil {
		t.Fatal("expected error when StoreInDatabase=true without repository, got nil")
	}
}

func TestTopLevelPluginConstructor(t *testing.T) {
	store := memory.New()
	p1 := plugins.LastLoginMethod()
	if p1.ID() != lastloginmethod.PluginID {
		t.Fatalf("expected plugin ID %q, got %q", lastloginmethod.PluginID, p1.ID())
	}

	p2 := plugins.LastLoginMethodWithRepository(store, lastloginmethod.WithStoreInDatabase(true))
	if p2.ID() != lastloginmethod.PluginID {
		t.Fatalf("expected plugin ID %q, got %q", lastloginmethod.PluginID, p2.ID())
	}
}

func TestClearLastLoginMethod(t *testing.T) {
	ctx := context.Background()
	p := lastloginmethod.New()

	w := httptest.NewRecorder()
	p.ClearLastLoginMethod(ctx, w)

	cookies := w.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("expected set-cookie header for deletion")
	}
	if cookies[0].MaxAge >= 0 {
		t.Fatalf("expected negative MaxAge for cookie deletion, got %d", cookies[0].MaxAge)
	}
}

func TestCustomCookieOptions(t *testing.T) {
	p := lastloginmethod.New(
		lastloginmethod.WithCookieName("my_custom_last_method"),
		lastloginmethod.WithMaxAge(7*24*time.Hour),
		lastloginmethod.WithCookieAttributes("example.com", "/auth", http.SameSiteStrictMode, true),
	)

	req := httptest.NewRequest(http.MethodPost, "/api/auth/sign-in/email", nil)
	w := httptest.NewRecorder()

	_, err := p.SetLastLoginMethod(context.Background(), w, req, "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cookies := w.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("expected set-cookie header")
	}
	c := cookies[0]
	if c.Name != "my_custom_last_method" {
		t.Fatalf("expected custom cookie name, got %q", c.Name)
	}
	if c.Domain != "example.com" {
		t.Fatalf("expected domain example.com, got %q", c.Domain)
	}
	if c.Path != "/auth" {
		t.Fatalf("expected path /auth, got %q", c.Path)
	}
	if c.SameSite != http.SameSiteStrictMode {
		t.Fatalf("expected Strict SameSite mode, got %v", c.SameSite)
	}
	if !c.Secure {
		t.Fatal("expected Secure=true")
	}
}

func TestMemoryRepository(t *testing.T) {
	ctx := context.Background()
	repo := lastloginmethod.NewMemoryRepository()

	// Test Get on missing user
	_, err := repo.GetLastLoginMethod(ctx, "nonexistent")
	if err == nil {
		t.Fatal("expected error getting nonexistent user method")
	}

	// Test Update and Get
	if err := repo.UpdateLastLoginMethod(ctx, "user_1", "passkey"); err != nil {
		t.Fatalf("failed to update method: %v", err)
	}

	method, err := repo.GetLastLoginMethod(ctx, "user_1")
	if err != nil {
		t.Fatalf("failed to get method: %v", err)
	}
	if method != "passkey" {
		t.Fatalf("expected method 'passkey', got %q", method)
	}
}
