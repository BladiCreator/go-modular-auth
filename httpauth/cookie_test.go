package httpauth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSetSessionCookie_DefaultConfig(t *testing.T) {
	rec := httptest.NewRecorder()
	token := "sess_token_xyz_123"
	expires := time.Now().Add(24 * time.Hour)

	SetSessionCookie(rec, token, expires)

	res := rec.Result()
	defer res.Body.Close()

	cookies := res.Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}

	cookie := cookies[0]
	if cookie.Name != DefaultSessionCookieName {
		t.Errorf("expected cookie name %q, got %q", DefaultSessionCookieName, cookie.Name)
	}
	if cookie.Value != token {
		t.Errorf("expected cookie value %q, got %q", token, cookie.Value)
	}
	if cookie.Path != "/" {
		t.Errorf("expected path %q, got %q", "/", cookie.Path)
	}
	if !cookie.HttpOnly {
		t.Errorf("expected HttpOnly to be true")
	}
	if !cookie.Secure {
		t.Errorf("expected Secure to be true")
	}
	if cookie.SameSite != http.SameSiteLaxMode {
		t.Errorf("expected SameSite Lax, got %v", cookie.SameSite)
	}
	if cookie.MaxAge <= 0 || cookie.MaxAge > 86400 {
		t.Errorf("expected MaxAge around 86400, got %d", cookie.MaxAge)
	}
}

func TestSetSessionCookie_CustomOptions(t *testing.T) {
	rec := httptest.NewRecorder()
	token := "custom_token_abc"
	expires := time.Now().Add(2 * time.Hour)

	SetSessionCookie(rec, token, expires,
		WithCookieName("app_session"),
		WithPath("/auth"),
		WithDomain("example.com"),
		WithSecure(false),
		WithHTTPOnly(false),
		WithSameSite(http.SameSiteStrictMode),
		WithPartitioned(true),
	)

	res := rec.Result()
	defer res.Body.Close()

	cookies := res.Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}

	cookie := cookies[0]
	if cookie.Name != "app_session" {
		t.Errorf("expected name %q, got %q", "app_session", cookie.Name)
	}
	if cookie.Value != token {
		t.Errorf("expected value %q, got %q", token, cookie.Value)
	}
	if cookie.Path != "/auth" {
		t.Errorf("expected path %q, got %q", "/auth", cookie.Path)
	}
	if cookie.Domain != "example.com" {
		t.Errorf("expected domain %q, got %q", "example.com", cookie.Domain)
	}
	if cookie.Secure {
		t.Errorf("expected Secure to be false")
	}
	if cookie.HttpOnly {
		t.Errorf("expected HttpOnly to be false")
	}
	if cookie.SameSite != http.SameSiteStrictMode {
		t.Errorf("expected SameSite Strict, got %v", cookie.SameSite)
	}
	if !cookie.Partitioned {
		t.Errorf("expected Partitioned to be true")
	}
}

func TestSetSessionCookie_ZeroExpiration(t *testing.T) {
	rec := httptest.NewRecorder()
	SetSessionCookie(rec, "token_zero", time.Time{})

	res := rec.Result()
	defer res.Body.Close()

	cookies := res.Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}
	if cookies[0].MaxAge != 0 {
		t.Errorf("expected MaxAge 0 for zero expiration, got %d", cookies[0].MaxAge)
	}
}

func TestSetSessionCookie_PastExpiration(t *testing.T) {
	rec := httptest.NewRecorder()
	SetSessionCookie(rec, "token_past", time.Now().Add(-10*time.Minute))

	res := rec.Result()
	defer res.Body.Close()

	cookies := res.Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}
	if cookies[0].MaxAge != -1 {
		t.Errorf("expected MaxAge -1 for past expiration, got %d", cookies[0].MaxAge)
	}
}

func TestClearSessionCookie(t *testing.T) {
	rec := httptest.NewRecorder()

	ClearSessionCookie(rec,
		WithCookieName("auth_session"),
		WithPath("/"),
		WithDomain("sub.example.com"),
	)

	res := rec.Result()
	defer res.Body.Close()

	cookies := res.Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}

	cookie := cookies[0]
	if cookie.Name != "auth_session" {
		t.Errorf("expected name auth_session, got %q", cookie.Name)
	}
	if cookie.Value != "" {
		t.Errorf("expected empty value, got %q", cookie.Value)
	}
	if cookie.MaxAge != -1 {
		t.Errorf("expected MaxAge -1, got %d", cookie.MaxAge)
	}
	if !cookie.Expires.Before(time.Now()) {
		t.Errorf("expected cookie.Expires to be in the past")
	}
	if cookie.Domain != "sub.example.com" {
		t.Errorf("expected domain sub.example.com, got %q", cookie.Domain)
	}
}

func TestCookie_NilResponseWriter(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("did not expect panic on nil ResponseWriter: %v", r)
		}
	}()

	SetSessionCookie(nil, "token", time.Now())
	ClearSessionCookie(nil)
}
