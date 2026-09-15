package httpauth

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestExtractToken_CascadePriority(t *testing.T) {
	t.Run("cookie has priority over header by default", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/protected", nil)
		req.AddCookie(&http.Cookie{Name: "auth_session", Value: "cookie_token_111"})
		req.Header.Set("Authorization", "Bearer header_token_222")

		token, err := ExtractToken(req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if token != "cookie_token_111" {
			t.Errorf("expected cookie token %q, got %q", "cookie_token_111", token)
		}
	})

	t.Run("fallback to authorization bearer header when cookie missing", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/protected", nil)
		req.Header.Set("Authorization", "Bearer header_token_222")

		token, err := ExtractToken(req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if token != "header_token_222" {
			t.Errorf("expected header token %q, got %q", "header_token_222", token)
		}
	})

	t.Run("case-insensitive bearer prefix", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/protected", nil)
		req.Header.Set("Authorization", "bearer lowercase_token_333")

		token, err := ExtractToken(req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if token != "lowercase_token_333" {
			t.Errorf("expected header token %q, got %q", "lowercase_token_333", token)
		}
	})

	t.Run("fallback to query parameter when configured", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/protected?token=query_token_444", nil)

		token, err := ExtractToken(req, WithExtractQueryParam("token"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if token != "query_token_444" {
			t.Errorf("expected query token %q, got %q", "query_token_444", token)
		}
	})

	t.Run("returns ErrTokenNotFound when no token present", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/protected", nil)

		_, err := ExtractToken(req)
		if !errors.Is(err, ErrTokenNotFound) {
			t.Errorf("expected ErrTokenNotFound, got %v", err)
		}
	})
}

func TestExtractToken_CustomSourceOrdering(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.AddCookie(&http.Cookie{Name: "auth_session", Value: "cookie_val"})
	req.Header.Set("Authorization", "Bearer header_val")

	token, err := ExtractToken(req, WithSources(SourceHeader, SourceCookie))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != "header_val" {
		t.Errorf("expected header_val due to custom order, got %q", token)
	}
}

func TestExtractToken_MalformedBearer(t *testing.T) {
	t.Run("empty bearer token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/protected", nil)
		req.Header.Set("Authorization", "Bearer ")

		_, err := ExtractToken(req)
		if !errors.Is(err, ErrTokenNotFound) {
			t.Errorf("expected ErrTokenNotFound for empty bearer, got %v", err)
		}
	})

	t.Run("non-bearer scheme skipped and falls back to query", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/protected?token=fallback_query", nil)
		req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")

		token, err := ExtractToken(req, WithExtractQueryParam("token"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if token != "fallback_query" {
			t.Errorf("expected fallback_query, got %q", token)
		}
	})
}

func TestExtractToken_CustomHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("X-API-Key", "custom_key_999")

	token, err := ExtractToken(req, WithExtractHeader("X-API-Key", ""))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != "custom_key_999" {
		t.Errorf("expected custom_key_999, got %q", token)
	}
}

func TestExtractToken_Options(t *testing.T) {
	t.Run("custom cookie name with WithExtractCookie", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(&http.Cookie{Name: "my_custom_sess", Value: "custom_cookie_val"})

		token, err := ExtractToken(req, WithExtractCookie("my_custom_sess"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if token != "custom_cookie_val" {
			t.Errorf("expected custom_cookie_val, got %q", token)
		}
	})

	t.Run("explicit WithExtractBearer", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer bearer_token_explicit")

		token, err := ExtractToken(req, WithExtractBearer())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if token != "bearer_token_explicit" {
			t.Errorf("expected bearer_token_explicit, got %q", token)
		}
	})

	t.Run("redundant WithExtractQueryParam does not duplicate source", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/?token=val123", nil)
		token, err := ExtractToken(req, WithExtractQueryParam("token"), WithExtractQueryParam("token"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if token != "val123" {
			t.Errorf("expected val123, got %q", token)
		}
	})
}

func TestExtractToken_NilRequest(t *testing.T) {
	_, err := ExtractToken(nil)
	if !errors.Is(err, ErrNilRequest) {
		t.Errorf("expected ErrNilRequest, got %v", err)
	}
}
