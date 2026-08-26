package jwt_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/BladiCreator/go-modular-auth/adapters/memory"
	"github.com/BladiCreator/go-modular-auth/plugins/jwt"
)

func TestJWTHTTPMiddleware(t *testing.T) {
	repo := memory.New()
	p := jwt.New(repo, jwt.WithSecret("test-secret-key-32-bytes-long!"))

	signRes, err := p.Sign(context.Background(), jwt.SignParams{
		Subject: "usr_gopher",
		Payload: map[string]any{"role": "admin"},
	})
	if err != nil {
		t.Fatalf("failed to sign test JWT: %v", err)
	}

	handler := p.Authenticate()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sub, ok := r.Context().Value(jwt.SubjectContextKey).(string)
		if !ok || sub != "usr_gopher" {
			t.Errorf("expected subject 'usr_gopher', got '%s'", sub)
		}
		w.WriteHeader(http.StatusOK)
	}))

	t.Run("missing authorization header returns 401", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/protected", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected status 401, got %d", rec.Code)
		}
	})

	t.Run("valid JWT authorization header passes", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/protected", nil)
		req.Header.Set("Authorization", "Bearer "+signRes.Token)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected status 200, got %d", rec.Code)
		}
	})

	t.Run("invalid JWT token returns 401", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/protected", nil)
		req.Header.Set("Authorization", "Bearer invalid.jwt.token")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected status 401, got %d", rec.Code)
		}
	})
}
