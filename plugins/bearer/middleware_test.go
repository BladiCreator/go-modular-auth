package bearer_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/BladiCreator/go-modular-auth/adapters/memory"
	"github.com/BladiCreator/go-modular-auth/domain/dto"
	"github.com/BladiCreator/go-modular-auth/domain/entity"
	"github.com/BladiCreator/go-modular-auth/plugins/bearer"
)

func TestHTTPMiddleware(t *testing.T) {
	repo := memory.New()
	p := bearer.New(repo, bearer.WithSecret("test-secret-key"))

	// Create test session
	sess, err := repo.CreateSession(context.Background(), &dto.CreateSessionParams{
		UserID:    "usr_456",
		Token:     "raw_session_token",
		ExpiresAt: time.Now().Add(1 * time.Hour),
		CreatedAt: time.Now(),
	})
	if err != nil {
		t.Fatalf("failed to create test session: %v", err)
	}

	// Create signed token
	signedToken := bearer.SignToken("raw_session_token", "test-secret-key")

	handler := p.Authenticate()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rawVal, ok := r.Context().Value(bearer.RawTokenContextKey).(string)
		if !ok || rawVal != "raw_session_token" {
			t.Errorf("expected raw token 'raw_session_token', got '%s'", rawVal)
		}
		sessionVal, ok := r.Context().Value(bearer.SessionContextKey).(*entity.Session)
		if !ok || sessionVal == nil || sessionVal.ID != sess.ID {
			t.Errorf("expected resolved session with ID '%s'", sess.ID)
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

	t.Run("valid authorization header passes middleware", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/protected", nil)
		req.Header.Set("Authorization", "Bearer "+signedToken)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected status 200, got %d", rec.Code)
		}
	})

	t.Run("invalid signature returns 401", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/protected", nil)
		req.Header.Set("Authorization", "Bearer invalid_signature_token.bad")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected status 401, got %d", rec.Code)
		}
	})
}
