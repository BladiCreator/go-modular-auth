package twofactor_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/BladiCreator/go-modular-auth/adapters/memory"
	"github.com/BladiCreator/go-modular-auth/plugins/twofactor"
)

func TestTwoFactorHTTPMiddleware(t *testing.T) {
	repo := memory.New()
	p := twofactor.New(repo)

	handler := p.Require2FA()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	t.Run("unverified 2FA returns 428", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/sensitive-action", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusPreconditionRequired {
			t.Fatalf("expected status 428, got %d", rec.Code)
		}
	})

	t.Run("verified 2FA via context passes", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/sensitive-action", nil)
		ctx := context.WithValue(req.Context(), twofactor.TwoFactorVerifiedContextKey, true)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req.WithContext(ctx))
		if rec.Code != http.StatusOK {
			t.Fatalf("expected status 200, got %d", rec.Code)
		}
	})

	t.Run("verified 2FA via header passes", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/sensitive-action", nil)
		req.Header.Set("X-2FA-Verified", "true")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected status 200, got %d", rec.Code)
		}
	})
}
