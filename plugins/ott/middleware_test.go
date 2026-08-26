package ott_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/BladiCreator/go-modular-auth/domain/entity"
	"github.com/BladiCreator/go-modular-auth/plugins/ott"
)

func TestOTTHTTPMiddleware(t *testing.T) {
	repo := newMockRepository()
	p := ott.New(repo)

	// Seed User & Session
	user := &entity.User{ID: "usr_123", Email: "gopher@golang.org"}
	repo.users[user.ID] = user

	sess := &entity.Session{
		ID:        "sess_123",
		UserID:    user.ID,
		Token:     "raw_session_token",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}
	repo.sessions[sess.Token] = sess

	genRes, err := p.GenerateToken(context.Background(), ott.GenerateTokenParams{
		SessionToken: sess.Token,
	})
	if err != nil {
		t.Fatalf("failed to generate OTT token: %v", err)
	}

	handler := p.Authenticate()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sessVal, ok := r.Context().Value(ott.SessionContextKey).(*entity.Session)
		if !ok || sessVal == nil || sessVal.ID != sess.ID {
			t.Errorf("expected resolved session with ID '%s'", sess.ID)
		}
		w.WriteHeader(http.StatusOK)
	}))

	t.Run("missing token returns 401", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/sso", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected status 401, got %d", rec.Code)
		}
	})

	t.Run("valid OTT header passes", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/sso", nil)
		req.Header.Set("X-OTT-Token", genRes.Token)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected status 200, got %d", rec.Code)
		}
	})
}
