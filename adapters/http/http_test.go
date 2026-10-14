package http_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	auth "github.com/BladiCreator/go-modular-auth"
	adaptermem "github.com/BladiCreator/go-modular-auth/adapter/memory"
	httpadapter "github.com/BladiCreator/go-modular-auth/adapters/http"
)

func setupAuth(t *testing.T) (*auth.Auth, string, string) {
	t.Helper()
	a, err := auth.New(auth.Config{Adapter: adaptermem.New()})
	if err != nil {
		t.Fatalf("failed to init auth: %v", err)
	}

	ctx := context.Background()
	res, err := a.SignUp(ctx, auth.SignUpInput{
		Email:    "user@example.com",
		Password: "Password123!",
	})
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	issued, err := a.CreateSession(ctx, res.User.ID, auth.SessionOptions{})
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	return a, res.User.ID, issued.Token
}

func TestHTTPAdapter_RequireAuth(t *testing.T) {
	a, expectedUserID, rawToken := setupAuth(t)

	var recordedUser string
	handler := httpadapter.RequireAuth(a)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := httpadapter.PrincipalFrom(r.Context())
		if ok {
			recordedUser = p.Subject
		}
		w.WriteHeader(http.StatusOK)
	}))

	// 1. Missing token -> 401
	req1 := httptest.NewRequest(http.MethodGet, "/protected", nil)
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 on missing token, got %d", rec1.Code)
	}

	// 2. Invalid token -> 401
	req2 := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req2.Header.Set("Authorization", "Bearer invalid-token")
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 on invalid token, got %d", rec2.Code)
	}

	// 3. Valid Bearer token -> 200 and context populated
	req3 := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req3.Header.Set("Authorization", "Bearer "+rawToken)
	rec3 := httptest.NewRecorder()
	handler.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusOK {
		t.Errorf("expected 200 on valid token, got %d", rec3.Code)
	}
	if recordedUser != expectedUserID {
		t.Errorf("expected user %s in context, got %s", expectedUserID, recordedUser)
	}

	// 4. Valid Cookie token -> 200
	req4 := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req4.AddCookie(&http.Cookie{Name: "auth_token", Value: rawToken})
	rec4 := httptest.NewRecorder()
	handler.ServeHTTP(rec4, req4)
	if rec4.Code != http.StatusOK {
		t.Errorf("expected 200 on valid cookie, got %d", rec4.Code)
	}
}

func TestHTTPAdapter_LenientAuthenticate(t *testing.T) {
	a, _, rawToken := setupAuth(t)

	var wasAuthed bool
	handler := httpadapter.Authenticate(a)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, wasAuthed = httpadapter.SessionFrom(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	// Without token -> passes, not authed
	req1 := httptest.NewRequest(http.MethodGet, "/public", nil)
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusOK || wasAuthed {
		t.Errorf("expected 200 unauthed, got code=%d authed=%v", rec1.Code, wasAuthed)
	}

	// With token -> passes, authed
	req2 := httptest.NewRequest(http.MethodGet, "/public", nil)
	req2.Header.Set("Authorization", "Bearer "+rawToken)
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK || !wasAuthed {
		t.Errorf("expected 200 authed, got code=%d authed=%v", rec2.Code, wasAuthed)
	}
}
