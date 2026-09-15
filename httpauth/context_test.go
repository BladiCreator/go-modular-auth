package httpauth

import (
	"context"
	"testing"
	"time"

	"github.com/BladiCreator/go-modular-auth/domain/dto"
	"github.com/BladiCreator/go-modular-auth/domain/entity"
)

func TestSessionContext(t *testing.T) {
	session := &entity.Session{
		ID:        "sess_001",
		UserID:    "user_123",
		Token:     "raw_token_xyz",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	ctx := WithSession(context.Background(), session)

	retrieved, ok := SessionFromContext(ctx)
	if !ok {
		t.Fatalf("expected SessionFromContext to return true")
	}
	if retrieved.ID != session.ID || retrieved.Token != session.Token {
		t.Errorf("retrieved session does not match original: %+v", retrieved)
	}

	// Empty context returns false
	_, ok = SessionFromContext(context.Background())
	if ok {
		t.Errorf("expected SessionFromContext to return false for empty context")
	}

	// Nil context handled safely
	ctxWithNil := WithSession(nil, session)
	if ctxWithNil == nil {
		t.Fatalf("expected non-nil context from WithSession(nil, ...)")
	}
	retrievedNil, okNil := SessionFromContext(nil)
	if okNil || retrievedNil != nil {
		t.Errorf("expected (nil, false) for SessionFromContext(nil)")
	}
}

func TestUserContext(t *testing.T) {
	user := &entity.User{
		ID:    "user_456",
		Email: "alex@example.com",
		Name:  "Alex Developer",
	}

	ctx := WithUser(context.Background(), user)

	retrieved, ok := UserFromContext(ctx)
	if !ok {
		t.Fatalf("expected UserFromContext to return true")
	}
	if retrieved.ID != user.ID || retrieved.Email != user.Email {
		t.Errorf("retrieved user does not match original: %+v", retrieved)
	}

	// Empty context returns false
	_, ok = UserFromContext(context.Background())
	if ok {
		t.Errorf("expected UserFromContext to return false for empty context")
	}

	// Nil context handled safely
	ctxWithNil := WithUser(nil, user)
	if ctxWithNil == nil {
		t.Fatalf("expected non-nil context from WithUser(nil, ...)")
	}
	retrievedNil, okNil := UserFromContext(nil)
	if okNil || retrievedNil != nil {
		t.Errorf("expected (nil, false) for UserFromContext(nil)")
	}
}

func TestSessionDataContext(t *testing.T) {
	session := &entity.Session{
		ID:     "sess_789",
		UserID: "user_789",
	}
	user := &entity.User{
		ID:    "user_789",
		Email: "jordan@example.com",
	}

	data := &dto.SessionData{
		Session: session,
		User:    user,
	}

	ctx := WithSessionData(context.Background(), data)

	// Can retrieve combined SessionData
	retrievedData, ok := SessionDataFromContext(ctx)
	if !ok {
		t.Fatalf("expected SessionDataFromContext to return true")
	}
	if retrievedData.Session.ID != session.ID {
		t.Errorf("expected session ID %q, got %q", session.ID, retrievedData.Session.ID)
	}
	if retrievedData.User.Email != user.Email {
		t.Errorf("expected user email %q, got %q", user.Email, retrievedData.User.Email)
	}

	// Can also retrieve individual Session and User
	retrievedSess, okSess := SessionFromContext(ctx)
	if !okSess || retrievedSess.ID != session.ID {
		t.Errorf("expected individual SessionFromContext to find session")
	}

	retrievedUser, okUser := UserFromContext(ctx)
	if !okUser || retrievedUser.Email != user.Email {
		t.Errorf("expected individual UserFromContext to find user")
	}

	// Empty context returns false
	_, okEmpty := SessionDataFromContext(context.Background())
	if okEmpty {
		t.Errorf("expected SessionDataFromContext to return false on empty context")
	}

	// Partial SessionData
	onlySessData := &dto.SessionData{Session: session}
	ctxOnlySess := WithSessionData(context.Background(), onlySessData)
	if s, ok := SessionFromContext(ctxOnlySess); !ok || s.ID != session.ID {
		t.Errorf("expected session to be extracted from onlySessData")
	}
	if _, ok := UserFromContext(ctxOnlySess); ok {
		t.Errorf("expected user not to be present in ctxOnlySess")
	}

	onlyUserData := &dto.SessionData{User: user}
	ctxOnlyUser := WithSessionData(context.Background(), onlyUserData)
	if u, ok := UserFromContext(ctxOnlyUser); !ok || u.Email != user.Email {
		t.Errorf("expected user to be extracted from onlyUserData")
	}
	if _, ok := SessionFromContext(ctxOnlyUser); ok {
		t.Errorf("expected session not to be present in ctxOnlyUser")
	}
}

func TestContextKey_String(t *testing.T) {
	key := &contextKey{name: "test_key"}
	expected := "httpauth context key: test_key"
	if key.String() != expected {
		t.Errorf("expected %q, got %q", expected, key.String())
	}
}
