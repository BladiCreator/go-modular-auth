package dto_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/BladiCreator/go-modular-auth/domain/dto"
	"github.com/BladiCreator/go-modular-auth/domain/entity"
)

func TestAuthResult_Completed(t *testing.T) {
	now := time.Now()
	session := &entity.Session{
		ID:        "sess_123",
		UserID:    "user_123",
		Token:     "token_abc",
		ExpiresAt: now.Add(24 * time.Hour),
	}
	user := &entity.User{
		ID:    "user_123",
		Email: "test@example.com",
		Name:  "Test User",
	}
	sessionData := &dto.SessionData{
		Session: session,
		User:    user,
	}

	res := dto.NewAuthResultCompleted(sessionData)

	if !res.IsComplete() {
		t.Fatalf("expected IsComplete() to be true")
	}
	if res.RequiresChallenge() {
		t.Fatalf("expected RequiresChallenge() to be false")
	}
	if res.SessionData() == nil || res.SessionData().Session.ID != "sess_123" {
		t.Fatalf("expected valid SessionData()")
	}
	if res.Challenge() != nil {
		t.Fatalf("expected Challenge() to be nil")
	}
	if res.Session == nil || res.Session.Token != "token_abc" {
		t.Fatalf("expected Session field to be populated")
	}
	if res.User == nil || res.User.Email != "test@example.com" {
		t.Fatalf("expected User field to be populated")
	}

	// Test JSON Marshalling
	data, err := json.Marshal(res)
	if err != nil {
		t.Fatalf("failed to marshal AuthResult: %v", err)
	}

	var unmarshaled dto.AuthResult
	if err := json.Unmarshal(data, &unmarshaled); err != nil {
		t.Fatalf("failed to unmarshal AuthResult: %v", err)
	}

	if unmarshaled.Status != dto.AuthStatusComplete {
		t.Errorf("expected status %s, got %s", dto.AuthStatusComplete, unmarshaled.Status)
	}
	if unmarshaled.Session == nil || unmarshaled.Session.ID != "sess_123" {
		t.Errorf("expected unmarshaled session ID sess_123")
	}
	if unmarshaled.SessionData() == nil || unmarshaled.SessionData().User.Email != "test@example.com" {
		t.Errorf("expected session data helper to reconstruct user from unmarshaled fields")
	}
}

func TestAuthResult_Challenge(t *testing.T) {
	now := time.Now()
	challenge := &dto.AuthChallenge{
		ChallengeID:    "ch_abc123",
		UserID:         "user_123",
		FactorRequired: "totp",
		TempToken:      "temp_token_xyz",
		ExpiresAt:      now.Add(5 * time.Minute),
		CreatedAt:      now,
	}

	res := dto.NewAuthResultChallenge(challenge)

	if res.IsComplete() {
		t.Fatalf("expected IsComplete() to be false")
	}
	if !res.RequiresChallenge() {
		t.Fatalf("expected RequiresChallenge() to be true")
	}
	if res.SessionData() != nil {
		t.Fatalf("expected SessionData() to be nil")
	}
	if res.Challenge() == nil || res.Challenge().TempToken != "temp_token_xyz" {
		t.Fatalf("expected valid Challenge()")
	}
	if res.ChallengeData() == nil || res.ChallengeData().ChallengeID != "ch_abc123" {
		t.Fatalf("expected ChallengeData() alias to work")
	}

	// Test JSON Marshalling
	data, err := json.Marshal(res)
	if err != nil {
		t.Fatalf("failed to marshal AuthResult: %v", err)
	}

	var unmarshaled dto.AuthResult
	if err := json.Unmarshal(data, &unmarshaled); err != nil {
		t.Fatalf("failed to unmarshal AuthResult: %v", err)
	}

	if unmarshaled.Status != dto.AuthStatusMFARequired {
		t.Errorf("expected status %s, got %s", dto.AuthStatusMFARequired, unmarshaled.Status)
	}
	if unmarshaled.Challenge() == nil || unmarshaled.Challenge().TempToken != "temp_token_xyz" {
		t.Errorf("expected unmarshaled challenge temp token temp_token_xyz")
	}
	if !unmarshaled.RequiresChallenge() {
		t.Errorf("expected RequiresChallenge() to be true on unmarshaled challenge result")
	}
}

func TestAuthResult_NilSafety(t *testing.T) {
	var nilRes *dto.AuthResult
	if nilRes.IsComplete() {
		t.Errorf("nil AuthResult should not be complete")
	}
	if nilRes.RequiresChallenge() {
		t.Errorf("nil AuthResult should not require challenge")
	}
	if nilRes.SessionData() != nil {
		t.Errorf("nil AuthResult SessionData should be nil")
	}
	if nilRes.Challenge() != nil {
		t.Errorf("nil AuthResult Challenge should be nil")
	}

	emptyCompleted := dto.NewAuthResultCompleted(nil)
	if emptyCompleted.IsComplete() {
		t.Errorf("empty completed AuthResult should not be complete")
	}

	emptyChallenge := dto.NewAuthResultChallenge(nil)
	if emptyChallenge.RequiresChallenge() {
		t.Errorf("empty challenge AuthResult should not require challenge")
	}
}
