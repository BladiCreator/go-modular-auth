package repository_test

import (
	"context"
	"testing"
	"time"

	"github.com/BladiCreator/go-modular-auth/domain/dto"
	"github.com/BladiCreator/go-modular-auth/domain/repository"
)

var _ repository.SessionRepository = (*repository.MemorySessionRepository)(nil)

func TestMemorySessionRepository_CRUD(t *testing.T) {
	ctx := context.Background()
	repo := repository.NewMemorySessionRepository()

	// 1. CreateSession
	sess, err := repo.CreateSession(ctx, &dto.CreateSessionParams{
		UserID:    "user_123",
		Token:     "tok_abc",
		IPAddress: "127.0.0.1",
		UserAgent: "Mozilla/5.0",
		ExpiresAt: time.Now().Add(24 * time.Hour),
		CreatedAt: time.Now(),
	})
	if err != nil {
		t.Fatalf("unexpected error creating session: %v", err)
	}
	if sess.ID == "" || sess.Token != "tok_abc" || sess.UserID != "user_123" {
		t.Fatalf("unexpected session data: %+v", sess)
	}

	// 2. GetSessionByToken
	foundByToken, err := repo.GetSessionByToken(ctx, "tok_abc")
	if err != nil {
		t.Fatalf("unexpected error finding session by token: %v", err)
	}
	if foundByToken.ID != sess.ID {
		t.Fatalf("expected session ID %s, got %s", sess.ID, foundByToken.ID)
	}

	// 3. GetSessionByID
	foundByID, err := repo.GetSessionByID(ctx, sess.ID)
	if err != nil {
		t.Fatalf("unexpected error finding session by ID: %v", err)
	}
	if foundByID.Token != "tok_abc" {
		t.Fatalf("expected token tok_abc, got %s", foundByID.Token)
	}

	// 4. ListSessionsByUserID
	list, err := repo.ListSessionsByUserID(ctx, "user_123")
	if err != nil {
		t.Fatalf("unexpected error listing sessions: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 session, got %d", len(list))
	}

	// 5. UpdateSession
	sess.UserAgent = "UpdatedAgent"
	if err := repo.UpdateSession(ctx, sess); err != nil {
		t.Fatalf("unexpected error updating session: %v", err)
	}
	updated, _ := repo.GetSessionByID(ctx, sess.ID)
	if updated.UserAgent != "UpdatedAgent" {
		t.Fatalf("expected UpdatedAgent, got %s", updated.UserAgent)
	}

	// 6. SetActiveOrganization & SetActiveTeam
	orgID := "org_999"
	teamID := "team_456"
	if err := repo.SetActiveOrganization(ctx, sess.ID, orgID); err != nil {
		t.Fatalf("unexpected error setting active org: %v", err)
	}
	if err := repo.SetActiveTeam(ctx, sess.ID, teamID); err != nil {
		t.Fatalf("unexpected error setting active team: %v", err)
	}
	withOrg, _ := repo.GetSessionByID(ctx, sess.ID)
	if withOrg.ActiveOrganizationID == nil || *withOrg.ActiveOrganizationID != orgID {
		t.Fatalf("expected active org %s, got %v", orgID, withOrg.ActiveOrganizationID)
	}
	if withOrg.ActiveTeamID == nil || *withOrg.ActiveTeamID != teamID {
		t.Fatalf("expected active team %s, got %v", teamID, withOrg.ActiveTeamID)
	}

	// 7. SaveCustomSessionFields & GetCustomSessionFields
	customFields := map[string]any{"plan": "pro", "theme": "dark"}
	if err := repo.SaveCustomSessionFields(ctx, sess.ID, customFields); err != nil {
		t.Fatalf("unexpected error saving custom fields: %v", err)
	}
	savedFields, err := repo.GetCustomSessionFields(ctx, sess.ID)
	if err != nil {
		t.Fatalf("unexpected error getting custom fields: %v", err)
	}
	if savedFields["plan"] != "pro" || savedFields["theme"] != "dark" {
		t.Fatalf("expected custom fields pro/dark, got %+v", savedFields)
	}

	// 8. DeleteSession
	if err := repo.DeleteSession(ctx, "tok_abc"); err != nil {
		t.Fatalf("unexpected error deleting session: %v", err)
	}
	_, err = repo.GetSessionByToken(ctx, "tok_abc")
	if err != repository.ErrSessionNotFound {
		t.Fatalf("expected ErrSessionNotFound, got %v", err)
	}
}

func TestMemorySessionRepository_ExpiryAndBulkDelete(t *testing.T) {
	ctx := context.Background()
	repo := repository.NewMemorySessionRepository()

	// Create sessions
	_, _ = repo.CreateSession(ctx, &dto.CreateSessionParams{
		UserID:    "user_1",
		Token:     "tok_1",
		ExpiresAt: time.Now().Add(10 * time.Hour),
		CreatedAt: time.Now(),
	})
	_, _ = repo.CreateSession(ctx, &dto.CreateSessionParams{
		UserID:    "user_2",
		Token:     "tok_2",
		ExpiresAt: time.Now().Add(-1 * time.Hour), // Expired
		CreatedAt: time.Now(),
	})

	// DeleteExpiredSessions
	purged, err := repo.DeleteExpiredSessions(ctx)
	if err != nil {
		t.Fatalf("unexpected error purging expired: %v", err)
	}
	if purged != 1 {
		t.Fatalf("expected 1 purged session, got %d", purged)
	}

	// DeleteSessionsByUserID
	if err := repo.DeleteSessionsByUserID(ctx, "user_1"); err != nil {
		t.Fatalf("unexpected error deleting by user ID: %v", err)
	}
	list, _ := repo.ListSessionsByUserID(ctx, "user_1")
	if len(list) != 0 {
		t.Fatalf("expected 0 sessions after user deletion, got %d", len(list))
	}
}
