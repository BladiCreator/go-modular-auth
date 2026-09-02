package auth_test

import (
	"context"
	"encoding/hex"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/BladiCreator/go-modular-auth/adapters/memory"
	"github.com/BladiCreator/go-modular-auth/auth"
	"github.com/BladiCreator/go-modular-auth/config"
	"github.com/BladiCreator/go-modular-auth/domain/dto"
	"github.com/BladiCreator/go-modular-auth/domain/repository"
	"github.com/BladiCreator/go-modular-auth/plugin"
	"github.com/BladiCreator/go-modular-auth/plugins/multisession"
)

func setupAuth(t *testing.T, opts ...config.Option) (*auth.Auth, *memory.Store) {
	t.Helper()
	store := memory.New()
	defaultOpts := []config.Option{
		config.WithSessionRepository(store),
	}
	defaultOpts = append(defaultOpts, opts...)

	a, err := auth.New(defaultOpts...)
	if err != nil {
		t.Fatalf("setupAuth: failed to create auth engine: %v", err)
	}
	return a, store
}

func TestCreateSession_DefaultDuration(t *testing.T) {
	ctx := context.Background()
	a, _ := setupAuth(t)

	now := time.Now()
	sess, err := a.CreateSession(ctx, "user-123")
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if sess.ID == "" {
		t.Error("expected non-empty session ID")
	}
	if sess.UserID != "user-123" {
		t.Errorf("expected userID 'user-123', got %s", sess.UserID)
	}
	if len(sess.Token) != 64 {
		t.Errorf("expected 64-char hex token (32 bytes entropy), got %d chars: %s", len(sess.Token), sess.Token)
	}

	expectedExpiry := now.Add(24 * time.Hour)
	diff := sess.ExpiresAt.Sub(expectedExpiry)
	if diff < -5*time.Second || diff > 5*time.Second {
		t.Errorf("expected expiresAt around 24h from now, diff: %v", diff)
	}
}

func TestCreateSession_WithDuration(t *testing.T) {
	ctx := context.Background()
	a, _ := setupAuth(t)

	customDur := 3 * time.Hour
	now := time.Now()
	sess, err := a.CreateSession(ctx, "user-custom-dur", auth.WithDuration(customDur))
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	expectedExpiry := now.Add(customDur)
	diff := sess.ExpiresAt.Sub(expectedExpiry)
	if diff < -5*time.Second || diff > 5*time.Second {
		t.Errorf("expected expiresAt around 3h from now, diff: %v", diff)
	}
}

func TestCreateSession_WithRememberMe(t *testing.T) {
	ctx := context.Background()
	a, _ := setupAuth(t)

	now := time.Now()
	sess, err := a.CreateSession(ctx, "user-remember", auth.WithRememberMe(true))
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	expectedExpiry := now.Add(30 * 24 * time.Hour)
	diff := sess.ExpiresAt.Sub(expectedExpiry)
	if diff < -5*time.Second || diff > 5*time.Second {
		t.Errorf("expected expiresAt around 30 days from now, diff: %v", diff)
	}
}

func TestCreateSession_ClientMetadata(t *testing.T) {
	ctx := context.Background()
	a, store := setupAuth(t)

	ip := "192.168.1.15"
	ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
	devID := "device-desktop-01"

	sess, err := a.CreateSession(ctx, "user-meta",
		auth.WithIPAddress(ip),
		auth.WithUserAgent(ua),
		auth.WithDeviceID(devID),
	)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if sess.IPAddress != ip {
		t.Errorf("expected IPAddress %s, got %s", ip, sess.IPAddress)
	}
	if sess.UserAgent != ua {
		t.Errorf("expected UserAgent %s, got %s", ua, sess.UserAgent)
	}
	if sess.DeviceID == nil || *sess.DeviceID != devID {
		t.Errorf("expected DeviceID %s, got %v", devID, sess.DeviceID)
	}

	stored, err := store.GetSessionByToken(ctx, sess.Token)
	if err != nil {
		t.Fatalf("failed to retrieve stored session: %v", err)
	}
	if stored.IPAddress != ip || stored.UserAgent != ua {
		t.Errorf("stored metadata mismatch: ip=%s ua=%s", stored.IPAddress, stored.UserAgent)
	}
}

func TestCreateSession_ExtraMetadata(t *testing.T) {
	ctx := context.Background()
	a, _ := setupAuth(t)

	sess, err := a.CreateSession(ctx, "user-extra",
		auth.WithExtra("role", "admin"),
		auth.WithExtraMap(map[string]any{
			"tenant": "enterprise-corp",
			"tier":   "platinum",
		}),
	)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if sess.Extra == nil {
		t.Fatal("expected non-nil sess.Extra")
	}
	if sess.Extra["role"] != "admin" {
		t.Errorf("expected role 'admin', got %v", sess.Extra["role"])
	}
	if sess.Extra["tenant"] != "enterprise-corp" {
		t.Errorf("expected tenant 'enterprise-corp', got %v", sess.Extra["tenant"])
	}
	if sess.Extra["tier"] != "platinum" {
		t.Errorf("expected tier 'platinum', got %v", sess.Extra["tier"])
	}
}

func TestCreateSession_CryptographicEntropy(t *testing.T) {
	ctx := context.Background()
	a, _ := setupAuth(t)

	seen := make(map[string]bool)
	const count = 50

	for i := 0; i < count; i++ {
		sess, err := a.CreateSession(ctx, "user-entropy")
		if err != nil {
			t.Fatalf("failed to create session on iteration %d: %v", i, err)
		}

		if len(sess.Token) != 64 {
			t.Fatalf("expected 64 hex characters, got %d", len(sess.Token))
		}

		decoded, err := hex.DecodeString(sess.Token)
		if err != nil {
			t.Fatalf("token is not valid hex: %v", err)
		}
		if len(decoded) != 32 {
			t.Fatalf("expected 32 decoded bytes, got %d", len(decoded))
		}

		if seen[sess.Token] {
			t.Fatalf("token collision detected: %s", sess.Token)
		}
		seen[sess.Token] = true
	}
}

func TestValidateSession_Success(t *testing.T) {
	ctx := context.Background()
	a, store := setupAuth(t)

	user, err := store.CreateUser(ctx, &dto.CreateUserParams{
		Name:  "Ada Lovelace",
		Email: "ada@example.com",
		Role:  "pioneer",
	})
	if err != nil {
		t.Fatalf("failed to seed user: %v", err)
	}

	sess, err := a.CreateSession(ctx, user.ID,
		auth.WithIPAddress("10.0.0.1"),
		auth.WithExtra("scope", "read:write"),
	)
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	sData, err := a.ValidateSession(ctx, sess.Token)
	if err != nil {
		t.Fatalf("ValidateSession failed: %v", err)
	}

	if sData.Session == nil {
		t.Fatal("expected non-nil Session in SessionData")
	}
	if sData.Session.ID != sess.ID {
		t.Errorf("expected session ID %s, got %s", sess.ID, sData.Session.ID)
	}

	if sData.User == nil {
		t.Fatal("expected non-nil User in SessionData")
	}
	if sData.User.ID != user.ID || sData.User.Email != "ada@example.com" {
		t.Errorf("user resolution mismatch: ID=%s Email=%s", sData.User.ID, sData.User.Email)
	}

	if sData.Extra == nil || sData.Extra["scope"] != "read:write" {
		t.Errorf("expected extra scope in SessionData, got %v", sData.Extra)
	}
}

func TestValidateSession_Expired(t *testing.T) {
	ctx := context.Background()
	a, _ := setupAuth(t)

	sess, err := a.CreateSession(ctx, "user-expired", auth.WithDuration(-1*time.Hour))
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	_, err = a.ValidateSession(ctx, sess.Token)
	if !errors.Is(err, repository.ErrSessionExpired) {
		t.Errorf("expected ErrSessionExpired, got %v", err)
	}
}

func TestValidateSession_NotFoundAndInvalid(t *testing.T) {
	ctx := context.Background()
	a, _ := setupAuth(t)

	_, err := a.ValidateSession(ctx, "")
	if !errors.Is(err, repository.ErrInvalidSessionToken) {
		t.Errorf("expected ErrInvalidSessionToken on empty token, got %v", err)
	}

	_, err = a.ValidateSession(ctx, "non-existent-token-12345678901234567890123456789012")
	if !errors.Is(err, repository.ErrSessionNotFound) {
		t.Errorf("expected ErrSessionNotFound on missing token, got %v", err)
	}
}

func TestRevokeSession(t *testing.T) {
	ctx := context.Background()
	a, _ := setupAuth(t)

	sess, err := a.CreateSession(ctx, "user-revoke")
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	sData, err := a.ValidateSession(ctx, sess.Token)
	if err != nil || sData == nil {
		t.Fatalf("session should be valid before revocation: %v", err)
	}

	if err := a.RevokeSession(ctx, sess.Token); err != nil {
		t.Fatalf("RevokeSession failed: %v", err)
	}

	_, err = a.ValidateSession(ctx, sess.Token)
	if !errors.Is(err, repository.ErrSessionNotFound) {
		t.Errorf("expected ErrSessionNotFound after revocation, got %v", err)
	}

	if err := a.RevokeSession(ctx, ""); !errors.Is(err, repository.ErrInvalidSessionToken) {
		t.Errorf("expected ErrInvalidSessionToken on empty token, got %v", err)
	}
}

func TestSession_NoRepositoryConfigured(t *testing.T) {
	ctx := context.Background()
	a, err := auth.New()
	if err != nil {
		t.Fatalf("failed to create auth: %v", err)
	}

	if a.SessionManager() != nil {
		t.Error("expected nil SessionManager when no repository configured")
	}

	if _, err := a.CreateSession(ctx, "u1"); !errors.Is(err, auth.ErrSessionRepositoryRequired) {
		t.Errorf("expected ErrSessionRepositoryRequired on CreateSession, got %v", err)
	}

	if _, err := a.ValidateSession(ctx, "tok"); !errors.Is(err, auth.ErrSessionRepositoryRequired) {
		t.Errorf("expected ErrSessionRepositoryRequired on ValidateSession, got %v", err)
	}

	if err := a.RevokeSession(ctx, "tok"); !errors.Is(err, auth.ErrSessionRepositoryRequired) {
		t.Errorf("expected ErrSessionRepositoryRequired on RevokeSession, got %v", err)
	}
}

func TestSessionEvents_CreatedAndRevoked(t *testing.T) {
	ctx := context.Background()
	a, _ := setupAuth(t)

	var (
		createdWg sync.WaitGroup
		revokedWg sync.WaitGroup
		gotCreated *auth.SessionCreatedPayload
		gotRevoked *auth.SessionRevokedPayload
	)

	createdWg.Add(1)
	_ = a.Events().Subscribe(auth.EventSessionCreated, func(c context.Context, p *auth.SessionCreatedPayload) {
		gotCreated = p
		createdWg.Done()
	})

	revokedWg.Add(1)
	_ = a.Events().Subscribe(auth.EventSessionRevoked, func(c context.Context, p *auth.SessionRevokedPayload) {
		gotRevoked = p
		revokedWg.Done()
	})

	sess, err := a.CreateSession(ctx, "user-events", auth.WithExtra("tag", "test-event"))
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}
	createdWg.Wait()

	if gotCreated == nil || gotCreated.Session == nil || gotCreated.Session.ID != sess.ID {
		t.Errorf("EventSessionCreated payload mismatch: %v", gotCreated)
	}
	if gotCreated.Extra["tag"] != "test-event" {
		t.Errorf("expected extra tag 'test-event', got %v", gotCreated.Extra)
	}

	if err := a.RevokeSession(ctx, sess.Token); err != nil {
		t.Fatalf("failed to revoke session: %v", err)
	}
	revokedWg.Wait()

	if gotRevoked == nil || gotRevoked.Token != sess.Token || gotRevoked.SessionID != sess.ID {
		t.Errorf("EventSessionRevoked payload mismatch: %v", gotRevoked)
	}
	if gotRevoked.UserID != "user-events" {
		t.Errorf("expected revoked userID 'user-events', got %s", gotRevoked.UserID)
	}
}

// testPlugin simulates a modular plugin interacting with ctx.Session()
type testPlugin struct {
	ctx *plugin.Context
}

func (p *testPlugin) ID() string { return "test-session-plugin" }
func (p *testPlugin) Init(ctx *plugin.Context) error {
	p.ctx = ctx
	return nil
}

func TestPluginContext_SessionManagerInjection(t *testing.T) {
	tp := &testPlugin{}
	store := memory.New()

	a, err := auth.New(
		config.WithSessionRepository(store),
		config.WithPlugins(tp),
	)
	if err != nil {
		t.Fatalf("failed to initialize auth with plugin: %v", err)
	}

	if tp.ctx == nil {
		t.Fatal("plugin context was not set")
	}

	sm := tp.ctx.Session()
	if sm == nil {
		t.Fatal("expected non-nil SessionManager in plugin context")
	}

	ctx := context.Background()
	sess, err := sm.CreateSession(ctx, "plugin-user", plugin.WithDuration(1*time.Hour))
	if err != nil {
		t.Fatalf("plugin failed to create session via context: %v", err)
	}

	sData, err := a.ValidateSession(ctx, sess.Token)
	if err != nil || sData.Session.ID != sess.ID {
		t.Fatalf("session created by plugin context validation failed: %v", err)
	}
}

func TestPluginCoordination_MultiSession(t *testing.T) {
	store := memory.New()
	multiPlugin := multisession.New(store)

	a, err := auth.New(
		config.WithSessionRepository(store),
		config.WithPlugins(multiPlugin),
	)
	if err != nil {
		t.Fatalf("failed to initialize auth with multisession: %v", err)
	}

	var (
		wg sync.WaitGroup
		capturedSessionID string
	)
	wg.Add(1)

	_ = a.Events().Subscribe(multisession.EventSessionCreated, func(payload *multisession.SessionCreatedEventPayload) {
		if payload != nil && payload.Session != nil {
			capturedSessionID = payload.Session.ID
		}
		wg.Done()
	})

	ctx := context.Background()
	sess, err := a.CreateSession(ctx, "user-multi-coord")
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	wg.Wait()

	if capturedSessionID != sess.ID {
		t.Errorf("multisession did not automatically receive created session: expected %s, got %s", sess.ID, capturedSessionID)
	}
}

func TestAuxiliaryMethods(t *testing.T) {
	ctx := context.Background()
	a, _ := setupAuth(t)
	sm := a.SessionManager()

	sess1, err := sm.CreateSession(ctx, "user-aux-1")
	if err != nil {
		t.Fatalf("failed to create sess1: %v", err)
	}
	sess2, err := sm.CreateSession(ctx, "user-aux-1")
	if err != nil {
		t.Fatalf("failed to create sess2: %v", err)
	}

	// GetSessionByToken
	byToken, err := sm.GetSessionByToken(ctx, sess1.Token)
	if err != nil || byToken.ID != sess1.ID {
		t.Errorf("GetSessionByToken failed: %v", err)
	}

	// GetSessionByID
	byID, err := sm.GetSessionByID(ctx, sess2.ID)
	if err != nil || byID.Token != sess2.Token {
		t.Errorf("GetSessionByID failed: %v", err)
	}

	// ListSessionsByUserID
	list, err := sm.ListSessionsByUserID(ctx, "user-aux-1")
	if err != nil || len(list) != 2 {
		t.Errorf("ListSessionsByUserID expected 2 sessions, got %d, err: %v", len(list), err)
	}

	// RevokeSessionsByUserID
	if err := sm.RevokeSessionsByUserID(ctx, "user-aux-1"); err != nil {
		t.Fatalf("RevokeSessionsByUserID failed: %v", err)
	}

	listAfter, err := sm.ListSessionsByUserID(ctx, "user-aux-1")
	if err != nil || len(listAfter) != 0 {
		t.Errorf("ListSessionsByUserID expected 0 sessions after mass revoke, got %d", len(listAfter))
	}
}
