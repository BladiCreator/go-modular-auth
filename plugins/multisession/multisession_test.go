package multisession_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	"github.com/BladiCreator/go-modular-auth/plugins/multisession"
	"github.com/BladiCreator/go-modular-auth/plugins/multisession/plugins"
	adaptermem "github.com/BladiCreator/go-modular-auth/adapter/memory"
	corecache "github.com/BladiCreator/go-modular-auth/cache"
	memcache "github.com/BladiCreator/go-modular-auth/cache/memory"
	"github.com/BladiCreator/go-modular-auth/session"
	corestore "github.com/BladiCreator/go-modular-auth/store"
	"github.com/BladiCreator/go-modular-auth/user"
)

type testRig struct {
	auth   *auth.Auth
	store  corestore.Store
	cache  *memcache.Cache
	plugin multisession.MultiSession
}

func setupTestRig(t *testing.T, opts ...multisession.Option) *testRig {
	t.Helper()
	ad := adaptermem.New()
	cache := memcache.New()

	mod := multisession.New(opts...)
	app, err := auth.New(auth.Config{
		Adapter: ad,
		Cache:   cache,
		Plugins: []auth.PluginModule{mod},
	})
	if err != nil {
		t.Fatalf("failed to create auth engine: %v", err)
	}

	cap, err := auth.Get[multisession.MultiSession](app)
	if err != nil {
		t.Fatalf("failed to get MultiSession capability: %v", err)
	}

	return &testRig{
		auth:   app,
		store:  app.Store(),
		cache:  cache,
		plugin: cap,
	}
}

func createTestUser(t *testing.T, rig *testRig, email string) *user.User {
	t.Helper()
	res, err := rig.auth.SignUp(context.Background(), auth.SignUpInput{
		Email:    email,
		Password: "SecurePassword123!",
	})
	if err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}
	return res.User
}

func TestMultiSession_PluginRegistrationAndCapabilityLookup(t *testing.T) {
	rig := setupTestRig(t)

	// Test lookup via multisession.MultiSession
	cap1, err := auth.Get[multisession.MultiSession](rig.auth)
	if err != nil {
		t.Fatalf("Get[multisession.MultiSession] failed: %v", err)
	}
	if cap1 == nil {
		t.Fatal("expected non-nil capability")
	}

	// Test lookup via plugins.MultiSession alias
	cap2, err := auth.Get[plugins.MultiSession](rig.auth)
	if err != nil {
		t.Fatalf("Get[plugins.MultiSession] failed: %v", err)
	}
	if cap2 == nil {
		t.Fatal("expected non-nil capability from plugins alias")
	}

	mod := multisession.New()
	if mod.ID() != multisession.PluginID {
		t.Fatalf("expected module ID %q, got %q", multisession.PluginID, mod.ID())
	}
}

func TestMultiSession_ListAndGetSessions(t *testing.T) {
	ctx := context.Background()
	rig := setupTestRig(t)
	u := createTestUser(t, rig, "list_get@example.com")

	// Create 2 additional sessions
	sess1, err := rig.auth.CreateSession(ctx, u.ID, auth.SessionOptions{
		IPAddress: "192.168.1.10",
		UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
	})
	if err != nil {
		t.Fatalf("CreateSession 1 failed: %v", err)
	}

	sess2, err := rig.auth.CreateSession(ctx, u.ID, auth.SessionOptions{
		IPAddress: "10.0.0.5",
		UserAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1",
	})
	if err != nil {
		t.Fatalf("CreateSession 2 failed: %v", err)
	}

	// List sessions: 1 from SignUp + 2 created = 3 total active
	list, err := rig.plugin.ListSessions(ctx, u.ID)
	if err != nil {
		t.Fatalf("ListSessions failed: %v", err)
	}
	if len(list) != 3 {
		t.Fatalf("expected 3 active sessions, got %d", len(list))
	}

	// Get session by ID
	fetched, err := rig.plugin.GetSession(ctx, sess1.Session.ID)
	if err != nil {
		t.Fatalf("GetSession failed: %v", err)
	}
	if fetched.ID != sess1.Session.ID || fetched.UserID != u.ID {
		t.Fatalf("fetched session mismatch: %+v", fetched)
	}

	// Non-existent session
	_, err = rig.plugin.GetSession(ctx, "non_existent_id")
	if !errors.Is(err, multisession.ErrSessionNotFound) {
		t.Fatalf("expected ErrSessionNotFound, got %v", err)
	}

	// Invalid input
	if _, err := rig.plugin.ListSessions(ctx, ""); !errors.Is(err, multisession.ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}
	if _, err := rig.plugin.GetSession(ctx, ""); !errors.Is(err, multisession.ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}

	_ = sess2
}

func TestMultiSession_ListDetailedSessions_AutoDeviceDetection(t *testing.T) {
	ctx := context.Background()
	rig := setupTestRig(t)
	u := createTestUser(t, rig, "detailed@example.com")

	sess, err := rig.auth.CreateSession(ctx, u.ID, auth.SessionOptions{
		IPAddress: "203.0.113.195",
		UserAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Safari/604.1",
	})
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	detailed, err := rig.plugin.ListDetailedSessions(ctx, u.ID, sess.Session.ID)
	if err != nil {
		t.Fatalf("ListDetailedSessions failed: %v", err)
	}

	var foundCurrent *multisession.SessionDetail
	for _, d := range detailed {
		if d.IsCurrent {
			foundCurrent = d
			break
		}
	}

	if foundCurrent == nil {
		t.Fatal("expected current session to be flagged with IsCurrent=true")
	}
	if foundCurrent.Session.ID != sess.Session.ID {
		t.Fatalf("expected current session ID %q, got %q", sess.Session.ID, foundCurrent.Session.ID)
	}
	if foundCurrent.Metadata == nil {
		t.Fatal("expected auto-inferred metadata")
	}
	if foundCurrent.Metadata.Device.OS != "iOS" {
		t.Fatalf("expected Device.OS 'iOS', got %q", foundCurrent.Metadata.Device.OS)
	}
	if foundCurrent.Metadata.Device.Type != "mobile" {
		t.Fatalf("expected Device.Type 'mobile', got %q", foundCurrent.Metadata.Device.Type)
	}
	if foundCurrent.Metadata.Device.IPAddress != "203.0.113.195" {
		t.Fatalf("expected IPAddress '203.0.113.195', got %q", foundCurrent.Metadata.Device.IPAddress)
	}
}

func TestMultiSession_MetadataCRUD(t *testing.T) {
	ctx := context.Background()
	rig := setupTestRig(t)
	u := createTestUser(t, rig, "metadata@example.com")

	sess, err := rig.auth.CreateSession(ctx, u.ID, auth.SessionOptions{})
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	// Initially no metadata set
	_, err = rig.plugin.GetMetadata(ctx, sess.Session.ID)
	if !errors.Is(err, multisession.ErrMetadataNotFound) {
		t.Fatalf("expected ErrMetadataNotFound, got %v", err)
	}

	// Set metadata
	err = rig.plugin.SetMetadata(ctx, sess.Session.ID, multisession.MetadataInput{
		Device: multisession.DeviceMetadata{
			Name:    "Workstation",
			Type:    "desktop",
			OS:      "Linux",
			Browser: "Firefox",
		},
		Custom: map[string]string{
			"department": "Engineering",
			"location":   "Berlin",
		},
	})
	if err != nil {
		t.Fatalf("SetMetadata failed: %v", err)
	}

	// Get metadata (reads through cache / store)
	meta, err := rig.plugin.GetMetadata(ctx, sess.Session.ID)
	if err != nil {
		t.Fatalf("GetMetadata failed: %v", err)
	}
	if meta.Device.Name != "Workstation" || meta.Custom["department"] != "Engineering" {
		t.Fatalf("unexpected metadata content: %+v", meta)
	}

	// Verify GetDetailedSession uses explicit metadata
	detailed, err := rig.plugin.GetDetailedSession(ctx, sess.Session.ID)
	if err != nil {
		t.Fatalf("GetDetailedSession failed: %v", err)
	}
	if detailed.Metadata.Device.Name != "Workstation" {
		t.Fatalf("expected metadata device name 'Workstation', got %q", detailed.Metadata.Device.Name)
	}
}

func TestMultiSession_RevokeSession(t *testing.T) {
	ctx := context.Background()
	rig := setupTestRig(t)
	u := createTestUser(t, rig, "revoke_single@example.com")

	sess, err := rig.auth.CreateSession(ctx, u.ID, auth.SessionOptions{})
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	// Verify session is active in store and cache
	stored, err := rig.store.Sessions().GetByID(ctx, sess.Session.ID)
	if err != nil || stored.Revoked() {
		t.Fatalf("session should be unrevoked: %v", err)
	}

	// Revoke session
	err = rig.plugin.RevokeSession(ctx, sess.Session.ID)
	if err != nil {
		t.Fatalf("RevokeSession failed: %v", err)
	}

	// Store must be updated first
	stored, err = rig.store.Sessions().GetByID(ctx, sess.Session.ID)
	if err != nil {
		t.Fatalf("GetByID failed: %v", err)
	}
	if !stored.Revoked() {
		t.Fatal("store session was not revoked")
	}

	// Core SessionCache must be invalidated
	var cached session.Session
	err = rig.cache.Get(ctx, corecache.Key("session", sess.Session.TokenHash), &cached)
	if !errors.Is(err, corecache.ErrMiss) {
		t.Fatalf("expected cache miss after revocation, got %v", err)
	}

	// GetSession must now return ErrSessionNotFound
	_, err = rig.plugin.GetSession(ctx, sess.Session.ID)
	if !errors.Is(err, multisession.ErrSessionNotFound) {
		t.Fatalf("expected ErrSessionNotFound, got %v", err)
	}

	// RevokeSession again must be idempotent (no error)
	if err := rig.plugin.RevokeSession(ctx, sess.Session.ID); err != nil {
		t.Fatalf("expected idempotent revoke to succeed, got %v", err)
	}
}

func TestMultiSession_RevokeOtherSessions(t *testing.T) {
	ctx := context.Background()
	rig := setupTestRig(t)
	u := createTestUser(t, rig, "revoke_others@example.com")

	sess1, err := rig.auth.CreateSession(ctx, u.ID, auth.SessionOptions{})
	if err != nil {
		t.Fatalf("CreateSession 1 failed: %v", err)
	}
	sess2, err := rig.auth.CreateSession(ctx, u.ID, auth.SessionOptions{})
	if err != nil {
		t.Fatalf("CreateSession 2 failed: %v", err)
	}

	// Revoke others keeping sess1
	err = rig.plugin.RevokeOtherSessions(ctx, u.ID, sess1.Session.ID)
	if err != nil {
		t.Fatalf("RevokeOtherSessions failed: %v", err)
	}

	// sess1 must remain valid
	if _, err := rig.plugin.GetSession(ctx, sess1.Session.ID); err != nil {
		t.Fatalf("current session should still be valid, got: %v", err)
	}

	// sess2 must be revoked
	if _, err := rig.plugin.GetSession(ctx, sess2.Session.ID); !errors.Is(err, multisession.ErrSessionNotFound) {
		t.Fatalf("other session should be revoked, got: %v", err)
	}

	// List sessions should now have exactly 1 active session (sess1)
	active, err := rig.plugin.ListSessions(ctx, u.ID)
	if err != nil {
		t.Fatalf("ListSessions failed: %v", err)
	}
	if len(active) != 1 || active[0].ID != sess1.Session.ID {
		t.Fatalf("expected only sess1 active, got %d sessions", len(active))
	}

	// Security: unauthorized access check
	otherUser := createTestUser(t, rig, "attacker@example.com")
	err = rig.plugin.RevokeOtherSessions(ctx, otherUser.ID, sess1.Session.ID)
	if !errors.Is(err, multisession.ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized when session belongs to another user, got %v", err)
	}
}

func TestMultiSession_RevokeAllSessions(t *testing.T) {
	ctx := context.Background()
	rig := setupTestRig(t)
	u := createTestUser(t, rig, "revoke_all@example.com")

	_, err := rig.auth.CreateSession(ctx, u.ID, auth.SessionOptions{})
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	err = rig.plugin.RevokeAllSessions(ctx, u.ID)
	if err != nil {
		t.Fatalf("RevokeAllSessions failed: %v", err)
	}

	active, err := rig.plugin.ListSessions(ctx, u.ID)
	if err != nil {
		t.Fatalf("ListSessions failed: %v", err)
	}
	if len(active) != 0 {
		t.Fatalf("expected 0 active sessions after RevokeAllSessions, got %d", len(active))
	}
}

func TestMultiSession_MaxConcurrentSessions_RejectPolicy(t *testing.T) {
	ctx := context.Background()
	// Limit: 2 concurrent sessions with Reject policy
	rig := setupTestRig(t, multisession.WithMaxConcurrentSessions(2, multisession.OverflowReject))
	u := createTestUser(t, rig, "reject_policy@example.com") // Consumes session 1

	// Create session 2 -> Success
	_, err := rig.auth.CreateSession(ctx, u.ID, auth.SessionOptions{})
	if err != nil {
		t.Fatalf("second session creation should succeed: %v", err)
	}

	// Create session 3 -> Exceeds max, must return ErrMaxConcurrentSessionsReached
	_, err = rig.auth.CreateSession(ctx, u.ID, auth.SessionOptions{})
	if !errors.Is(err, multisession.ErrMaxConcurrentSessionsReached) {
		t.Fatalf("expected ErrMaxConcurrentSessionsReached, got %v", err)
	}

	// Verify still exactly 2 active sessions
	active, err := rig.plugin.ListSessions(ctx, u.ID)
	if err != nil {
		t.Fatalf("ListSessions failed: %v", err)
	}
	if len(active) != 2 {
		t.Fatalf("expected 2 active sessions, got %d", len(active))
	}
}

func TestMultiSession_MaxConcurrentSessions_RevokeOldestPolicy(t *testing.T) {
	ctx := context.Background()
	// Limit: 2 concurrent sessions with RevokeOldest policy
	rig := setupTestRig(t, multisession.WithMaxConcurrentSessions(2, multisession.OverflowRevokeOldest))
	u := createTestUser(t, rig, "revoke_oldest@example.com") // Session 1 (oldest)

	time.Sleep(10 * time.Millisecond)
	sess2, err := rig.auth.CreateSession(ctx, u.ID, auth.SessionOptions{})
	if err != nil {
		t.Fatalf("session 2 failed: %v", err)
	}

	time.Sleep(10 * time.Millisecond)
	sess3, err := rig.auth.CreateSession(ctx, u.ID, auth.SessionOptions{})
	if err != nil {
		t.Fatalf("session 3 should succeed by evicting session 1: %v", err)
	}

	// Active sessions should now be sess2 and sess3
	active, err := rig.plugin.ListSessions(ctx, u.ID)
	if err != nil {
		t.Fatalf("ListSessions failed: %v", err)
	}
	if len(active) != 2 {
		t.Fatalf("expected 2 active sessions, got %d", len(active))
	}

	// Verify session 2 and session 3 are active
	ids := map[string]bool{sess2.Session.ID: true, sess3.Session.ID: true}
	for _, s := range active {
		if !ids[s.ID] {
			t.Fatalf("unexpected active session: %s", s.ID)
		}
	}
}

func TestMultiSession_EventsEmitted(t *testing.T) {
	ctx := context.Background()
	rig := setupTestRig(t, multisession.WithMaxConcurrentSessions(1, multisession.OverflowRevokeOldest))

	var eventsReceived []auth.EventName
	var mu sync.Mutex

	handler := func(_ context.Context, e auth.Event) {
		mu.Lock()
		defer mu.Unlock()
		eventsReceived = append(eventsReceived, e.Name)
	}

	rig.auth.Events().Subscribe(multisession.EventSessionRevoked, handler)
	rig.auth.Events().Subscribe(multisession.EventSessionsRevoked, handler)
	rig.auth.Events().Subscribe(multisession.EventSessionEvicted, handler)
	rig.auth.Events().Subscribe(multisession.EventMetadataUpdated, handler)

	u := createTestUser(t, rig, "events@example.com")

	// Creating a second session should trigger eviction of the first
	sess2, err := rig.auth.CreateSession(ctx, u.ID, auth.SessionOptions{})
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	// Set metadata
	_ = rig.plugin.SetMetadata(ctx, sess2.Session.ID, multisession.MetadataInput{
		Device: multisession.DeviceMetadata{Name: "Laptop"},
	})

	// Revoke session
	_ = rig.plugin.RevokeSession(ctx, sess2.Session.ID)

	mu.Lock()
	events := append([]auth.EventName(nil), eventsReceived...)
	mu.Unlock()

	hasEvicted := false
	hasMetadata := false
	hasRevoked := false

	for _, e := range events {
		switch e {
		case multisession.EventSessionEvicted:
			hasEvicted = true
		case multisession.EventMetadataUpdated:
			hasMetadata = true
		case multisession.EventSessionRevoked:
			hasRevoked = true
		}
	}

	if !hasEvicted {
		t.Error("expected EventSessionEvicted to be emitted")
	}
	if !hasMetadata {
		t.Error("expected EventMetadataUpdated to be emitted")
	}
	if !hasRevoked {
		t.Error("expected EventSessionRevoked to be emitted")
	}
}

func TestMultiSession_ConcurrentRevocationSafety(t *testing.T) {
	ctx := context.Background()
	rig := setupTestRig(t)
	u := createTestUser(t, rig, "concurrent@example.com")

	sess, err := rig.auth.CreateSession(ctx, u.ID, auth.SessionOptions{})
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	var wg sync.WaitGroup
	errCh := make(chan error, 20)

	// Launch 20 concurrent revocations of the same session
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := rig.plugin.RevokeSession(ctx, sess.Session.ID); err != nil {
				errCh <- err
			}
		}()
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Fatalf("concurrent RevokeSession returned error: %v", err)
	}

	// Ensure session is cleanly revoked
	stored, err := rig.store.Sessions().GetByID(ctx, sess.Session.ID)
	if err != nil || !stored.Revoked() {
		t.Fatal("session should be revoked in store after concurrent calls")
	}
}

func TestMultiSession_UserAgentParser(t *testing.T) {
	tests := []struct {
		name    string
		ua      string
		ip      string
		wantOS  string
		wantDev string
		wantBrw string
	}{
		{
			name:    "macOS Chrome",
			ua:      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			ip:      "1.2.3.4",
			wantOS:  "macOS",
			wantDev: "desktop",
			wantBrw: "Chrome",
		},
		{
			name:    "iPhone Safari",
			ua:      "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
			ip:      "5.6.7.8",
			wantOS:  "iOS",
			wantDev: "mobile",
			wantBrw: "Safari",
		},
		{
			name:    "Windows Edge",
			ua:      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
			ip:      "9.10.11.12",
			wantOS:  "Windows",
			wantDev: "desktop",
			wantBrw: "Edge",
		},
		{
			name:    "Android Tablet Firefox",
			ua:      "Mozilla/5.0 (Android; Tablet; rv:120.0) Gecko/120.0 Firefox/120.0",
			ip:      "13.14.15.16",
			wantOS:  "Android",
			wantDev: "tablet",
			wantBrw: "Firefox",
		},
		{
			name:    "Crawler bot",
			ua:      "Googlebot/2.1 (+http://www.google.com/bot.html)",
			ip:      "66.249.66.1",
			wantOS:  "Unknown",
			wantDev: "bot",
			wantBrw: "Unknown Browser",
		},
		{
			name:    "Empty User-Agent",
			ua:      "",
			ip:      "127.0.0.1",
			wantOS:  "Unknown",
			wantDev: "unknown",
			wantBrw: "Unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dev := multisession.ParseUserAgent(tt.ua, tt.ip)
			if dev.OS != tt.wantOS {
				t.Errorf("OS: expected %q, got %q", tt.wantOS, dev.OS)
			}
			if dev.Type != tt.wantDev {
				t.Errorf("Type: expected %q, got %q", tt.wantDev, dev.Type)
			}
			if dev.Browser != tt.wantBrw {
				t.Errorf("Browser: expected %q, got %q", tt.wantBrw, dev.Browser)
			}
			if dev.IPAddress != tt.ip {
				t.Errorf("IPAddress: expected %q, got %q", tt.ip, dev.IPAddress)
			}
		})
	}
}
