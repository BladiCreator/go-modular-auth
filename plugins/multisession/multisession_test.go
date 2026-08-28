package multisession_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/BladiCreator/go-modular-auth/adapters/memory"
	"github.com/BladiCreator/go-modular-auth/domain/dto"
	"github.com/BladiCreator/go-modular-auth/domain/entity"
	"github.com/BladiCreator/go-modular-auth/plugin"
	"github.com/BladiCreator/go-modular-auth/plugins/multisession"
	"github.com/asaskevich/EventBus"
)

func setupTestPlugin(t *testing.T, opts ...multisession.Option) (*multisession.Plugin, *memory.Store, EventBus.Bus) {
	t.Helper()
	store := memory.New()
	bus := EventBus.New()
	cryptoMock := &mockCrypto{}
	pCtx := plugin.NewContext(cryptoMock, bus)

	defaultOpts := []multisession.Option{
		multisession.WithSecret("test-hmac-secret-12345"),
		multisession.WithCookiePrefix("modular-auth"),
		multisession.WithMaximumSessions(5),
	}
	defaultOpts = append(defaultOpts, opts...)
	p := multisession.New(store, defaultOpts...)
	if err := p.Init(pCtx); err != nil {
		t.Fatalf("failed to init plugin context: %v", err)
	}

	return p, store, bus
}

type mockCrypto struct{}

func (m *mockCrypto) HashPassword(password string) (string, error) { return password, nil }
func (m *mockCrypto) ComparePassword(hash, password string) bool   { return hash == password }
func (m *mockCrypto) GenerateRandomToken(length int) (string, error) {
	return "random_token_123", nil
}

func createTestUserAndSession(t *testing.T, store *memory.Store, name, email string) (*entity.User, *entity.Session) {
	t.Helper()
	ctx := context.Background()
	user, err := store.CreateUser(ctx, &dto.CreateUserParams{
		Name:  name,
		Email: email,
	})
	if err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}

	session, err := store.CreateSession(ctx, &dto.CreateSessionParams{
		UserID:    user.ID,
		Token:     "token_" + strings.ReplaceAll(user.ID, ":", "_"),
		ExpiresAt: time.Now().Add(24 * time.Hour),
		CreatedAt: time.Now(),
	})
	if err != nil {
		t.Fatalf("failed to create test session: %v", err)
	}

	return user, session
}

func TestMultiSession(t *testing.T) {
	t.Run("GetConfigInfo", func(t *testing.T) {
		p, _, _ := setupTestPlugin(t)
		info := p.GetConfigInfo()
		if info.MaximumSessions != 5 || info.CookiePrefix != "modular-auth" {
			t.Fatalf("unexpected config info: %+v", info)
		}
	})

	t.Run("SetCookieOnLogin", func(t *testing.T) {
		p, store, _ := setupTestPlugin(t)
		_, session := createTestUserAndSession(t, store, "Alice", "alice@example.com")

		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/sign-in", nil)

		err := p.AfterSessionCreated(context.Background(), w, r, session)
		if err != nil {
			t.Fatalf("AfterSessionCreated failed: %v", err)
		}

		res := w.Result()
		cookies := res.Cookies()
		if len(cookies) == 0 {
			t.Fatalf("expected cookies to be set, got none")
		}

		multiCookieName := p.GetMultiCookieName(session.Token)
		var foundMultiCookie *http.Cookie
		for _, c := range cookies {
			if c.Name == multiCookieName {
				foundMultiCookie = c
				break
			}
		}

		if foundMultiCookie == nil {
			t.Fatalf("expected multi-session cookie %s, got none", multiCookieName)
		}

		rawToken, err := multisession.VerifyCookieValue(foundMultiCookie.Value, p.Config().Secret)
		if err != nil || rawToken != session.Token {
			t.Fatalf("cookie signature verification failed: got rawToken %q, err %v", rawToken, err)
		}
	})

	t.Run("ListDeviceSessionsWithIsActive", func(t *testing.T) {
		p, store, bus := setupTestPlugin(t)
		u1, s1 := createTestUserAndSession(t, store, "Alice", "alice@example.com")
		u2, s2 := createTestUserAndSession(t, store, "Bob", "bob@example.com")

		eventFired := false
		_ = bus.Subscribe(multisession.EventListDeviceSessionsAfter, func(payload *multisession.ListDeviceSessionsEventPayload) {
			eventFired = true
		})

		c1Val := multisession.SignCookieValue(s1.Token, p.Config().Secret)
		c2Val := multisession.SignCookieValue(s2.Token, p.Config().Secret)

		r := httptest.NewRequest("GET", "/multi-session/list-device-sessions", nil)
		r.AddCookie(&http.Cookie{Name: p.GetMultiCookieName(s1.Token), Value: c1Val})
		r.AddCookie(&http.Cookie{Name: p.GetMultiCookieName(s2.Token), Value: c2Val})

		tokens := p.ExtractMultiSessionTokens(r)
		listRes, err := p.ListDeviceSessions(r.Context(), multisession.ListDeviceSessionsParams{
			Tokens:      tokens,
			ActiveToken: s2.Token,
		})
		if err != nil {
			t.Fatalf("ListDeviceSessions failed: %v", err)
		}

		if len(listRes.DeviceSessions) != 2 || listRes.TotalCount != 2 {
			t.Fatalf("expected 2 device sessions, got %d", len(listRes.DeviceSessions))
		}

		if listRes.ActiveSession == nil || listRes.ActiveSession.User.ID != u2.ID {
			t.Fatalf("expected ActiveSession to be user Bob (%s), got %+v", u2.ID, listRes.ActiveSession)
		}

		userIDs := map[string]bool{listRes.DeviceSessions[0].User.ID: true, listRes.DeviceSessions[1].User.ID: true}
		if !userIDs[u1.ID] || !userIDs[u2.ID] {
			t.Fatalf("expected users %s and %s in list, got %+v", u1.ID, u2.ID, listRes.DeviceSessions)
		}

		if !eventFired {
			t.Fatalf("expected EventListDeviceSessionsAfter event to be fired")
		}
	})

	t.Run("SetActiveSession", func(t *testing.T) {
		p, store, bus := setupTestPlugin(t)
		_, s1 := createTestUserAndSession(t, store, "Alice", "alice@example.com")
		u2, s2 := createTestUserAndSession(t, store, "Bob", "bob@example.com")

		eventFired := false
		_ = bus.Subscribe(multisession.EventSetActiveSessionAfter, func(payload *multisession.SetActiveSessionEventPayload) {
			eventFired = true
		})

		c2Val := multisession.SignCookieValue(s2.Token, p.Config().Secret)

		r := httptest.NewRequest("POST", "/multi-session/set-active", nil)
		r.AddCookie(&http.Cookie{Name: p.GetMultiCookieName(s2.Token), Value: c2Val})

		tokens := p.ExtractMultiSessionTokens(r)
		foundTarget := false
		for _, tok := range tokens {
			if tok == s2.Token {
				foundTarget = true
				break
			}
		}
		if !foundTarget {
			t.Fatalf("target token %s not found in verified request cookies", s2.Token)
		}

		res, err := p.SetActiveSession(r.Context(), multisession.SetActiveSessionParams{
			SessionToken: s2.Token,
		})
		if err != nil {
			t.Fatalf("SetActiveSession failed: %v", err)
		}

		if res.DeviceSession.User.ID != u2.ID || res.ActiveToken != s2.Token || !res.Status {
			t.Fatalf("expected active user %s with status true, got %+v", u2.ID, res)
		}

		// Verify main session cookie setting helper
		w := httptest.NewRecorder()
		p.SetMainSessionCookie(w, res.ActiveToken, res.ExpiresAt)

		cookies := w.Result().Cookies()
		var mainCookie *http.Cookie
		for _, c := range cookies {
			if c.Name == "modular-auth.session_token" {
				mainCookie = c
				break
			}
		}
		if mainCookie == nil {
			t.Fatalf("expected main session cookie to be set")
		}
		activeToken, err := multisession.VerifyCookieValue(mainCookie.Value, p.Config().Secret)
		if err != nil || activeToken != s2.Token {
			t.Fatalf("expected active token %s in main cookie, got %s (err %v)", s2.Token, activeToken, err)
		}

		if !eventFired {
			t.Fatalf("expected EventSetActiveSessionAfter event to be fired")
		}
		_ = s1
	})

	t.Run("RevokeAndSwitchActive", func(t *testing.T) {
		p, store, bus := setupTestPlugin(t)
		_, s1 := createTestUserAndSession(t, store, "Alice", "alice@example.com")
		_, s2 := createTestUserAndSession(t, store, "Bob", "bob@example.com")

		eventFired := false
		_ = bus.Subscribe(multisession.EventRevokeDeviceSessionAfter, func(payload *multisession.RevokeDeviceSessionEventPayload) {
			eventFired = true
		})

		c1Val := multisession.SignCookieValue(s1.Token, p.Config().Secret)
		c2Val := multisession.SignCookieValue(s2.Token, p.Config().Secret)
		mainVal := multisession.SignCookieValue(s1.Token, p.Config().Secret)

		r := httptest.NewRequest("POST", "/multi-session/revoke", nil)
		r.AddCookie(&http.Cookie{Name: "modular-auth.session_token", Value: mainVal})
		r.AddCookie(&http.Cookie{Name: p.GetMultiCookieName(s1.Token), Value: c1Val})
		r.AddCookie(&http.Cookie{Name: p.GetMultiCookieName(s2.Token), Value: c2Val})

		activeTokenInReq := p.ExtractMainSessionToken(r)
		deviceTokens := p.ExtractMultiSessionTokens(r)

		res, err := p.RevokeDeviceSession(r.Context(), multisession.RevokeDeviceSessionParams{
			SessionToken:     s1.Token,
			DeviceTokens:     deviceTokens,
			ActiveTokenInReq: activeTokenInReq,
		})
		if err != nil {
			t.Fatalf("RevokeDeviceSession failed: %v", err)
		}

		if !res.Status || !res.WasActive || res.NewActiveSession == nil {
			t.Fatalf("expected active session switch, got result %+v", res)
		}

		if res.NewActiveSession.Token != s2.Token {
			t.Fatalf("expected new active token %s, got %s", s2.Token, res.NewActiveSession.Token)
		}

		// Verify session s1 is deleted from DB
		ctx := context.Background()
		_, err = store.GetSessionByToken(ctx, s1.Token)
		if err == nil {
			t.Fatalf("expected session s1 to be deleted from store")
		}

		if !eventFired {
			t.Fatalf("expected EventRevokeDeviceSessionAfter event to be fired")
		}
	})

	t.Run("RevokeAllAndRevokeOther", func(t *testing.T) {
		p, store, _ := setupTestPlugin(t)
		_, s1 := createTestUserAndSession(t, store, "Alice", "alice@example.com")
		_, s2 := createTestUserAndSession(t, store, "Bob", "bob@example.com")
		_, s3 := createTestUserAndSession(t, store, "Charlie", "charlie@example.com")

		ctx := context.Background()

		// Test RevokeOther
		otherRes, err := p.RevokeOtherSessions(ctx, multisession.RevokeOtherSessionsParams{
			DeviceTokens: []string{s1.Token, s2.Token, s3.Token},
			ActiveToken:  s1.Token,
		})
		if err != nil {
			t.Fatalf("RevokeOtherSessions failed: %v", err)
		}
		if otherRes.Count != 2 {
			t.Fatalf("expected 2 tokens revoked, got %d", otherRes.Count)
		}
		if _, err := store.GetSessionByToken(ctx, s1.Token); err != nil {
			t.Fatalf("active session s1 should still exist")
		}
		if _, err := store.GetSessionByToken(ctx, s2.Token); err == nil {
			t.Fatalf("s2 should be revoked")
		}

		// Test RevokeAll
		allRes, err := p.RevokeAllSessions(ctx, multisession.RevokeAllSessionsParams{
			DeviceTokens: []string{s1.Token},
		})
		if err != nil {
			t.Fatalf("RevokeAllSessions failed: %v", err)
		}
		if allRes.Count != 1 {
			t.Fatalf("expected 1 token revoked, got %d", allRes.Count)
		}
		if _, err := store.GetSessionByToken(ctx, s1.Token); err == nil {
			t.Fatalf("s1 should be revoked now")
		}
	})

	t.Run("SignOutAll", func(t *testing.T) {
		p, store, bus := setupTestPlugin(t)
		_, s1 := createTestUserAndSession(t, store, "Alice", "alice@example.com")
		_, s2 := createTestUserAndSession(t, store, "Bob", "bob@example.com")

		eventFired := false
		_ = bus.Subscribe(multisession.EventSignOut, func(payload *multisession.SignOutEventPayload) {
			eventFired = true
		})

		c1Val := multisession.SignCookieValue(s1.Token, p.Config().Secret)
		c2Val := multisession.SignCookieValue(s2.Token, p.Config().Secret)

		r := httptest.NewRequest("POST", "/sign-out", nil)
		r.AddCookie(&http.Cookie{Name: p.GetMultiCookieName(s1.Token), Value: c1Val})
		r.AddCookie(&http.Cookie{Name: p.GetMultiCookieName(s2.Token), Value: c2Val})

		w := httptest.NewRecorder()
		err := p.AfterSignOut(context.Background(), w, r)
		if err != nil {
			t.Fatalf("AfterSignOut failed: %v", err)
		}

		ctx := context.Background()
		if _, err := store.GetSessionByToken(ctx, s1.Token); err == nil {
			t.Fatalf("expected s1 to be deleted")
		}
		if _, err := store.GetSessionByToken(ctx, s2.Token); err == nil {
			t.Fatalf("expected s2 to be deleted")
		}

		// Verify multi-session cookies are expired
		cookies := w.Result().Cookies()
		expiredCount := 0
		for _, c := range cookies {
			if c.MaxAge == -1 || c.Expires.Before(time.Now()) {
				expiredCount++
			}
		}
		if expiredCount < 2 {
			t.Fatalf("expected at least 2 expired cookies, got %d", expiredCount)
		}

		if !eventFired {
			t.Fatalf("expected EventSignOut event to be fired")
		}
	})

	t.Run("ReplaceOldUserSession", func(t *testing.T) {
		p, store, _ := setupTestPlugin(t)
		u1, s1 := createTestUserAndSession(t, store, "Alice", "alice@example.com")

		// Create new session for SAME user
		s1New, err := store.CreateSession(context.Background(), &dto.CreateSessionParams{
			UserID:    u1.ID,
			Token:     "token_alice_new",
			ExpiresAt: time.Now().Add(24 * time.Hour),
			CreatedAt: time.Now(),
		})
		if err != nil {
			t.Fatalf("failed to create new session: %v", err)
		}

		c1Val := multisession.SignCookieValue(s1.Token, p.Config().Secret)

		r := httptest.NewRequest("POST", "/sign-in", nil)
		r.AddCookie(&http.Cookie{Name: p.GetMultiCookieName(s1.Token), Value: c1Val})

		w := httptest.NewRecorder()
		err = p.AfterSessionCreated(context.Background(), w, r, s1New)
		if err != nil {
			t.Fatalf("AfterSessionCreated failed: %v", err)
		}

		// Verify old session s1 is deleted from store
		ctx := context.Background()
		if _, err := store.GetSessionByToken(ctx, s1.Token); err == nil {
			t.Fatalf("expected old session s1 to be deleted")
		}
		if _, err := store.GetSessionByToken(ctx, s1New.Token); err != nil {
			t.Fatalf("expected new session s1New to exist")
		}
	})

	t.Run("RejectForgedCookies", func(t *testing.T) {
		p, store, _ := setupTestPlugin(t)
		_, s1 := createTestUserAndSession(t, store, "Alice", "alice@example.com")

		// Forged cookie value with invalid signature
		forgedVal := s1.Token + ".invalid_signature_hash"

		r := httptest.NewRequest("POST", "/multi-session/revoke", nil)
		r.AddCookie(&http.Cookie{Name: p.GetMultiCookieName(s1.Token), Value: forgedVal})

		// Verified token extraction must ignore forged cookies
		tokens := p.ExtractMultiSessionTokens(r)
		if len(tokens) != 0 {
			t.Fatalf("expected forged cookie token to be rejected, but extracted: %v", tokens)
		}

		// Verify victim session was NOT revoked
		ctx := context.Background()
		if _, err := store.GetSessionByToken(ctx, s1.Token); err != nil {
			t.Fatalf("victim session was incorrectly deleted!")
		}
	})

	t.Run("MaxSessionsLimit", func(t *testing.T) {
		p, store, _ := setupTestPlugin(t, multisession.WithMaximumSessions(2))

		u1, s1 := createTestUserAndSession(t, store, "Alice", "alice@example.com")
		u2, s2 := createTestUserAndSession(t, store, "Bob", "bob@example.com")
		u3, s3 := createTestUserAndSession(t, store, "Charlie", "charlie@example.com")

		c1Val := multisession.SignCookieValue(s1.Token, p.Config().Secret)
		c2Val := multisession.SignCookieValue(s2.Token, p.Config().Secret)

		r := httptest.NewRequest("POST", "/sign-in", nil)
		r.AddCookie(&http.Cookie{Name: p.GetMultiCookieName(s1.Token), Value: c1Val})
		r.AddCookie(&http.Cookie{Name: p.GetMultiCookieName(s2.Token), Value: c2Val})

		w := httptest.NewRecorder()
		err := p.AfterSessionCreated(context.Background(), w, r, s3)
		if err != nil {
			t.Fatalf("AfterSessionCreated failed: %v", err)
		}

		// Verify Charlie's multi-session cookie was NOT set because limit (2) is reached
		c3Name := p.GetMultiCookieName(s3.Token)
		cookies := w.Result().Cookies()
		for _, c := range cookies {
			if c.Name == c3Name {
				t.Fatalf("expected multi-session cookie for Charlie to be skipped due to MaximumSessions limit")
			}
		}
		_ = u1
		_ = u2
		_ = u3
	})

	t.Run("Callbacks", func(t *testing.T) {
		activatedFired := false
		revokedFired := false

		p, store, _ := setupTestPlugin(t,
			multisession.WithOnSessionActivated(func(ctx context.Context, res *multisession.SetActiveSessionResult) error {
				activatedFired = true
				return nil
			}),
			multisession.WithOnSessionRevoked(func(ctx context.Context, res *multisession.RevokeDeviceSessionResult) error {
				revokedFired = true
				return nil
			}),
		)

		_, s1 := createTestUserAndSession(t, store, "Alice", "alice@example.com")

		_, err := p.SetActiveSession(context.Background(), multisession.SetActiveSessionParams{
			SessionToken: s1.Token,
		})
		if err != nil {
			t.Fatalf("SetActiveSession failed: %v", err)
		}
		if !activatedFired {
			t.Fatalf("expected OnSessionActivated callback to be invoked")
		}

		_, err = p.RevokeDeviceSession(context.Background(), multisession.RevokeDeviceSessionParams{
			SessionToken: s1.Token,
		})
		if err != nil {
			t.Fatalf("RevokeDeviceSession failed: %v", err)
		}
		if !revokedFired {
			t.Fatalf("expected OnSessionRevoked callback to be invoked")
		}
	})
}
