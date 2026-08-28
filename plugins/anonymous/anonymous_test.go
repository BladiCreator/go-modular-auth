package anonymous_test

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/BladiCreator/go-modular-auth/domain/dto"
	"github.com/BladiCreator/go-modular-auth/domain/entity"
	"github.com/BladiCreator/go-modular-auth/plugin"
	"github.com/BladiCreator/go-modular-auth/plugins/anonymous"
)

func setupPlugin(opts ...anonymous.Option) (*anonymous.Plugin, *anonymous.MemoryRepository, context.Context) {
	repo := anonymous.NewMemoryRepository()
	p := anonymous.NewWithRepository(repo, opts...)
	ctx := context.Background()

	busCtx := plugin.NewContext(nil, nil)
	_ = p.Init(busCtx)

	return p, repo, ctx
}

func TestSignInAnonymous_Success(t *testing.T) {
	p, repo, ctx := setupPlugin()

	res, err := p.SignInAnonymous(ctx, nil, anonymous.SignInAnonymousParams{
		IPAddress: "127.0.0.1",
		UserAgent: "Go-Test-Agent",
	})
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if res == nil || res.User == nil || res.Session == nil || res.Token == "" {
		t.Fatalf("expected non-nil user, session and token")
	}

	if !res.User.IsAnonymous {
		t.Errorf("expected User.IsAnonymous to be true")
	}

	if !strings.HasSuffix(res.User.Email, "@anonymous.local") {
		t.Errorf("expected email to end with @anonymous.local, got: %s", res.User.Email)
	}

	if res.User.Name != "Anonymous" {
		t.Errorf("expected name Anonymous, got: %s", res.User.Name)
	}

	// Verify persistence
	dbUser, err := repo.GetUserByID(ctx, res.User.ID)
	if err != nil || dbUser == nil {
		t.Fatalf("expected user to be saved in repository")
	}
}

func TestSignInAnonymous_AlreadyAnonymous(t *testing.T) {
	p, _, ctx := setupPlugin()

	res, err := p.SignInAnonymous(ctx, nil, anonymous.SignInAnonymousParams{})
	if err != nil {
		t.Fatalf("unexpected error on first sign in: %v", err)
	}

	// Attempt sign in with active anonymous session
	_, err = p.SignInAnonymous(ctx, res.Session, anonymous.SignInAnonymousParams{})
	if !errors.Is(err, anonymous.ErrAnonymousUsersCannotSignInAgain) {
		t.Fatalf("expected ErrAnonymousUsersCannotSignInAgain, got: %v", err)
	}
}

func TestSignInAnonymous_CustomGenerators(t *testing.T) {
	t.Run("Custom Domain and Name", func(t *testing.T) {
		p, _, ctx := setupPlugin(
			anonymous.WithEmailDomainName("guest.myapp.io"),
			anonymous.WithGenerateName(func(ctx context.Context) (string, error) {
				return "Guest Hero", nil
			}),
		)

		res, err := p.SignInAnonymous(ctx, nil, anonymous.SignInAnonymousParams{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if res.User.Name != "Guest Hero" {
			t.Errorf("expected 'Guest Hero', got: %s", res.User.Name)
		}

		if !strings.HasSuffix(res.User.Email, "@guest.myapp.io") {
			t.Errorf("expected suffix @guest.myapp.io, got: %s", res.User.Email)
		}
	})

	t.Run("Invalid Email Format", func(t *testing.T) {
		p, _, ctx := setupPlugin(
			anonymous.WithGenerateRandomEmail(func(ctx context.Context) (string, error) {
				return "invalid-email-no-at-sign", nil
			}),
		)

		_, err := p.SignInAnonymous(ctx, nil, anonymous.SignInAnonymousParams{})
		if !errors.Is(err, anonymous.ErrInvalidEmailFormat) {
			t.Fatalf("expected ErrInvalidEmailFormat, got: %v", err)
		}
	})
}

func TestDeleteAnonymousUser_Success(t *testing.T) {
	p, repo, ctx := setupPlugin()

	res, err := p.SignInAnonymous(ctx, nil, anonymous.SignInAnonymousParams{})
	if err != nil {
		t.Fatalf("unexpected error creating guest user: %v", err)
	}

	delRes, err := p.DeleteAnonymousUser(ctx, res.Session)
	if err != nil {
		t.Fatalf("expected no error deleting guest user, got: %v", err)
	}

	if !delRes.Success {
		t.Errorf("expected delRes.Success to be true")
	}

	// Verify user is purged from repo
	_, err = repo.GetUserByID(ctx, res.User.ID)
	if !errors.Is(err, anonymous.ErrUserNotFound) {
		t.Fatalf("expected ErrUserNotFound after deletion, got: %v", err)
	}
}

func TestDeleteAnonymousUser_NotAnonymousUser(t *testing.T) {
	p, repo, ctx := setupPlugin()

	// Create a non-anonymous user directly in repo
	nonAnonUser := &entity.User{
		ID:          "permanent-user-1",
		Name:        "John Doe",
		Email:       "john@example.com",
		IsAnonymous: false,
	}
	// We use MemoryRepository internal or CreateSession for setup
	sess, err := repo.CreateSession(ctx, &dto.CreateSessionParams{
		UserID:    nonAnonUser.ID,
		Token:     "perm-token",
		ExpiresAt: time.Now().Add(1 * time.Hour),
		CreatedAt: time.Now(),
	})
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	// Save non-anon user directly in repo for testing
	// MemoryRepository CreateAnonymousUser creates with IsAnonymous=true, so we test DeleteAnonymousUser with non-anon User.
	// But GetUserByID will fail if not in repo. Let's create an anon user first, then manually mutate IsAnonymous to false.
	res, err := p.SignInAnonymous(ctx, nil, anonymous.SignInAnonymousParams{})
	if err != nil {
		t.Fatalf("failed setup: %v", err)
	}

	res.User.IsAnonymous = false // Mutate in memory repo reference
	_, err = p.DeleteAnonymousUser(ctx, sess)
	if err == nil {
		t.Fatalf("expected error deleting non-anonymous user, got nil")
	}
}

func TestDeleteAnonymousUser_Disabled(t *testing.T) {
	p, _, ctx := setupPlugin(
		anonymous.WithDisableDeleteAnonymousUser(true),
	)

	res, err := p.SignInAnonymous(ctx, nil, anonymous.SignInAnonymousParams{})
	if err != nil {
		t.Fatalf("failed setup: %v", err)
	}

	_, err = p.DeleteAnonymousUser(ctx, res.Session)
	if !errors.Is(err, anonymous.ErrDeleteAnonymousUserDisabled) {
		t.Fatalf("expected ErrDeleteAnonymousUserDisabled, got: %v", err)
	}
}

func TestLinkAccount_SuccessAndCleanup(t *testing.T) {
	var callbackExecuted bool
	p, repo, ctx := setupPlugin(
		anonymous.WithOnLinkAccount(func(ctx context.Context, data *anonymous.OnLinkAccountData) error {
			callbackExecuted = true
			if data.AnonymousUser.User == nil || data.NewUser.User == nil {
				return errors.New("nil users in link data")
			}
			return nil
		}),
	)

	res, err := p.SignInAnonymous(ctx, nil, anonymous.SignInAnonymousParams{})
	if err != nil {
		t.Fatalf("failed setup: %v", err)
	}

	newUser := &entity.User{
		ID:          "new-permanent-user-id",
		Name:        "Alice",
		Email:       "alice@example.com",
		IsAnonymous: false,
	}

	linkData := &anonymous.OnLinkAccountData{
		AnonymousUser: anonymous.UserSessionPair{
			User:    res.User,
			Session: res.Session,
		},
		NewUser: anonymous.UserSessionPair{
			User:    newUser,
			Session: &entity.Session{ID: "new-sess-id", UserID: newUser.ID},
		},
	}

	err = p.LinkAccount(ctx, linkData)
	if err != nil {
		t.Fatalf("expected no error linking account, got: %v", err)
	}

	if !callbackExecuted {
		t.Errorf("expected OnLinkAccount callback to be executed")
	}

	// Verify anonymous user was purged
	_, err = repo.GetUserByID(ctx, res.User.ID)
	if !errors.Is(err, anonymous.ErrUserNotFound) {
		t.Fatalf("expected guest user to be deleted after linking")
	}
}

func TestLinkAccount_ErrorAbortsDeletion(t *testing.T) {
	p, repo, ctx := setupPlugin(
		anonymous.WithOnLinkAccount(func(ctx context.Context, data *anonymous.OnLinkAccountData) error {
			return errors.New("migration failed due to DB constraint")
		}),
	)

	res, err := p.SignInAnonymous(ctx, nil, anonymous.SignInAnonymousParams{})
	if err != nil {
		t.Fatalf("failed setup: %v", err)
	}

	newUser := &entity.User{
		ID:          "new-permanent-user-id",
		Name:        "Alice",
		Email:       "alice@example.com",
		IsAnonymous: false,
	}

	linkData := &anonymous.OnLinkAccountData{
		AnonymousUser: anonymous.UserSessionPair{
			User:    res.User,
			Session: res.Session,
		},
		NewUser: anonymous.UserSessionPair{
			User:    newUser,
			Session: &entity.Session{ID: "new-sess-id", UserID: newUser.ID},
		},
	}

	err = p.LinkAccount(ctx, linkData)
	if err == nil {
		t.Fatalf("expected error from LinkAccount, got nil")
	}

	// Verify anonymous user was NOT purged because callback failed
	dbUser, err := repo.GetUserByID(ctx, res.User.ID)
	if err != nil || dbUser == nil {
		t.Fatalf("expected guest user to remain in repo when linking fails")
	}
}

func TestHTTP_ServeSignInAnonymous(t *testing.T) {
	p, _, _ := setupPlugin()

	req := httptest.NewRequest(http.MethodPost, "/sign-in/anonymous", bytes.NewBufferString("{}"))
	w := httptest.NewRecorder()

	p.ServeSignInAnonymous(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected HTTP 200, got: %d", resp.StatusCode)
	}

	cookies := resp.Cookies()
	if len(cookies) == 0 {
		t.Fatalf("expected session cookie to be set")
	}

	foundCookie := false
	for _, c := range cookies {
		if c.Name == anonymous.DefaultCookieName && c.Value != "" {
			foundCookie = true
			break
		}
	}

	if !foundCookie {
		t.Errorf("expected cookie %s to be present in response", anonymous.DefaultCookieName)
	}
}
