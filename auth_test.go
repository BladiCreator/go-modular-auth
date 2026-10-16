package auth_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	"github.com/BladiCreator/go-modular-auth/adapter"
	adaptermem "github.com/BladiCreator/go-modular-auth/adapter/memory"
	"github.com/BladiCreator/go-modular-auth/cache"
	memcache "github.com/BladiCreator/go-modular-auth/cache/memory"
	mememail "github.com/BladiCreator/go-modular-auth/email/memory"
	"github.com/BladiCreator/go-modular-auth/password"
	"github.com/BladiCreator/go-modular-auth/schema"
	"github.com/BladiCreator/go-modular-auth/session"
	"github.com/BladiCreator/go-modular-auth/user"
)

// fastHasher keeps tests quick; never use these parameters in production.
var fastHasher = password.NewArgon2id(password.Argon2idParams{Memory: 64, Iterations: 1})

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time          { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Advance(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

type fixture struct {
	auth    *auth.Auth
	adapter *adaptermem.Adapter
	cache   *memcache.Cache
	email   *mememail.Sender
	clock   *clock
}

func newFixture(t *testing.T, mutate func(*auth.Config)) *fixture {
	t.Helper()
	clk := &clock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	f := &fixture{
		adapter: adaptermem.New(),
		cache:   memcache.New(memcache.WithClock(clk.Now)),
		email:   mememail.New(),
		clock:   clk,
	}
	cfg := auth.Config{Adapter: f.adapter, Cache: f.cache, Email: f.email, Hasher: fastHasher, Now: clk.Now}
	if mutate != nil {
		mutate(&cfg)
	}
	a, err := auth.New(cfg)
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}
	f.auth = a
	return f
}

func mustSignUp(t *testing.T, f *fixture, email, pw string) *auth.AuthResult {
	t.Helper()
	res, err := f.auth.SignUp(context.Background(), auth.SignUpInput{Email: email, Password: pw})
	if err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	return res
}

func lastToken(t *testing.T, s *mememail.Sender) string {
	t.Helper()
	m, ok := s.Last()
	if !ok {
		t.Fatal("no email sent")
	}
	lines := strings.Split(strings.TrimSpace(m.Text), "\n")
	for _, l := range lines {
		if l = strings.TrimSpace(l); len(l) == 43 { // base64url(32 bytes)
			return l
		}
	}
	t.Fatalf("token not found in %q", m.Text)
	return ""
}

func TestNewRequiresAdapter(t *testing.T) {
	if _, err := auth.New(auth.Config{}); !errors.Is(err, auth.ErrAdapterRequired) {
		t.Fatalf("want ErrAdapterRequired, got %v", err)
	}
}

func TestMinimalConfigWorksWithoutCache(t *testing.T) {
	ctx := context.Background()
	a, err := auth.New(auth.Config{Adapter: adaptermem.New(), Hasher: fastHasher})
	if err != nil {
		t.Fatal(err)
	}
	res, err := a.SignUp(ctx, auth.SignUpInput{Email: "a@b.co", Password: "password1"})
	if err != nil {
		t.Fatal(err)
	}
	got, err := a.RequireSession(ctx, res.Token)
	if err != nil || got.User.ID != res.User.ID {
		t.Fatalf("RequireSession: %v %+v", err, got)
	}
}

func TestSignUpSignInSignOut(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, nil)

	up := mustSignUp(t, f, "  Gopher@Example.com ", "correct horse")
	if up.User.Email != "gopher@example.com" {
		t.Fatalf("email not normalized: %q", up.User.Email)
	}
	if up.Token == "" || up.Session == nil {
		t.Fatal("sign up should issue a session")
	}
	stored, err := f.adapter.FindOne(ctx, schema.ModelSessions, []adapter.Condition{adapter.Eq("id", up.Session.ID)})
	if err != nil {
		t.Fatalf("session not found in adapter: %v", err)
	}
	tokenHash, _ := stored["token_hash"].(string)
	if tokenHash == up.Token || strings.Contains(tokenHash, up.Token) {
		t.Fatal("plaintext token must never be stored")
	}

	if _, err := f.auth.SignUp(ctx, auth.SignUpInput{Email: "gopher@example.com", Password: "another pw"}); !errors.Is(err, auth.ErrEmailAlreadyExists) {
		t.Fatalf("want ErrEmailAlreadyExists, got %v", err)
	}

	if _, err := f.auth.SignIn(ctx, auth.SignInInput{Email: "gopher@example.com", Password: "wrong pass"}); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("wrong password: %v", err)
	}
	if _, err := f.auth.SignIn(ctx, auth.SignInInput{Email: "nobody@example.com", Password: "whatever1"}); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("unknown user: %v", err)
	}

	in, err := f.auth.SignIn(ctx, auth.SignInInput{Email: "GOPHER@example.com", Password: "correct horse"})
	if err != nil {
		t.Fatal(err)
	}
	res, err := f.auth.RequireSession(ctx, in.Token)
	if err != nil {
		t.Fatal(err)
	}
	if p := res.Principal(); p.Subject != up.User.ID || p.Type != auth.PrincipalUser {
		t.Fatalf("unexpected principal %+v", p)
	}

	if err := f.auth.SignOut(ctx, auth.SignOutInput{Token: in.Token}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.auth.RequireSession(ctx, in.Token); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatalf("session must be revoked immediately, got %v", err)
	}
	if err := f.auth.SignOut(ctx, auth.SignOutInput{Token: in.Token}); err != nil {
		t.Fatalf("SignOut must be idempotent: %v", err)
	}
	// The other session remains valid.
	if _, err := f.auth.RequireSession(ctx, up.Token); err != nil {
		t.Fatalf("unrelated session revoked: %v", err)
	}
}

func TestPasswordPolicyAndEmailValidation(t *testing.T) {
	f := newFixture(t, nil)
	ctx := context.Background()
	if _, err := f.auth.SignUp(ctx, auth.SignUpInput{Email: "x@y.co", Password: "short"}); !errors.Is(err, auth.ErrInvalidPassword) {
		t.Fatalf("want ErrInvalidPassword, got %v", err)
	}
	if _, err := f.auth.SignUp(ctx, auth.SignUpInput{Email: "not-an-email", Password: "long enough"}); !errors.Is(err, auth.ErrInvalidEmail) {
		t.Fatalf("want ErrInvalidEmail, got %v", err)
	}
}

func TestSessionExpiry(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, func(c *auth.Config) { c.Session.TTL = time.Hour })
	up := mustSignUp(t, f, "e@x.co", "password1")

	f.clock.Advance(59 * time.Minute)
	if res, _ := f.auth.GetSession(ctx, up.Token); res == nil {
		t.Fatal("session should still be valid")
	}
	f.clock.Advance(time.Minute)
	if res, err := f.auth.GetSession(ctx, up.Token); res != nil || err != nil {
		t.Fatalf("expired session must not resolve: %+v %v", res, err)
	}
}

func TestSessionCacheAsideAndInvalidation(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, nil)
	up := mustSignUp(t, f, "c@x.co", "password1")

	sc := cache.NewSessionCache(f.cache)
	cached, err := sc.Get(ctx, up.Session.TokenHash)
	if err != nil || cached.ID != up.Session.ID {
		t.Fatalf("session should be cached after creation: %v", err)
	}

	// Adapter is the source of truth: revoke directly in the adapter, the cache
	// still serves the stale entry (bounded by CacheTTL) ...
	if _, err := f.adapter.Update(ctx, schema.ModelSessions, []adapter.Condition{adapter.Eq("id", up.Session.ID)}, map[string]any{"revoked_at": f.clock.Now()}); err != nil {
		t.Fatal(err)
	}
	if res, _ := f.auth.GetSession(ctx, up.Token); res == nil {
		t.Fatal("expected stale cache hit when bypassing the core")
	}
	// ... which is why the core always invalidates after critical mutations.
	if err := f.auth.RevokeSession(ctx, up.Session.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := sc.Get(ctx, up.Session.TokenHash); !errors.Is(err, cache.ErrMiss) {
		t.Fatalf("cache entry must be deleted, got %v", err)
	}
	if res, _ := f.auth.GetSession(ctx, up.Token); res != nil {
		t.Fatal("revoked session resolved")
	}
}

func TestSessionCacheTTLNeverExceedsSessionLifetime(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, func(c *auth.Config) {
		c.Session.TTL = 2 * time.Minute
		c.Session.CacheTTL = time.Hour
	})
	up := mustSignUp(t, f, "ttl@x.co", "password1")
	f.clock.Advance(2 * time.Minute)
	if _, err := cache.NewSessionCache(f.cache).Get(ctx, up.Session.TokenHash); !errors.Is(err, cache.ErrMiss) {
		t.Fatalf("cache entry outlived session: %v", err)
	}
}

type brokenCache struct{}

func (brokenCache) Get(context.Context, string, any) error { return errors.New("redis down") }
func (brokenCache) Set(context.Context, string, any, time.Duration) error {
	return errors.New("redis down")
}
func (brokenCache) Delete(context.Context, string) error { return errors.New("redis down") }

func TestCacheFailureDegradesToStore(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, func(c *auth.Config) { c.Cache = brokenCache{} })
	up := mustSignUp(t, f, "down@x.co", "password1")
	if _, err := f.auth.RequireSession(ctx, up.Token); err != nil {
		t.Fatalf("auth must keep working when cache is down: %v", err)
	}
	if err := f.auth.SignOut(ctx, auth.SignOutInput{Token: up.Token}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.auth.RequireSession(ctx, up.Token); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatalf("got %v", err)
	}
}

func TestTransactionRollbackOnHookVeto(t *testing.T) {
	ctx := context.Background()
	veto := errors.New("vetoed")
	f := newFixture(t, nil)
	f.auth.Hooks().BeforeSessionCreate(func(ctx context.Context, s *session.Session) error { return veto })

	if _, err := f.auth.SignUp(ctx, auth.SignUpInput{Email: "tx@x.co", Password: "password1"}); !errors.Is(err, veto) {
		t.Fatalf("want veto, got %v", err)
	}
	if _, err := f.adapter.FindOne(ctx, schema.ModelUsers, []adapter.Condition{adapter.Eq("email", "tx@x.co")}); !errors.Is(err, adapter.ErrNotFound) {
		t.Fatalf("user must be rolled back, got %v", err)
	}
}

func TestEmailVerificationRequired(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, func(c *auth.Config) {
		c.EmailVerification.Required = true
		c.EmailVerification.SendOnSignUp = true
	})
	var verified []string
	f.auth.Events().Subscribe(auth.EventEmailVerified, func(_ context.Context, e auth.Event) {
		verified = append(verified, e.Subject)
	})

	up := mustSignUp(t, f, "v@x.co", "password1")
	if up.Session != nil || up.Token != "" {
		t.Fatal("no session before verification")
	}
	if _, err := f.auth.SignIn(ctx, auth.SignInInput{Email: "v@x.co", Password: "password1"}); !errors.Is(err, auth.ErrEmailNotVerified) {
		t.Fatalf("want ErrEmailNotVerified, got %v", err)
	}
	token := lastToken(t, f.email)
	u, err := f.auth.VerifyEmail(ctx, auth.VerifyEmailInput{Token: token})
	if err != nil || !u.EmailVerified {
		t.Fatalf("VerifyEmail: %v", err)
	}
	if _, err := f.auth.VerifyEmail(ctx, auth.VerifyEmailInput{Token: token}); !errors.Is(err, auth.ErrInvalidToken) {
		t.Fatalf("token must be single-use, got %v", err)
	}
	if _, err := f.auth.SignIn(ctx, auth.SignInInput{Email: "v@x.co", Password: "password1"}); err != nil {
		t.Fatal(err)
	}
	if len(verified) != 1 || verified[0] != up.User.ID {
		t.Fatalf("EmailVerified event not published: %v", verified)
	}
}

func TestPasswordResetRevokesAllSessions(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, nil)
	up := mustSignUp(t, f, "r@x.co", "old password")

	if err := f.auth.RequestPasswordReset(ctx, auth.RequestPasswordResetInput{Email: "unknown@x.co"}); err != nil {
		t.Fatalf("unknown email must not error: %v", err)
	}
	if len(f.email.Messages()) != 0 {
		t.Fatal("no email for unknown users")
	}
	if err := f.auth.RequestPasswordReset(ctx, auth.RequestPasswordResetInput{Email: "r@x.co"}); err != nil {
		t.Fatal(err)
	}
	token := lastToken(t, f.email)

	if err := f.auth.ResetPassword(ctx, auth.ResetPasswordInput{Token: token, NewPassword: "x"}); !errors.Is(err, auth.ErrInvalidPassword) {
		t.Fatalf("policy first: %v", err)
	}
	if err := f.auth.ResetPassword(ctx, auth.ResetPasswordInput{Token: token, NewPassword: "new password"}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.auth.RequireSession(ctx, up.Token); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatalf("sessions must be revoked after reset: %v", err)
	}
	if _, err := f.auth.SignIn(ctx, auth.SignInInput{Email: "r@x.co", Password: "old password"}); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatal("old password must not work")
	}
	if _, err := f.auth.SignIn(ctx, auth.SignInInput{Email: "r@x.co", Password: "new password"}); err != nil {
		t.Fatal(err)
	}
	if err := f.auth.ResetPassword(ctx, auth.ResetPasswordInput{Token: token, NewPassword: "third password"}); !errors.Is(err, auth.ErrInvalidToken) {
		t.Fatalf("reset token must be single-use: %v", err)
	}
}

func TestResetTokenExpires(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, func(c *auth.Config) { c.PasswordReset.TokenTTL = time.Minute })
	mustSignUp(t, f, "exp@x.co", "password1")
	if err := f.auth.RequestPasswordReset(ctx, auth.RequestPasswordResetInput{Email: "exp@x.co"}); err != nil {
		t.Fatal(err)
	}
	f.clock.Advance(time.Minute)
	if err := f.auth.ResetPassword(ctx, auth.ResetPasswordInput{Token: lastToken(t, f.email), NewPassword: "password2"}); !errors.Is(err, auth.ErrInvalidToken) {
		t.Fatalf("want ErrInvalidToken, got %v", err)
	}
}

func TestChangePasswordKeepsCurrentSession(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, nil)
	first := mustSignUp(t, f, "cp@x.co", "password1")
	second, err := f.auth.SignIn(ctx, auth.SignInInput{Email: "cp@x.co", Password: "password1"})
	if err != nil {
		t.Fatal(err)
	}
	err = f.auth.ChangePassword(ctx, auth.ChangePasswordInput{
		UserID: first.User.ID, CurrentPassword: "password1", NewPassword: "password2",
		CurrentSessionID: second.Session.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.auth.RequireSession(ctx, second.Token); err != nil {
		t.Fatalf("current session must survive: %v", err)
	}
	if _, err := f.auth.RequireSession(ctx, first.Token); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatalf("other sessions must be revoked: %v", err)
	}
	if err := f.auth.ChangePassword(ctx, auth.ChangePasswordInput{
		UserID: first.User.ID, CurrentPassword: "password1", NewPassword: "password3",
	}); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("want ErrInvalidCredentials, got %v", err)
	}
}

func TestGetAndRequireUser(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, nil)
	up := mustSignUp(t, f, "u@x.co", "password1")
	if u, err := f.auth.RequireUser(ctx, up.User.ID); err != nil || u.Email != "u@x.co" {
		t.Fatalf("RequireUser: %v", err)
	}
	if u, err := f.auth.GetUser(ctx, "missing"); u != nil || err != nil {
		t.Fatalf("GetUser(missing) = %v, %v", u, err)
	}
	if _, err := f.auth.RequireUser(ctx, "missing"); !errors.Is(err, auth.ErrUserNotFound) {
		t.Fatalf("got %v", err)
	}
}

func TestHooksCanMutateAndObserve(t *testing.T) {
	f := newFixture(t, nil)
	var created []*user.User
	f.auth.Hooks().BeforeSignUp(func(_ context.Context, in *auth.SignUpInput) error {
		in.Email = strings.ReplaceAll(in.Email, "+spam", "")
		return nil
	})
	f.auth.Hooks().AfterUserCreate(func(_ context.Context, u *user.User) { created = append(created, u) })
	up := mustSignUp(t, f, "me+spam@x.co", "password1")
	if up.User.Email != "me@x.co" || len(created) != 1 {
		t.Fatalf("hooks not applied: %q %d", up.User.Email, len(created))
	}
}

func TestEventHandlerPanicDoesNotBreakFlow(t *testing.T) {
	f := newFixture(t, nil)
	f.auth.Events().SubscribeAll(func(context.Context, auth.Event) { panic("boom") })
	mustSignUp(t, f, "p@x.co", "password1")
}

func TestPurgeExpired(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, func(c *auth.Config) { c.Session.TTL = time.Minute })
	mustSignUp(t, f, "purge@x.co", "password1")
	f.clock.Advance(2 * time.Minute)
	n, _, err := f.auth.PurgeExpired(ctx)
	if err != nil || n != 1 {
		t.Fatalf("PurgeExpired = %d, %v", n, err)
	}
}

type schemaTestPlugin struct {
	registered bool
}

func (p *schemaTestPlugin) ID() string { return "schema_test_plugin" }

func (p *schemaTestPlugin) RegisterSchema(s *schema.Schema) error {
	p.registered = true
	// Extend users
	if err := s.ExtendModel(schema.ModelUsers, schema.Field{
		Name:    "two_factor_enabled",
		Type:    schema.TypeBool,
		Default: false,
	}); err != nil {
		return err
	}
	// Add new model
	m := schema.NewModel("two_factors", "two_factors", "id")
	_ = m.AddField(schema.Field{Name: "id", Type: schema.TypeString, Required: true})
	_ = m.AddField(schema.Field{
		Name:     "user_id",
		Type:     schema.TypeString,
		Required: true,
		References: &schema.Reference{
			Model:    schema.ModelUsers,
			Field:    "id",
			OnDelete: "CASCADE",
		},
	})
	return s.AddModel(m)
}

func (p *schemaTestPlugin) Init(h *auth.Host) error {
	if h.Adapter() == nil {
		return errors.New("expected adapter on host")
	}
	if h.Schema() == nil {
		return errors.New("expected schema on host")
	}
	return nil
}

func TestAdapterDrivenAuthAndSchemaProvider(t *testing.T) {
	ctx := context.Background()
	memAdapter := adaptermem.New()
	plugin := &schemaTestPlugin{}

	engine, err := auth.New(auth.Config{
		Adapter: memAdapter,
		Hasher:  fastHasher,
		Plugins: []auth.PluginModule{plugin},
	})
	if err != nil {
		t.Fatalf("auth.New with Adapter failed: %v", err)
	}

	if !plugin.registered {
		t.Fatal("expected plugin.RegisterSchema to be called")
	}

	// Verify authentication workflow works transparently over generic adapter
	res, err := engine.SignUp(ctx, auth.SignUpInput{
		Email:    "adapter_user@example.com",
		Password: "SecurePassword123!",
	})
	if err != nil {
		t.Fatalf("SignUp on adapter failed: %v", err)
	}
	if res.User.Email != "adapter_user@example.com" {
		t.Errorf("expected adapter_user@example.com, got %v", res.User.Email)
	}

	// Sign In
	signInRes, err := engine.SignIn(ctx, auth.SignInInput{
		Email:    "adapter_user@example.com",
		Password: "SecurePassword123!",
	})
	if err != nil {
		t.Fatalf("SignIn on adapter failed: %v", err)
	}
	if signInRes.Session == nil {
		t.Fatal("expected session from SignIn")
	}

	// Require Session
	sessionRes, err := engine.RequireSession(ctx, signInRes.Token)
	if err != nil {
		t.Fatalf("RequireSession failed: %v", err)
	}
	if sessionRes.User.ID != res.User.ID {
		t.Errorf("user ID mismatch: %v vs %v", sessionRes.User.ID, res.User.ID)
	}
}

