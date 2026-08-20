package username_test

import (
	"context"
	"errors"
	"testing"

	"github.com/BladiCreator/go-modular-auth/domain/dto"
	"github.com/BladiCreator/go-modular-auth/domain/entity"
	"github.com/BladiCreator/go-modular-auth/plugin"
	"github.com/BladiCreator/go-modular-auth/plugins/username"
	"golang.org/x/crypto/bcrypt"
)

// MockRepository implements username.Repository for testing purposes.
type MockRepository struct {
	users    map[string]*entity.User    // key: ID
	byName   map[string]*entity.User    // key: normalized username
	accounts map[string]*entity.Account // key: userID
	sessions map[string]*entity.Session // key: token
}

func NewMockRepository() *MockRepository {
	return &MockRepository{
		users:    make(map[string]*entity.User),
		byName:   make(map[string]*entity.User),
		accounts: make(map[string]*entity.Account),
		sessions: make(map[string]*entity.Session),
	}
}

func (m *MockRepository) AddUser(u *entity.User, password string) error {
	m.users[u.ID] = u
	if u.Username != "" {
		m.byName[u.Username] = u
	}
	if password != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
		if err != nil {
			return err
		}
		m.accounts[u.ID] = &entity.Account{
			ID:       "acc_" + u.ID,
			UserID:   u.ID,
			Provider: username.CredentialProvider,
			Password: string(hash),
		}
	}
	return nil
}

func (m *MockRepository) GetUserByUsername(ctx context.Context, name string) (*entity.User, error) {
	if u, ok := m.byName[name]; ok {
		return u, nil
	}
	return nil, username.ErrUserNotFound
}

func (m *MockRepository) GetUserByID(ctx context.Context, userID string) (*entity.User, error) {
	if u, ok := m.users[userID]; ok {
		return u, nil
	}
	return nil, username.ErrUserNotFound
}

func (m *MockRepository) IsUsernameAvailable(ctx context.Context, name string) (bool, error) {
	_, ok := m.byName[name]
	return !ok, nil
}

func (m *MockRepository) UpdateUsername(ctx context.Context, userID, newUsername, displayUsername string) error {
	u, ok := m.users[userID]
	if !ok {
		return username.ErrUserNotFound
	}
	if u.Username != "" {
		delete(m.byName, u.Username)
	}
	u.Username = newUsername
	u.DisplayUsername = displayUsername
	m.byName[newUsername] = u
	return nil
}

func (m *MockRepository) GetAccountByUserIDAndProvider(ctx context.Context, userID, providerID string) (*entity.Account, error) {
	if acc, ok := m.accounts[userID]; ok && acc.Provider == providerID {
		return acc, nil
	}
	return nil, username.ErrCredentialAccountNotFound
}

func (m *MockRepository) CreateSession(ctx context.Context, params *dto.CreateSessionParams) (*entity.Session, error) {
	sess := &entity.Session{
		ID:        "sess_" + params.Token,
		UserID:    params.UserID,
		Token:     params.Token,
		ExpiresAt: params.ExpiresAt,
	}
	m.sessions[params.Token] = sess
	return sess, nil
}

// Unit Tests

func TestUsername_PluginIDAndInit(t *testing.T) {
	repo := NewMockRepository()
	p := username.New(repo)

	if p.ID() != "username" {
		t.Fatalf("expected plugin ID 'username', got '%s'", p.ID())
	}

	ctx := plugin.NewContext(nil, nil)
	if err := p.Init(ctx); err != nil {
		t.Fatalf("unexpected error initializing plugin: %v", err)
	}
}

func TestUsername_Normalize(t *testing.T) {
	repo := NewMockRepository()

	// Default normalization (strings.ToLower + TrimSpace)
	p1 := username.New(repo)
	if res := p1.Normalize("  John_Doe.99 "); res != "john_doe.99" {
		t.Errorf("expected 'john_doe.99', got '%s'", res)
	}

	// Normalization disabled
	p2 := username.New(repo, username.WithNormalization(false))
	if res := p2.Normalize("  John_Doe.99 "); res != "John_Doe.99" {
		t.Errorf("expected 'John_Doe.99', got '%s'", res)
	}
}

func TestUsername_ValidateUsername(t *testing.T) {
	repo := NewMockRepository()
	ctx := context.Background()

	p := username.New(repo,
		username.WithMinLength(4),
		username.WithMaxLength(15),
	)

	// Valid username
	if err := p.ValidateUsername(ctx, "gopher123"); err != nil {
		t.Errorf("unexpected error for valid username: %v", err)
	}

	// Too short
	if err := p.ValidateUsername(ctx, "abc"); !errors.Is(err, username.ErrUsernameTooShort) {
		t.Errorf("expected ErrUsernameTooShort, got %v", err)
	}

	// Too long
	if err := p.ValidateUsername(ctx, "this_is_a_very_long_username_exceeding_max"); !errors.Is(err, username.ErrUsernameTooLong) {
		t.Errorf("expected ErrUsernameTooLong, got %v", err)
	}

	// Invalid format / special chars
	if err := p.ValidateUsername(ctx, "user@domain"); !errors.Is(err, username.ErrInvalidUsername) {
		t.Errorf("expected ErrInvalidUsername, got %v", err)
	}

	// Custom validator
	errCustom := errors.New("reserved word")
	pCustom := username.New(repo, username.WithCustomValidator(func(ctx context.Context, u string) error {
		if u == "admin" {
			return errCustom
		}
		return nil
	}))

	if err := pCustom.ValidateUsername(ctx, "admin"); !errors.Is(err, errCustom) {
		t.Errorf("expected errCustom, got %v", err)
	}
}

func TestUsername_IsAvailable(t *testing.T) {
	repo := NewMockRepository()
	ctx := context.Background()

	_ = repo.AddUser(&entity.User{
		ID:       "usr_1",
		Username: "gopher",
	}, "password123")

	p := username.New(repo)

	// Available username
	res, err := p.IsAvailable(ctx, "new_user")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Available {
		t.Errorf("expected new_user to be available")
	}

	// Taken username
	res, err = p.IsAvailable(ctx, "Gopher") // tests case-insensitive check
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Available {
		t.Errorf("expected gopher to be unavailable")
	}
}

func TestUsername_ProcessSignUpUsername(t *testing.T) {
	repo := NewMockRepository()
	ctx := context.Background()

	_ = repo.AddUser(&entity.User{
		ID:       "usr_existing",
		Username: "existing_user",
	}, "password123")

	p := username.New(repo)

	// Normal registration with display username fallback
	norm, disp, err := p.ProcessSignUpUsername(ctx, "  Alex_Dev  ", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if norm != "alex_dev" {
		t.Errorf("expected norm 'alex_dev', got '%s'", norm)
	}
	if disp != "  Alex_Dev  " && disp != "Alex_Dev" {
		t.Errorf("expected fallback display username, got '%s'", disp)
	}

	// Duplicate username registration
	_, _, err = p.ProcessSignUpUsername(ctx, "Existing_User", "Display Name")
	if !errors.Is(err, username.ErrUsernameAlreadyTaken) {
		t.Errorf("expected ErrUsernameAlreadyTaken, got %v", err)
	}
}

func TestUsername_SignIn(t *testing.T) {
	repo := NewMockRepository()
	ctx := context.Background()

	_ = repo.AddUser(&entity.User{
		ID:            "usr_2",
		Email:         "gopher@example.com",
		Username:      "gopher_coder",
		EmailVerified: true,
	}, "SecretPass123!")

	p := username.New(repo)

	// Successful sign in (case-insensitive)
	res, err := p.SignIn(ctx, username.SignInUsernameParams{
		Username: "Gopher_Coder",
		Password: "SecretPass123!",
	})
	if err != nil {
		t.Fatalf("unexpected sign in error: %v", err)
	}
	if res.User.ID != "usr_2" {
		t.Errorf("expected user ID 'usr_2', got '%s'", res.User.ID)
	}
	if res.SessionToken == "" {
		t.Errorf("expected non-empty session token")
	}

	// Wrong password
	_, err = p.SignIn(ctx, username.SignInUsernameParams{
		Username: "gopher_coder",
		Password: "WrongPassword",
	})
	if !errors.Is(err, username.ErrInvalidUsernameOrPassword) {
		t.Errorf("expected ErrInvalidUsernameOrPassword, got %v", err)
	}

	// Nonexistent user (timing attack dummy check path)
	_, err = p.SignIn(ctx, username.SignInUsernameParams{
		Username: "non_existent_user",
		Password: "SomePassword123!",
	})
	if !errors.Is(err, username.ErrInvalidUsernameOrPassword) {
		t.Errorf("expected ErrInvalidUsernameOrPassword, got %v", err)
	}
}

func TestUsername_SignIn_EmailVerificationRequired(t *testing.T) {
	repo := NewMockRepository()
	ctx := context.Background()

	_ = repo.AddUser(&entity.User{
		ID:            "usr_unverified",
		Email:         "unverified@example.com",
		Username:      "unverified_gopher",
		EmailVerified: false,
	}, "SecretPass123!")

	p := username.New(repo, username.WithRequireEmailVerification(true))

	_, err := p.SignIn(ctx, username.SignInUsernameParams{
		Username: "unverified_gopher",
		Password: "SecretPass123!",
	})
	if !errors.Is(err, username.ErrEmailNotVerified) {
		t.Errorf("expected ErrEmailNotVerified, got %v", err)
	}
}

func TestUsername_UpdateUsername(t *testing.T) {
	repo := NewMockRepository()
	ctx := context.Background()

	_ = repo.AddUser(&entity.User{
		ID:       "usr_update",
		Username: "old_username",
	}, "Password123!")

	_ = repo.AddUser(&entity.User{
		ID:       "usr_other",
		Username: "taken_username",
	}, "Password123!")

	p := username.New(repo)

	// Successful update
	res, err := p.UpdateUsername(ctx, username.UpdateUsernameParams{
		UserID:          "usr_update",
		Username:        "new_awesome_name",
		DisplayUsername: "Awesome Name",
	})
	if err != nil {
		t.Fatalf("unexpected update error: %v", err)
	}
	if res.User.Username != "new_awesome_name" {
		t.Errorf("expected updated username 'new_awesome_name', got '%s'", res.User.Username)
	}

	// Update to taken username
	_, err = p.UpdateUsername(ctx, username.UpdateUsernameParams{
		UserID:   "usr_update",
		Username: "taken_username",
	})
	if !errors.Is(err, username.ErrUsernameAlreadyTaken) {
		t.Errorf("expected ErrUsernameAlreadyTaken, got %v", err)
	}
}
