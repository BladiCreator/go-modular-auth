package mock

import (
	"context"
	"math/rand"
	"strconv"
	"sync"
	"time"

	"github.com/BladiCreator/go-modular-auth/domain"
	"github.com/BladiCreator/go-modular-auth/domain/dto"
	"github.com/BladiCreator/go-modular-auth/domain/entity"
	"github.com/BladiCreator/go-modular-auth/plugins/emailpassword"
	"github.com/BladiCreator/go-modular-auth/plugins/twofactor"
)

var (
	_ emailpassword.Repository = (*MockRepo)(nil)
	_ twofactor.Repository     = (*MockRepo)(nil)
)

type MockRepo struct {
	mu          sync.RWMutex
	users       map[string]*entity.User
	accounts    map[string]*entity.Account            // key: accountID
	userAccounts map[string]map[string]*entity.Account // key: userID -> provider -> Account
	tokens      map[string]*entity.VerificationToken  // key: token string
	sessions    map[string]*entity.Session
	totpSecrets map[string]string
}

func NewMockRepo() *MockRepo {
	return &MockRepo{
		users:        make(map[string]*entity.User),
		accounts:     make(map[string]*entity.Account),
		userAccounts: make(map[string]map[string]*entity.Account),
		tokens:       make(map[string]*entity.VerificationToken),
		sessions:     make(map[string]*entity.Session),
		totpSecrets:  make(map[string]string),
	}
}

// User Methods
func (m *MockRepo) CreateUser(ctx context.Context, u *entity.User) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if u.ID == "" {
		u.ID = "usr_" + strconv.FormatInt(rand.Int63(), 10)
	}
	u.CreatedAt = time.Now()
	u.UpdatedAt = time.Now()

	m.users[u.ID] = u
	return nil
}

func (m *MockRepo) GetUserByEmail(ctx context.Context, email string) (*entity.User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, u := range m.users {
		if u.Email == email {
			return u, nil
		}
	}
	return nil, domain.ErrUserNotFound
}

func (m *MockRepo) GetUserByID(ctx context.Context, id string) (*entity.User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if u, ok := m.users[id]; ok {
		return u, nil
	}
	return nil, domain.ErrUserNotFound
}

func (m *MockRepo) UpdateUser(ctx context.Context, u *entity.User) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.users[u.ID]; !ok {
		return domain.ErrUserNotFound
	}
	u.UpdatedAt = time.Now()
	m.users[u.ID] = u
	return nil
}

// Account Methods
func (m *MockRepo) CreateAccount(ctx context.Context, account *entity.Account) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if account.ID == "" {
		account.ID = "acc_" + strconv.FormatInt(rand.Int63(), 10)
	}
	account.CreatedAt = time.Now()
	account.UpdatedAt = time.Now()

	m.accounts[account.ID] = account
	if _, ok := m.userAccounts[account.UserID]; !ok {
		m.userAccounts[account.UserID] = make(map[string]*entity.Account)
	}
	m.userAccounts[account.UserID][account.Provider] = account
	return nil
}

func (m *MockRepo) GetAccountByUserIDAndProvider(ctx context.Context, userID, provider string) (*entity.Account, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if providers, ok := m.userAccounts[userID]; ok {
		if acc, ok := providers[provider]; ok {
			return acc, nil
		}
	}
	return nil, emailpassword.ErrAccountNotFound
}

func (m *MockRepo) UpdateAccountPassword(ctx context.Context, accountID, hashedPassword string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	acc, ok := m.accounts[accountID]
	if !ok {
		return emailpassword.ErrAccountNotFound
	}
	acc.Password = hashedPassword
	acc.UpdatedAt = time.Now()
	return nil
}

// Verification Token Methods
func (m *MockRepo) CreateVerificationToken(ctx context.Context, token *entity.VerificationToken) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.tokens[token.Token] = token
	return nil
}

func (m *MockRepo) GetVerificationToken(ctx context.Context, token string) (*entity.VerificationToken, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if t, ok := m.tokens[token]; ok {
		return t, nil
	}
	return nil, emailpassword.ErrInvalidToken
}

func (m *MockRepo) DeleteVerificationToken(ctx context.Context, token string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.tokens, token)
	return nil
}

// Session Methods
func (m *MockRepo) CreateSession(ctx context.Context, sessionCtx *dto.CreateSessionContext) (*entity.Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	sess := &entity.Session{
		ID:        "sess_" + strconv.FormatInt(rand.Int63(), 10),
		UserID:    sessionCtx.UserID,
		Token:     sessionCtx.Token,
		IPAddress: sessionCtx.IPAddress,
		UserAgent: sessionCtx.UserAgent,
		ExpiresAt: sessionCtx.ExpiresAt,
		CreatedAt: sessionCtx.CreatedAt,
	}
	m.sessions[sess.Token] = sess
	return sess, nil
}

func (m *MockRepo) GetSessionByToken(ctx context.Context, token string) (*entity.Session, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if sess, ok := m.sessions[token]; ok {
		return sess, nil
	}
	return nil, domain.ErrSessionNotFound
}

func (m *MockRepo) DeleteSession(ctx context.Context, token string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.sessions, token)
	return nil
}

// 2FA TOTP Methods
func (m *MockRepo) SaveTOTPSecret(ctx context.Context, userID string, secret string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.totpSecrets[userID] = secret
	return nil
}

func (m *MockRepo) GetTOTPSecret(ctx context.Context, userID string) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if sec, ok := m.totpSecrets[userID]; ok {
		return sec, nil
	}
	return "", domain.ErrTOTPNotFound
}
