// Package memory provides an in-memory repository implementation suitable for development and testing.
package memory

import (
	"context"
	"math/rand"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/BladiCreator/go-modular-auth/domain"
	"github.com/BladiCreator/go-modular-auth/domain/dto"
	"github.com/BladiCreator/go-modular-auth/domain/entity"
	"github.com/BladiCreator/go-modular-auth/plugins/bearer"
	"github.com/BladiCreator/go-modular-auth/plugins/emailpassword"
	"github.com/BladiCreator/go-modular-auth/plugins/jwt"
	"github.com/BladiCreator/go-modular-auth/plugins/twofactor"
)

var (
	_ emailpassword.Repository = (*Store)(nil)
	_ twofactor.Repository     = (*Store)(nil)
	_ bearer.Repository        = (*Store)(nil)
	_ jwt.Repository           = (*Store)(nil)
)

// Store is a thread-safe in-memory implementation of authentication storage interfaces.
type Store struct {
	mu            sync.RWMutex
	users         map[string]*entity.User
	accounts      map[string]*entity.Account            // key: accountID
	userAccounts  map[string]map[string]*entity.Account // key: userID -> provider -> Account
	tokens        map[string]*entity.VerificationToken  // key: token string
	sessions      map[string]*entity.Session
	totpSecrets   map[string]string
	twoFactors    map[string]*twofactor.TwoFactor    // key: userID
	otpChallenges map[string]*twofactor.OTPChallenge // key: challenge key
	jwks          map[string]*jwt.JWKRecord          // key: kid
}

// New instantiates a new thread-safe in-memory Store.
func New() *Store {
	return &Store{
		users:         make(map[string]*entity.User),
		accounts:      make(map[string]*entity.Account),
		userAccounts:  make(map[string]map[string]*entity.Account),
		tokens:        make(map[string]*entity.VerificationToken),
		sessions:      make(map[string]*entity.Session),
		totpSecrets:   make(map[string]string),
		twoFactors:    make(map[string]*twofactor.TwoFactor),
		otpChallenges: make(map[string]*twofactor.OTPChallenge),
		jwks:          make(map[string]*jwt.JWKRecord),
	}
}

// User Methods
func (s *Store) CreateUser(ctx context.Context, params *dto.CreateUserParams) (*entity.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	user := &entity.User{
		ID:        "memory:" + strconv.FormatInt(rand.Int63(), 10),
		Name:      params.Name,
		Email:     params.Email,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	s.users[user.ID] = user
	return user, nil
}

func (s *Store) GetUserByEmail(ctx context.Context, email string) (*entity.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.users {
		if u.Email == email {
			return u, nil
		}
	}
	return nil, domain.ErrUserNotFound
}

func (s *Store) GetUserByID(ctx context.Context, id string) (*entity.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if u, ok := s.users[id]; ok {
		return u, nil
	}
	return nil, domain.ErrUserNotFound
}

func (s *Store) UpdateUser(ctx context.Context, user *entity.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.users[user.ID]; !ok {
		return domain.ErrUserNotFound
	}
	user.UpdatedAt = time.Now()
	s.users[user.ID] = user
	return nil
}

// Account Methods
func (s *Store) CreateAccount(ctx context.Context, account *entity.Account) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if account.ID == "" {
		account.ID = "acc_" + strconv.FormatInt(rand.Int63(), 10)
	}
	account.CreatedAt = time.Now()
	account.UpdatedAt = time.Now()

	s.accounts[account.ID] = account
	if _, ok := s.userAccounts[account.UserID]; !ok {
		s.userAccounts[account.UserID] = make(map[string]*entity.Account)
	}
	s.userAccounts[account.UserID][account.Provider] = account
	return nil
}

func (s *Store) GetAccountByUserIDAndProvider(ctx context.Context, userID, provider string) (*entity.Account, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if providers, ok := s.userAccounts[userID]; ok {
		if acc, ok := providers[provider]; ok {
			return acc, nil
		}
	}
	return nil, emailpassword.ErrAccountNotFound
}

func (s *Store) UpdateAccountPassword(ctx context.Context, accountID, hashedPassword string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	acc, ok := s.accounts[accountID]
	if !ok {
		return emailpassword.ErrAccountNotFound
	}
	acc.Password = hashedPassword
	acc.UpdatedAt = time.Now()
	return nil
}

// Verification Token Methods
func (s *Store) CreateVerificationToken(ctx context.Context, token *entity.VerificationToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.tokens[token.Token] = token
	return nil
}

func (s *Store) GetVerificationToken(ctx context.Context, token string) (*entity.VerificationToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if t, ok := s.tokens[token]; ok {
		return t, nil
	}
	return nil, emailpassword.ErrInvalidToken
}

func (s *Store) DeleteVerificationToken(ctx context.Context, token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.tokens, token)
	return nil
}

// Session Methods
func (s *Store) CreateSession(ctx context.Context, session *dto.CreateSessionParams) (*entity.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sessionCreated := &entity.Session{
		ID:        "memory:" + strconv.FormatInt(rand.Int63(), 10),
		UserID:    session.UserID,
		Token:     session.Token,
		IPAddress: session.IPAddress,
		UserAgent: session.UserAgent,
		ExpiresAt: session.ExpiresAt,
		CreatedAt: session.CreatedAt,
	}
	s.sessions[session.Token] = sessionCreated
	return sessionCreated, nil
}

func (s *Store) GetSessionByToken(ctx context.Context, token string) (*entity.Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if sess, ok := s.sessions[token]; ok {
		return sess, nil
	}
	return nil, domain.ErrSessionNotFound
}

func (s *Store) DeleteSession(ctx context.Context, token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, token)
	return nil
}

// 2FA TOTP Methods
func (s *Store) SaveTOTPSecret(ctx context.Context, userID string, secret string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.totpSecrets[userID] = secret
	return nil
}

func (s *Store) GetTOTPSecret(ctx context.Context, userID string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if sec, ok := s.totpSecrets[userID]; ok {
		return sec, nil
	}
	return "", domain.ErrTOTPNotFound
}

func (s *Store) FindByUserID(ctx context.Context, userID string) (*twofactor.TwoFactor, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if tf, ok := s.twoFactors[userID]; ok {
		return tf, nil
	}
	return nil, twofactor.ErrTwoFactorNotEnabled
}

func (s *Store) Create(ctx context.Context, tf *twofactor.TwoFactor) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.twoFactors[tf.UserID] = tf
	return nil
}

func (s *Store) Update(ctx context.Context, tf *twofactor.TwoFactor) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.twoFactors[tf.UserID] = tf
	return nil
}

func (s *Store) DeleteByUserID(ctx context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.twoFactors, userID)
	delete(s.totpSecrets, userID)
	return nil
}

func (s *Store) SaveOTPChallenge(ctx context.Context, challenge *twofactor.OTPChallenge) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.otpChallenges[challenge.Key] = challenge
	return nil
}

func (s *Store) GetOTPChallenge(ctx context.Context, key string) (*twofactor.OTPChallenge, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if c, ok := s.otpChallenges[key]; ok {
		return c, nil
	}
	return nil, twofactor.ErrOTPExpired
}

func (s *Store) DeleteOTPChallenge(ctx context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.otpChallenges, key)
	return nil
}

// JWKS Methods (jwt.Repository)
func (s *Store) GetLatestKey(ctx context.Context) (*jwt.JWKRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var latest *jwt.JWKRecord
	for _, k := range s.jwks {
		if latest == nil || k.CreatedAt.After(latest.CreatedAt) {
			latest = k
		}
	}
	if latest == nil {
		return nil, jwt.ErrKeyNotFound
	}
	return latest, nil
}

func (s *Store) GetKeyByID(ctx context.Context, id string) (*jwt.JWKRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if k, ok := s.jwks[id]; ok {
		return k, nil
	}
	return nil, jwt.ErrKeyNotFound
}

func (s *Store) GetAllKeys(ctx context.Context) ([]*jwt.JWKRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	records := make([]*jwt.JWKRecord, 0, len(s.jwks))
	for _, k := range s.jwks {
		records = append(records, k)
	}
	sort.Slice(records, func(i, j int) bool {
		return records[i].CreatedAt.After(records[j].CreatedAt)
	})
	return records, nil
}

func (s *Store) CreateKey(ctx context.Context, record *jwt.JWKRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.jwks[record.ID] = record
	return nil
}

func (s *Store) DeleteKey(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.jwks, id)
	return nil
}
