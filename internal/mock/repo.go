package mock

import (
	"context"
	"fmt"
	"math/rand"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/BladiCreator/go-modular-auth/domain"
	"github.com/BladiCreator/go-modular-auth/domain/dto"
	"github.com/BladiCreator/go-modular-auth/domain/entity"
	"github.com/BladiCreator/go-modular-auth/plugins/admin"
	"github.com/BladiCreator/go-modular-auth/plugins/emailpassword"
	"github.com/BladiCreator/go-modular-auth/plugins/passkey"
	"github.com/BladiCreator/go-modular-auth/plugins/twofactor"
)

var (
	_ emailpassword.Repository = (*MockRepo)(nil)
	_ twofactor.Repository     = (*MockRepo)(nil)
	_ admin.Repository         = (*MockRepo)(nil)
	_ passkey.Repository       = (*MockRepo)(nil)
)

type MockRepo struct {
	mu                     sync.RWMutex
	users                  map[string]*entity.User
	accounts               map[string]*entity.Account            // key: accountID
	userAccounts           map[string]map[string]*entity.Account // key: userID -> provider -> Account
	tokens                 map[string]*entity.VerificationToken  // key: token string
	sessions               map[string]*entity.Session
	totpSecrets            map[string]string
	twoFactors             map[string]*twofactor.TwoFactor         // key: userID
	otpChallenges          map[string]*twofactor.OTPChallenge      // key: challenge key
	trustedDevices         map[string]*twofactor.TrustDeviceRecord // key: userID + ":" + deviceID
	challenges             map[string]*twofactor.ChallengeRecord   // key: token
	passkeys               map[string]*entity.Passkey              // key: id
	passkeysByCredentialID map[string]*entity.Passkey              // key: credentialID
	passkeyChallenges      map[string]*passkey.PasskeyChallenge    // key: token
}

func NewMockRepo() *MockRepo {
	return &MockRepo{
		users:                  make(map[string]*entity.User),
		accounts:               make(map[string]*entity.Account),
		userAccounts:           make(map[string]map[string]*entity.Account),
		tokens:                 make(map[string]*entity.VerificationToken),
		sessions:               make(map[string]*entity.Session),
		totpSecrets:            make(map[string]string),
		twoFactors:             make(map[string]*twofactor.TwoFactor),
		otpChallenges:          make(map[string]*twofactor.OTPChallenge),
		trustedDevices:         make(map[string]*twofactor.TrustDeviceRecord),
		challenges:             make(map[string]*twofactor.ChallengeRecord),
		passkeys:               make(map[string]*entity.Passkey),
		passkeysByCredentialID: make(map[string]*entity.Passkey),
		passkeyChallenges:      make(map[string]*passkey.PasskeyChallenge),
	}
}

// User Methods
func (m *MockRepo) CreateUser(ctx context.Context, params *dto.CreateUserParams) (*entity.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	user := &entity.User{
		ID:           "usr_" + strconv.FormatInt(rand.Int63(), 10),
		Name:         params.Name,
		Email:        params.Email,
		Role:         params.Role,
		PasswordHash: params.PasswordHash,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	m.users[user.ID] = user
	return user, nil
}

func (m *MockRepo) GetUserByEmail(ctx context.Context, email string) (*entity.User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, u := range m.users {
		if strings.EqualFold(u.Email, email) {
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

func (m *MockRepo) DeleteUser(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.users[id]; !ok {
		return admin.ErrUserNotFound
	}
	delete(m.users, id)
	delete(m.userAccounts, id)
	return nil
}

func (m *MockRepo) ListUsers(ctx context.Context, filter admin.ListUsersFilter) ([]*entity.User, int64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var matched []*entity.User
	for _, u := range m.users {
		if filter.FilterField != "" && filter.FilterValue != nil {
			switch strings.ToLower(filter.FilterField) {
			case "role":
				valStr := fmt.Sprintf("%v", filter.FilterValue)
				if filter.FilterOperator == "ne" {
					if u.Role == valStr {
						continue
					}
				} else {
					if u.Role != valStr && !strings.Contains(u.Role, valStr) {
						continue
					}
				}
			case "banned":
				if bVal, ok := filter.FilterValue.(bool); ok {
					if u.Banned != bVal {
						continue
					}
				}
			}
		}

		if filter.SearchValue != "" {
			query := strings.ToLower(filter.SearchValue)
			target := ""
			switch strings.ToLower(filter.SearchField) {
			case "email":
				target = strings.ToLower(u.Email)
			case "name":
				target = strings.ToLower(u.Name)
			default:
				target = strings.ToLower(u.Name + " " + u.Email)
			}

			matches := false
			switch strings.ToLower(filter.SearchOperator) {
			case "exact":
				matches = (target == query)
			case "starts_with":
				matches = strings.HasPrefix(target, query)
			case "ends_with":
				matches = strings.HasSuffix(target, query)
			default:
				matches = strings.Contains(target, query)
			}

			if !matches {
				continue
			}
		}

		cloned := *u
		matched = append(matched, &cloned)
	}

	sort.Slice(matched, func(i, j int) bool {
		asc := strings.ToLower(filter.SortDirection) == "asc"
		switch strings.ToLower(filter.SortBy) {
		case "email":
			if asc {
				return matched[i].Email < matched[j].Email
			}
			return matched[i].Email > matched[j].Email
		case "name":
			if asc {
				return matched[i].Name < matched[j].Name
			}
			return matched[i].Name > matched[j].Name
		default:
			if asc {
				return matched[i].CreatedAt.Before(matched[j].CreatedAt)
			}
			return matched[i].CreatedAt.After(matched[j].CreatedAt)
		}
	})

	total := int64(len(matched))
	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}
	if offset > len(matched) {
		return []*entity.User{}, total, nil
	}

	end := len(matched)
	if filter.Limit > 0 && offset+filter.Limit < len(matched) {
		end = offset + filter.Limit
	}

	return matched[offset:end], total, nil
}

func (m *MockRepo) LinkCredentialAccount(ctx context.Context, userID, passwordHash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.userAccounts[userID]; !ok {
		m.userAccounts[userID] = make(map[string]*entity.Account)
	}

	if acc, ok := m.userAccounts[userID]["credential"]; ok {
		acc.Password = passwordHash
		acc.UpdatedAt = time.Now()
		return nil
	}

	acc := &entity.Account{
		ID:        "acc_" + strconv.FormatInt(rand.Int63(), 10),
		UserID:    userID,
		Provider:  "credential",
		Password:  passwordHash,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	m.accounts[acc.ID] = acc
	m.userAccounts[userID]["credential"] = acc
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
func (m *MockRepo) CreateSession(ctx context.Context, sessionCtx *dto.CreateSessionParams) (*entity.Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	sess := &entity.Session{
		ID:             "sess_" + strconv.FormatInt(rand.Int63(), 10),
		UserID:         sessionCtx.UserID,
		Token:          sessionCtx.Token,
		IPAddress:      sessionCtx.IPAddress,
		UserAgent:      sessionCtx.UserAgent,
		ImpersonatedBy: sessionCtx.ImpersonatedBy,
		ExpiresAt:      sessionCtx.ExpiresAt,
		CreatedAt:      sessionCtx.CreatedAt,
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

func (m *MockRepo) ListSessionsByUserID(ctx context.Context, userID string) ([]*entity.Session, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []*entity.Session
	for _, sess := range m.sessions {
		if sess.UserID == userID {
			cloned := *sess
			result = append(result, &cloned)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].CreatedAt.After(result[j].CreatedAt)
	})
	return result, nil
}

func (m *MockRepo) DeleteSession(ctx context.Context, token string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.sessions, token)
	return nil
}

func (m *MockRepo) DeleteSessionsByUserID(ctx context.Context, userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for token, sess := range m.sessions {
		if sess.UserID == userID {
			delete(m.sessions, token)
		}
	}
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

func (m *MockRepo) FindByUserID(ctx context.Context, userID string) (*twofactor.TwoFactor, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if tf, ok := m.twoFactors[userID]; ok {
		return tf, nil
	}
	return nil, twofactor.ErrTwoFactorNotEnabled
}

func (m *MockRepo) Create(ctx context.Context, tf *twofactor.TwoFactor) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.twoFactors[tf.UserID] = tf
	return nil
}

func (m *MockRepo) Update(ctx context.Context, tf *twofactor.TwoFactor) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.twoFactors[tf.UserID] = tf
	return nil
}

func (m *MockRepo) DeleteByUserID(ctx context.Context, userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.twoFactors, userID)
	delete(m.totpSecrets, userID)
	return nil
}

func (m *MockRepo) SaveOTPChallenge(ctx context.Context, challenge *twofactor.OTPChallenge) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.otpChallenges[challenge.Key] = challenge
	return nil
}

func (m *MockRepo) GetOTPChallenge(ctx context.Context, key string) (*twofactor.OTPChallenge, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if c, ok := m.otpChallenges[key]; ok {
		return c, nil
	}
	return nil, twofactor.ErrOTPExpired
}

func (m *MockRepo) DeleteOTPChallenge(ctx context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.otpChallenges, key)
	return nil
}

// Trusted Devices Methods
func (m *MockRepo) SaveTrustDevice(ctx context.Context, record *twofactor.TrustDeviceRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := record.UserID + ":" + record.DeviceID
	m.trustedDevices[key] = record
	return nil
}

func (m *MockRepo) FindTrustDevice(ctx context.Context, userID, deviceID string) (*twofactor.TrustDeviceRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	key := userID + ":" + deviceID
	if rec, ok := m.trustedDevices[key]; ok {
		return rec, nil
	}
	return nil, twofactor.ErrInvalidDeviceToken
}

func (m *MockRepo) DeleteTrustDevice(ctx context.Context, userID, deviceID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := userID + ":" + deviceID
	delete(m.trustedDevices, key)
	return nil
}

func (m *MockRepo) DeleteTrustDevicesByUserID(ctx context.Context, userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, rec := range m.trustedDevices {
		if rec.UserID == userID {
			delete(m.trustedDevices, k)
		}
	}
	return nil
}

// Challenge Methods
func (m *MockRepo) SaveChallenge(ctx context.Context, challenge *twofactor.ChallengeRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.challenges[challenge.Token] = challenge
	return nil
}

func (m *MockRepo) GetChallenge(ctx context.Context, token string) (*twofactor.ChallengeRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if c, ok := m.challenges[token]; ok {
		return c, nil
	}
	return nil, twofactor.ErrInvalidChallengeToken
}

func (m *MockRepo) DeleteChallenge(ctx context.Context, token string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.challenges, token)
	return nil
}

// Passkey Repository Methods

func (m *MockRepo) CreatePasskey(ctx context.Context, pk *entity.Passkey) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.passkeys[pk.ID]; exists {
		return passkey.ErrPasskeyAlreadyExists
	}
	if _, exists := m.passkeysByCredentialID[pk.CredentialID]; exists {
		return passkey.ErrPasskeyAlreadyExists
	}

	m.passkeys[pk.ID] = pk
	m.passkeysByCredentialID[pk.CredentialID] = pk
	return nil
}

func (m *MockRepo) GetPasskeyByID(ctx context.Context, id string) (*entity.Passkey, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if pk, ok := m.passkeys[id]; ok {
		return pk, nil
	}
	return nil, passkey.ErrPasskeyNotFound
}

func (m *MockRepo) GetPasskeyByCredentialID(ctx context.Context, credentialID string) (*entity.Passkey, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if pk, ok := m.passkeysByCredentialID[credentialID]; ok {
		return pk, nil
	}
	return nil, passkey.ErrPasskeyNotFound
}

func (m *MockRepo) ListPasskeysByUserID(ctx context.Context, userID string) ([]*entity.Passkey, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []*entity.Passkey
	for _, pk := range m.passkeys {
		if pk.UserID == userID {
			result = append(result, pk)
		}
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].CreatedAt.Before(result[j].CreatedAt)
	})

	return result, nil
}

func (m *MockRepo) UpdatePasskey(ctx context.Context, pk *entity.Passkey) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.passkeys[pk.ID]; !ok {
		return passkey.ErrPasskeyNotFound
	}

	m.passkeys[pk.ID] = pk
	m.passkeysByCredentialID[pk.CredentialID] = pk
	return nil
}

func (m *MockRepo) UpdatePasskeyCounter(ctx context.Context, id string, newCounter uint32) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	pk, ok := m.passkeys[id]
	if !ok {
		return passkey.ErrPasskeyNotFound
	}

	pk.Counter = newCounter
	pk.UpdatedAt = time.Now()
	return nil
}

func (m *MockRepo) DeletePasskey(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	pk, ok := m.passkeys[id]
	if !ok {
		return passkey.ErrPasskeyNotFound
	}

	delete(m.passkeys, id)
	delete(m.passkeysByCredentialID, pk.CredentialID)
	return nil
}

func (m *MockRepo) DeletePasskeysByUserID(ctx context.Context, userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for id, pk := range m.passkeys {
		if pk.UserID == userID {
			delete(m.passkeys, id)
			delete(m.passkeysByCredentialID, pk.CredentialID)
		}
	}
	return nil
}

func (m *MockRepo) SavePasskeyChallenge(ctx context.Context, challenge *passkey.PasskeyChallenge) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.passkeyChallenges[challenge.Token] = challenge
	return nil
}

func (m *MockRepo) GetPasskeyChallenge(ctx context.Context, token string) (*passkey.PasskeyChallenge, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if c, ok := m.passkeyChallenges[token]; ok {
		return c, nil
	}
	return nil, passkey.ErrChallengeNotFound
}

func (m *MockRepo) ConsumePasskeyChallenge(ctx context.Context, token string) (*passkey.PasskeyChallenge, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if c, ok := m.passkeyChallenges[token]; ok {
		delete(m.passkeyChallenges, token)
		return c, nil
	}
	return nil, passkey.ErrChallengeNotFound
}

func (m *MockRepo) DeletePasskeyChallenge(ctx context.Context, token string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.passkeyChallenges, token)
	return nil
}
