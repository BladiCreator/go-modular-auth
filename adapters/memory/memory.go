// Package memory provides an in-memory repository implementation suitable for development and testing.
package memory

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
	"github.com/BladiCreator/go-modular-auth/plugins/bearer"
	"github.com/BladiCreator/go-modular-auth/plugins/emailpassword"
	"github.com/BladiCreator/go-modular-auth/plugins/jwt"
	"github.com/BladiCreator/go-modular-auth/plugins/multisession"
	"github.com/BladiCreator/go-modular-auth/plugins/oauth2"
	"github.com/BladiCreator/go-modular-auth/plugins/organization"
	"github.com/BladiCreator/go-modular-auth/plugins/passkey"
	"github.com/BladiCreator/go-modular-auth/plugins/twofactor"
)

var (
	_ emailpassword.Repository = (*Store)(nil)
	_ twofactor.Repository     = (*Store)(nil)
	_ bearer.Repository        = (*Store)(nil)
	_ jwt.Repository           = (*Store)(nil)
	_ organization.Repository  = (*Store)(nil)
	_ admin.Repository         = (*Store)(nil)
	_ passkey.Repository       = (*Store)(nil)
	_ oauth2.Repository        = (*Store)(nil)
	_ multisession.Repository  = (*Store)(nil)
)

// Store is a thread-safe in-memory implementation of authentication storage interfaces.
type Store struct {
	mu             sync.RWMutex
	users          map[string]*entity.User
	accounts       map[string]*entity.Account            // key: accountID
	userAccounts   map[string]map[string]*entity.Account // key: userID -> provider -> Account
	tokens         map[string]*entity.VerificationToken  // key: token string
	sessions       map[string]*entity.Session
	totpSecrets    map[string]string
	twoFactors     map[string]*twofactor.TwoFactor    // key: userID
	otpChallenges  map[string]*twofactor.OTPChallenge // key: challenge key
	trustedDevices map[string]*twofactor.TrustDeviceRecord
	challenges     map[string]*twofactor.ChallengeRecord
	jwks           map[string]*jwt.JWKRecord // key: kid
	orgs           map[string]*organization.Organization
	orgsBySlug     map[string]string
	members        map[string]*organization.Member // key: orgID + ":" + userID
	membersByID    map[string]*organization.Member // key: memberID
	invitations    map[string]*organization.Invitation
	teams          map[string]*organization.Team
	teamMembers    map[string]*organization.TeamMember // key: teamID + ":" + userID
	orgRoles       map[string]*organization.OrganizationRole

	passkeys               map[string]*entity.Passkey          // key: id
	passkeysByCredentialID map[string]*entity.Passkey          // key: credentialID
	passkeyChallenges      map[string]*passkey.PasskeyChallenge // key: token

	oauthClients        map[string]*oauth2.OAuthClient            // key: client_id
	oauthClientsByID    map[string]*oauth2.OAuthClient            // key: id
	oauthCodes          map[string]*oauth2.OAuthAuthorizationCode // key: code
	oauthAccessTokens   map[string]*oauth2.OAuthAccessToken       // key: tokenHash
	oauthRefreshTokens  map[string]*oauth2.OAuthRefreshToken      // key: tokenHash
	oauthConsents       map[string]*oauth2.OAuthConsent           // key: client_id + ":" + user_id
	oauthConsentsByID   map[string]*oauth2.OAuthConsent           // key: id
}

// New instantiates a new thread-safe in-memory Store.
func New() *Store {
	return &Store{
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
		jwks:                   make(map[string]*jwt.JWKRecord),
		orgs:                   make(map[string]*organization.Organization),
		orgsBySlug:             make(map[string]string),
		members:                make(map[string]*organization.Member),
		membersByID:            make(map[string]*organization.Member),
		invitations:            make(map[string]*organization.Invitation),
		teams:                  make(map[string]*organization.Team),
		teamMembers:            make(map[string]*organization.TeamMember),
		orgRoles:               make(map[string]*organization.OrganizationRole),
		passkeys:               make(map[string]*entity.Passkey),
		passkeysByCredentialID: make(map[string]*entity.Passkey),
		passkeyChallenges:      make(map[string]*passkey.PasskeyChallenge),
		oauthClients:           make(map[string]*oauth2.OAuthClient),
		oauthClientsByID:       make(map[string]*oauth2.OAuthClient),
		oauthCodes:             make(map[string]*oauth2.OAuthAuthorizationCode),
		oauthAccessTokens:      make(map[string]*oauth2.OAuthAccessToken),
		oauthRefreshTokens:     make(map[string]*oauth2.OAuthRefreshToken),
		oauthConsents:          make(map[string]*oauth2.OAuthConsent),
		oauthConsentsByID:      make(map[string]*oauth2.OAuthConsent),
	}
}

// User Methods
func (s *Store) CreateUser(ctx context.Context, params *dto.CreateUserParams) (*entity.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	user := &entity.User{
		ID:           "memory:" + strconv.FormatInt(rand.Int63(), 10),
		Name:         params.Name,
		Email:        params.Email,
		Role:         params.Role,
		PasswordHash: params.PasswordHash,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	s.users[user.ID] = user
	return user, nil
}

func (s *Store) GetUserByEmail(ctx context.Context, email string) (*entity.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.users {
		if strings.EqualFold(u.Email, email) {
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

func (s *Store) DeleteUser(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.users[id]; !ok {
		return admin.ErrUserNotFound
	}
	delete(s.users, id)
	delete(s.userAccounts, id)
	return nil
}

func (s *Store) ListUsers(ctx context.Context, filter admin.ListUsersFilter) ([]*entity.User, int64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var matched []*entity.User
	for _, u := range s.users {
		// Filter by field
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

		// Search
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
			default: // "contains"
				matches = strings.Contains(target, query)
			}

			if !matches {
				continue
			}
		}

		cloned := *u
		matched = append(matched, &cloned)
	}

	// Sort
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
		default: // created_at
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

func (s *Store) LinkCredentialAccount(ctx context.Context, userID, passwordHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.userAccounts[userID]; !ok {
		s.userAccounts[userID] = make(map[string]*entity.Account)
	}

	if acc, ok := s.userAccounts[userID]["credential"]; ok {
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
	s.accounts[acc.ID] = acc
	s.userAccounts[userID]["credential"] = acc
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
		ID:             "memory:" + strconv.FormatInt(rand.Int63(), 10),
		UserID:         session.UserID,
		Token:          session.Token,
		IPAddress:      session.IPAddress,
		UserAgent:      session.UserAgent,
		ImpersonatedBy: session.ImpersonatedBy,
		ExpiresAt:      session.ExpiresAt,
		CreatedAt:      session.CreatedAt,
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

func (s *Store) ListSessionsByUserID(ctx context.Context, userID string) ([]*entity.Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*entity.Session
	for _, sess := range s.sessions {
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

func (s *Store) DeleteSession(ctx context.Context, token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, token)
	return nil
}

func (s *Store) DeleteSessionsByUserID(ctx context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for token, sess := range s.sessions {
		if sess.UserID == userID {
			delete(s.sessions, token)
		}
	}
	return nil
}

func (s *Store) DeleteSessions(ctx context.Context, tokens []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, token := range tokens {
		delete(s.sessions, token)
	}
	return nil
}

func (s *Store) FindSessionsByTokens(ctx context.Context, tokens []string) ([]*entity.Session, []*entity.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	matchedSessions := make([]*entity.Session, 0)
	userIDsMap := make(map[string]bool)

	for _, token := range tokens {
		if sess, ok := s.sessions[token]; ok {
			cloned := *sess
			matchedSessions = append(matchedSessions, &cloned)
			userIDsMap[sess.UserID] = true
		}
	}

	matchedUsers := make([]*entity.User, 0)
	for userID := range userIDsMap {
		if u, ok := s.users[userID]; ok {
			cloned := *u
			matchedUsers = append(matchedUsers, &cloned)
		}
	}

	return matchedSessions, matchedUsers, nil
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

// Trusted Devices Methods (twofactor.Repository)
func (s *Store) SaveTrustDevice(ctx context.Context, record *twofactor.TrustDeviceRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := record.UserID + ":" + record.DeviceID
	s.trustedDevices[key] = record
	return nil
}

func (s *Store) FindTrustDevice(ctx context.Context, userID, deviceID string) (*twofactor.TrustDeviceRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	key := userID + ":" + deviceID
	if rec, ok := s.trustedDevices[key]; ok {
		return rec, nil
	}
	return nil, twofactor.ErrInvalidDeviceToken
}

func (s *Store) DeleteTrustDevice(ctx context.Context, userID, deviceID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := userID + ":" + deviceID
	delete(s.trustedDevices, key)
	return nil
}

func (s *Store) DeleteTrustDevicesByUserID(ctx context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, rec := range s.trustedDevices {
		if rec.UserID == userID {
			delete(s.trustedDevices, k)
		}
	}
	return nil
}

// Challenge Methods (twofactor.Repository)
func (s *Store) SaveChallenge(ctx context.Context, challenge *twofactor.ChallengeRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.challenges[challenge.Token] = challenge
	return nil
}

func (s *Store) GetChallenge(ctx context.Context, token string) (*twofactor.ChallengeRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if c, ok := s.challenges[token]; ok {
		return c, nil
	}
	return nil, twofactor.ErrInvalidChallengeToken
}

func (s *Store) DeleteChallenge(ctx context.Context, token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.challenges, token)
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

// Organization Methods

func (s *Store) CreateOrganization(ctx context.Context, org *organization.Organization) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.orgs[org.ID]; exists {
		return organization.ErrOrganizationAlreadyExists
	}
	if _, exists := s.orgsBySlug[org.Slug]; exists {
		return organization.ErrSlugAlreadyExists
	}

	s.orgs[org.ID] = org
	s.orgsBySlug[org.Slug] = org.ID
	return nil
}

func (s *Store) GetOrganizationByID(ctx context.Context, id string) (*organization.Organization, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	org, ok := s.orgs[id]
	if !ok {
		return nil, organization.ErrOrganizationNotFound
	}
	return org, nil
}

func (s *Store) GetOrganizationBySlug(ctx context.Context, slug string) (*organization.Organization, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	id, ok := s.orgsBySlug[slug]
	if !ok {
		return nil, organization.ErrOrganizationNotFound
	}
	return s.orgs[id], nil
}

func (s *Store) UpdateOrganization(ctx context.Context, org *organization.Organization) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	existing, ok := s.orgs[org.ID]
	if !ok {
		return organization.ErrOrganizationNotFound
	}

	if existing.Slug != org.Slug {
		delete(s.orgsBySlug, existing.Slug)
		s.orgsBySlug[org.Slug] = org.ID
	}

	s.orgs[org.ID] = org
	return nil
}

func (s *Store) DeleteOrganization(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	org, ok := s.orgs[id]
	if !ok {
		return organization.ErrOrganizationNotFound
	}

	delete(s.orgsBySlug, org.Slug)
	delete(s.orgs, id)

	// Cascade delete members
	for key, m := range s.members {
		if m.OrganizationID == id {
			delete(s.members, key)
			delete(s.membersByID, m.ID)
		}
	}

	// Cascade delete invitations
	for invID, inv := range s.invitations {
		if inv.OrganizationID == id {
			delete(s.invitations, invID)
		}
	}

	// Cascade delete teams and team members
	for teamID, t := range s.teams {
		if t.OrganizationID == id {
			delete(s.teams, teamID)
			for tmKey, tm := range s.teamMembers {
				if tm.TeamID == teamID {
					delete(s.teamMembers, tmKey)
				}
			}
		}
	}

	// Cascade delete roles
	for roleID, r := range s.orgRoles {
		if r.OrganizationID == id {
			delete(s.orgRoles, roleID)
		}
	}

	return nil
}

func (s *Store) ListOrganizationsByUserID(ctx context.Context, userID string) ([]*organization.Organization, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*organization.Organization
	for _, m := range s.members {
		if m.UserID == userID {
			if org, ok := s.orgs[m.OrganizationID]; ok {
				result = append(result, org)
			}
		}
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].CreatedAt.After(result[j].CreatedAt)
	})

	return result, nil
}

// Member Methods

func (s *Store) cloneMember(member *organization.Member) *organization.Member {
	if member == nil {
		return nil
	}
	cloned := *member
	if u, ok := s.users[member.UserID]; ok {
		cloned.User = &organization.UserInfo{
			ID:    u.ID,
			Email: u.Email,
			Name:  u.Name,
		}
	}
	return &cloned
}

func (s *Store) CreateMember(ctx context.Context, member *organization.Member) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := member.OrganizationID + ":" + member.UserID
	if _, exists := s.members[key]; exists {
		return organization.ErrMemberAlreadyExists
	}

	cloned := s.cloneMember(member)
	s.members[key] = cloned
	s.membersByID[member.ID] = cloned
	return nil
}

func (s *Store) GetMember(ctx context.Context, orgID, userID string) (*organization.Member, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key := orgID + ":" + userID
	member, ok := s.members[key]
	if !ok {
		return nil, organization.ErrMemberNotFound
	}
	return s.cloneMember(member), nil
}

func (s *Store) GetMemberByID(ctx context.Context, memberID string) (*organization.Member, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	member, ok := s.membersByID[memberID]
	if !ok {
		return nil, organization.ErrMemberNotFound
	}
	return s.cloneMember(member), nil
}

func (s *Store) UpdateMember(ctx context.Context, member *organization.Member) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := member.OrganizationID + ":" + member.UserID
	if _, ok := s.members[key]; !ok {
		return organization.ErrMemberNotFound
	}

	cloned := s.cloneMember(member)
	s.members[key] = cloned
	s.membersByID[member.ID] = cloned
	return nil
}

func (s *Store) DeleteMember(ctx context.Context, orgID, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := orgID + ":" + userID
	m, ok := s.members[key]
	if !ok {
		return organization.ErrMemberNotFound
	}

	delete(s.members, key)
	delete(s.membersByID, m.ID)
	return nil
}

func (s *Store) ListMembers(ctx context.Context, orgID string, limit, offset int) ([]*organization.Member, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var all []*organization.Member
	for _, m := range s.members {
		if m.OrganizationID == orgID {
			all = append(all, s.cloneMember(m))
		}
	}

	sort.Slice(all, func(i, j int) bool {
		return all[i].CreatedAt.Before(all[j].CreatedAt)
	})

	total := len(all)
	if offset < 0 {
		offset = 0
	}
	if offset > total {
		return []*organization.Member{}, total, nil
	}

	end := total
	if limit > 0 && offset+limit < total {
		end = offset + limit
	}

	return all[offset:end], total, nil
}

func (s *Store) CountMembersByRole(ctx context.Context, orgID, role string) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	count := 0
	for _, m := range s.members {
		if m.OrganizationID == orgID {
			if m.Role == role || (m.Role != "" && strings.Contains(m.Role, role)) {
				count++
			}
		}
	}
	return count, nil
}

func (s *Store) CountMembers(ctx context.Context, orgID string) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	count := 0
	for _, m := range s.members {
		if m.OrganizationID == orgID {
			count++
		}
	}
	return count, nil
}

// Invitation Methods

func (s *Store) CreateInvitation(ctx context.Context, invitation *organization.Invitation) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.invitations[invitation.ID] = invitation
	return nil
}

func (s *Store) GetInvitationByID(ctx context.Context, id string) (*organization.Invitation, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	inv, ok := s.invitations[id]
	if !ok {
		return nil, organization.ErrInvitationNotFound
	}
	return inv, nil
}

func (s *Store) GetPendingInvitation(ctx context.Context, orgID, email string) (*organization.Invitation, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, inv := range s.invitations {
		if inv.OrganizationID == orgID && strings.EqualFold(inv.Email, email) && inv.Status == organization.InvitationStatusPending {
			return inv, nil
		}
	}
	return nil, organization.ErrInvitationNotFound
}

func (s *Store) UpdateInvitation(ctx context.Context, invitation *organization.Invitation) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.invitations[invitation.ID]; !ok {
		return organization.ErrInvitationNotFound
	}
	s.invitations[invitation.ID] = invitation
	return nil
}

func (s *Store) DeleteInvitation(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.invitations[id]; !ok {
		return organization.ErrInvitationNotFound
	}
	delete(s.invitations, id)
	return nil
}

func (s *Store) ListInvitationsByOrgID(ctx context.Context, orgID string, status *organization.InvitationStatus) ([]*organization.Invitation, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*organization.Invitation
	for _, inv := range s.invitations {
		if inv.OrganizationID == orgID {
			if status == nil || inv.Status == *status {
				result = append(result, inv)
			}
		}
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].CreatedAt.After(result[j].CreatedAt)
	})

	return result, nil
}

func (s *Store) ListInvitationsByEmail(ctx context.Context, email string, status *organization.InvitationStatus) ([]*organization.Invitation, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*organization.Invitation
	for _, inv := range s.invitations {
		if strings.EqualFold(inv.Email, email) {
			if status == nil || inv.Status == *status {
				result = append(result, inv)
			}
		}
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].CreatedAt.After(result[j].CreatedAt)
	})

	return result, nil
}

func (s *Store) CountPendingInvitations(ctx context.Context, orgID string) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	count := 0
	for _, inv := range s.invitations {
		if inv.OrganizationID == orgID && inv.Status == organization.InvitationStatusPending {
			count++
		}
	}
	return count, nil
}

// Team Methods

func (s *Store) CreateTeam(ctx context.Context, team *organization.Team) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, t := range s.teams {
		if t.OrganizationID == team.OrganizationID && strings.EqualFold(t.Name, team.Name) {
			return organization.ErrTeamAlreadyExists
		}
	}

	s.teams[team.ID] = team
	return nil
}

func (s *Store) GetTeamByID(ctx context.Context, id string) (*organization.Team, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	team, ok := s.teams[id]
	if !ok {
		return nil, organization.ErrTeamNotFound
	}
	return team, nil
}

func (s *Store) UpdateTeam(ctx context.Context, team *organization.Team) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.teams[team.ID]; !ok {
		return organization.ErrTeamNotFound
	}

	for _, t := range s.teams {
		if t.ID != team.ID && t.OrganizationID == team.OrganizationID && strings.EqualFold(t.Name, team.Name) {
			return organization.ErrTeamAlreadyExists
		}
	}

	s.teams[team.ID] = team
	return nil
}

func (s *Store) DeleteTeam(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.teams[id]; !ok {
		return organization.ErrTeamNotFound
	}

	delete(s.teams, id)
	for tmKey, tm := range s.teamMembers {
		if tm.TeamID == id {
			delete(s.teamMembers, tmKey)
		}
	}
	return nil
}

func (s *Store) ListTeamsByOrgID(ctx context.Context, orgID string) ([]*organization.Team, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*organization.Team
	for _, t := range s.teams {
		if t.OrganizationID == orgID {
			result = append(result, t)
		}
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].CreatedAt.Before(result[j].CreatedAt)
	})

	return result, nil
}

func (s *Store) ListTeamsByUserID(ctx context.Context, orgID, userID string) ([]*organization.Team, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*organization.Team
	for _, t := range s.teams {
		if t.OrganizationID == orgID {
			key := t.ID + ":" + userID
			if _, ok := s.teamMembers[key]; ok {
				result = append(result, t)
			}
		}
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].CreatedAt.Before(result[j].CreatedAt)
	})

	return result, nil
}

func (s *Store) CountTeams(ctx context.Context, orgID string) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	count := 0
	for _, t := range s.teams {
		if t.OrganizationID == orgID {
			count++
		}
	}
	return count, nil
}

// Team Member Methods

func (s *Store) AddTeamMember(ctx context.Context, teamMember *organization.TeamMember) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := teamMember.TeamID + ":" + teamMember.UserID
	if _, ok := s.teamMembers[key]; ok {
		return organization.ErrTeamMemberAlreadyExists
	}

	s.teamMembers[key] = teamMember
	return nil
}

func (s *Store) RemoveTeamMember(ctx context.Context, teamID, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := teamID + ":" + userID
	if _, ok := s.teamMembers[key]; !ok {
		return organization.ErrTeamMemberNotFound
	}

	delete(s.teamMembers, key)
	return nil
}

func (s *Store) GetTeamMember(ctx context.Context, teamID, userID string) (*organization.TeamMember, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key := teamID + ":" + userID
	tm, ok := s.teamMembers[key]
	if !ok {
		return nil, organization.ErrTeamMemberNotFound
	}
	return tm, nil
}

func (s *Store) ListTeamMembers(ctx context.Context, teamID string) ([]*organization.TeamMember, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*organization.TeamMember
	for _, tm := range s.teamMembers {
		if tm.TeamID == teamID {
			result = append(result, tm)
		}
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].CreatedAt.Before(result[j].CreatedAt)
	})

	return result, nil
}

func (s *Store) CountTeamMembers(ctx context.Context, teamID string) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	count := 0
	for _, tm := range s.teamMembers {
		if tm.TeamID == teamID {
			count++
		}
	}
	return count, nil
}

// Dynamic Role Methods

func (s *Store) CreateRole(ctx context.Context, role *organization.OrganizationRole) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, r := range s.orgRoles {
		if r.OrganizationID == role.OrganizationID && strings.EqualFold(r.Role, role.Role) {
			return organization.ErrRoleAlreadyExists
		}
	}

	s.orgRoles[role.ID] = role
	return nil
}

func (s *Store) GetRoleByID(ctx context.Context, id string) (*organization.OrganizationRole, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	role, ok := s.orgRoles[id]
	if !ok {
		return nil, organization.ErrRoleNotFound
	}
	return role, nil
}

func (s *Store) GetRoleByName(ctx context.Context, orgID, roleName string) (*organization.OrganizationRole, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, r := range s.orgRoles {
		if r.OrganizationID == orgID && strings.EqualFold(r.Role, roleName) {
			return r, nil
		}
	}
	return nil, organization.ErrRoleNotFound
}

func (s *Store) UpdateRole(ctx context.Context, role *organization.OrganizationRole) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.orgRoles[role.ID]; !ok {
		return organization.ErrRoleNotFound
	}

	for _, r := range s.orgRoles {
		if r.ID != role.ID && r.OrganizationID == role.OrganizationID && strings.EqualFold(r.Role, role.Role) {
			return organization.ErrRoleAlreadyExists
		}
	}

	s.orgRoles[role.ID] = role
	return nil
}

func (s *Store) DeleteRole(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.orgRoles[id]; !ok {
		return organization.ErrRoleNotFound
	}
	delete(s.orgRoles, id)
	return nil
}

func (s *Store) ListRolesByOrgID(ctx context.Context, orgID string) ([]*organization.OrganizationRole, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*organization.OrganizationRole
	for _, r := range s.orgRoles {
		if r.OrganizationID == orgID {
			result = append(result, r)
		}
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].CreatedAt.Before(result[j].CreatedAt)
	})

	return result, nil
}

func (s *Store) CountRoles(ctx context.Context, orgID string) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	count := 0
	for _, r := range s.orgRoles {
		if r.OrganizationID == orgID {
			count++
		}
	}
	return count, nil
}

// Passkey Repository Implementation

func (s *Store) CreatePasskey(ctx context.Context, pk *entity.Passkey) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.passkeys[pk.ID]; exists {
		return passkey.ErrPasskeyAlreadyExists
	}
	if _, exists := s.passkeysByCredentialID[pk.CredentialID]; exists {
		return passkey.ErrPasskeyAlreadyExists
	}

	s.passkeys[pk.ID] = pk
	s.passkeysByCredentialID[pk.CredentialID] = pk
	return nil
}

func (s *Store) GetPasskeyByID(ctx context.Context, id string) (*entity.Passkey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if pk, ok := s.passkeys[id]; ok {
		return pk, nil
	}
	return nil, passkey.ErrPasskeyNotFound
}

func (s *Store) GetPasskeyByCredentialID(ctx context.Context, credentialID string) (*entity.Passkey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if pk, ok := s.passkeysByCredentialID[credentialID]; ok {
		return pk, nil
	}
	return nil, passkey.ErrPasskeyNotFound
}

func (s *Store) ListPasskeysByUserID(ctx context.Context, userID string) ([]*entity.Passkey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*entity.Passkey
	for _, pk := range s.passkeys {
		if pk.UserID == userID {
			result = append(result, pk)
		}
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].CreatedAt.Before(result[j].CreatedAt)
	})

	return result, nil
}

func (s *Store) UpdatePasskey(ctx context.Context, pk *entity.Passkey) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.passkeys[pk.ID]; !ok {
		return passkey.ErrPasskeyNotFound
	}

	s.passkeys[pk.ID] = pk
	s.passkeysByCredentialID[pk.CredentialID] = pk
	return nil
}

func (s *Store) UpdatePasskeyCounter(ctx context.Context, id string, newCounter uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	pk, ok := s.passkeys[id]
	if !ok {
		return passkey.ErrPasskeyNotFound
	}

	pk.Counter = newCounter
	pk.UpdatedAt = time.Now()
	return nil
}

func (s *Store) DeletePasskey(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	pk, ok := s.passkeys[id]
	if !ok {
		return passkey.ErrPasskeyNotFound
	}

	delete(s.passkeys, id)
	delete(s.passkeysByCredentialID, pk.CredentialID)
	return nil
}

func (s *Store) DeletePasskeysByUserID(ctx context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for id, pk := range s.passkeys {
		if pk.UserID == userID {
			delete(s.passkeys, id)
			delete(s.passkeysByCredentialID, pk.CredentialID)
		}
	}
	return nil
}

func (s *Store) SavePasskeyChallenge(ctx context.Context, challenge *passkey.PasskeyChallenge) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.passkeyChallenges[challenge.Token] = challenge
	return nil
}

func (s *Store) GetPasskeyChallenge(ctx context.Context, token string) (*passkey.PasskeyChallenge, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if c, ok := s.passkeyChallenges[token]; ok {
		return c, nil
	}
	return nil, passkey.ErrChallengeNotFound
}

func (s *Store) ConsumePasskeyChallenge(ctx context.Context, token string) (*passkey.PasskeyChallenge, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if c, ok := s.passkeyChallenges[token]; ok {
		delete(s.passkeyChallenges, token)
		return c, nil
	}
	return nil, passkey.ErrChallengeNotFound
}

func (s *Store) DeletePasskeyChallenge(ctx context.Context, token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.passkeyChallenges, token)
	return nil
}

// OAuth 2.1 & OpenID Connect Repository Methods

func (s *Store) FindClientByClientID(ctx context.Context, clientID string) (*oauth2.OAuthClient, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if client, ok := s.oauthClients[clientID]; ok {
		return client, nil
	}
	return nil, oauth2.ErrClientNotFound
}

func (s *Store) FindClientByID(ctx context.Context, id string) (*oauth2.OAuthClient, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if client, ok := s.oauthClientsByID[id]; ok {
		return client, nil
	}
	return nil, oauth2.ErrClientNotFound
}

func (s *Store) ListClientsByUserID(ctx context.Context, userID string) ([]*oauth2.OAuthClient, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*oauth2.OAuthClient
	for _, client := range s.oauthClients {
		if client.UserID != nil && *client.UserID == userID {
			result = append(result, client)
		}
	}
	return result, nil
}

func (s *Store) CreateClient(ctx context.Context, client *oauth2.OAuthClient) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.oauthClients[client.ClientID] = client
	s.oauthClientsByID[client.ID] = client
	return nil
}

func (s *Store) UpdateClient(ctx context.Context, client *oauth2.OAuthClient) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.oauthClients[client.ClientID] = client
	s.oauthClientsByID[client.ID] = client
	return nil
}

func (s *Store) DeleteClient(ctx context.Context, clientID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if client, ok := s.oauthClients[clientID]; ok {
		delete(s.oauthClientsByID, client.ID)
		delete(s.oauthClients, clientID)
	}
	return nil
}

func (s *Store) CreateAuthorizationCode(ctx context.Context, code *oauth2.OAuthAuthorizationCode) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.oauthCodes[code.Code] = code
	return nil
}

func (s *Store) ConsumeAuthorizationCode(ctx context.Context, code string) (*oauth2.OAuthAuthorizationCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if authCode, ok := s.oauthCodes[code]; ok {
		delete(s.oauthCodes, code)
		return authCode, nil
	}
	return nil, oauth2.ErrInvalidAuthorizationCode
}

func (s *Store) CreateAccessToken(ctx context.Context, token *oauth2.OAuthAccessToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.oauthAccessTokens[token.Token] = token
	return nil
}

func (s *Store) FindAccessToken(ctx context.Context, tokenHash string) (*oauth2.OAuthAccessToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if token, ok := s.oauthAccessTokens[tokenHash]; ok {
		return token, nil
	}
	return nil, oauth2.ErrInvalidAccessToken
}

func (s *Store) DeleteAccessToken(ctx context.Context, tokenHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.oauthAccessTokens, tokenHash)
	return nil
}

func (s *Store) CreateRefreshToken(ctx context.Context, token *oauth2.OAuthRefreshToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.oauthRefreshTokens[token.Token] = token
	return nil
}

func (s *Store) FindRefreshToken(ctx context.Context, tokenHash string) (*oauth2.OAuthRefreshToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if token, ok := s.oauthRefreshTokens[tokenHash]; ok {
		return token, nil
	}
	return nil, oauth2.ErrInvalidRefreshToken
}

func (s *Store) DeleteRefreshToken(ctx context.Context, tokenHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.oauthRefreshTokens, tokenHash)
	return nil
}

func (s *Store) RevokeRefreshTokenFamily(ctx context.Context, familyID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	for _, token := range s.oauthRefreshTokens {
		if token.FamilyID == familyID {
			token.RevokedAt = &now
		}
	}
	return nil
}

func (s *Store) FindConsent(ctx context.Context, clientID, userID string) (*oauth2.OAuthConsent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key := clientID + ":" + userID
	if consent, ok := s.oauthConsents[key]; ok {
		return consent, nil
	}
	return nil, oauth2.ErrConsentRequired
}

func (s *Store) ListConsentsByUserID(ctx context.Context, userID string) ([]*oauth2.OAuthConsent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*oauth2.OAuthConsent
	for _, consent := range s.oauthConsents {
		if consent.UserID == userID {
			result = append(result, consent)
		}
	}
	return result, nil
}

func (s *Store) CreateConsent(ctx context.Context, consent *oauth2.OAuthConsent) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := consent.ClientID + ":" + consent.UserID
	s.oauthConsents[key] = consent
	s.oauthConsentsByID[consent.ID] = consent
	return nil
}

func (s *Store) UpdateConsent(ctx context.Context, consent *oauth2.OAuthConsent) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := consent.ClientID + ":" + consent.UserID
	s.oauthConsents[key] = consent
	s.oauthConsentsByID[consent.ID] = consent
	return nil
}

func (s *Store) DeleteConsent(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if consent, ok := s.oauthConsentsByID[id]; ok {
		key := consent.ClientID + ":" + consent.UserID
		delete(s.oauthConsents, key)
		delete(s.oauthConsentsByID, id)
	}
	return nil
}

func (s *Store) FindUserByID(ctx context.Context, userID string) (*entity.User, error) {
	return s.GetUserByID(ctx, userID)
}

func (s *Store) FindSessionByID(ctx context.Context, sessionID string) (*entity.Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if sess, ok := s.sessions[sessionID]; ok {
		return sess, nil
	}
	return nil, domain.ErrSessionNotFound
}

func (s *Store) DeleteSessionByID(ctx context.Context, sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.sessions, sessionID)
	return nil
}

func (s *Store) SaveSession(session *entity.Session) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.sessions[session.ID] = session
}




