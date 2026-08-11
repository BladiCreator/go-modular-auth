// Package memory provides an in-memory repository implementation suitable for development and testing.
package memory

import (
	"context"
	"math/rand"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/BladiCreator/go-modular-auth/domain"
	"github.com/BladiCreator/go-modular-auth/domain/dto"
	"github.com/BladiCreator/go-modular-auth/domain/entity"
	"github.com/BladiCreator/go-modular-auth/plugins/bearer"
	"github.com/BladiCreator/go-modular-auth/plugins/emailpassword"
	"github.com/BladiCreator/go-modular-auth/plugins/jwt"
	"github.com/BladiCreator/go-modular-auth/plugins/organization"
	"github.com/BladiCreator/go-modular-auth/plugins/twofactor"
)

var (
	_ emailpassword.Repository = (*Store)(nil)
	_ twofactor.Repository     = (*Store)(nil)
	_ bearer.Repository        = (*Store)(nil)
	_ jwt.Repository           = (*Store)(nil)
	_ organization.Repository  = (*Store)(nil)
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
	orgs          map[string]*organization.Organization
	orgsBySlug    map[string]string
	members       map[string]*organization.Member // key: orgID + ":" + userID
	membersByID   map[string]*organization.Member // key: memberID
	invitations   map[string]*organization.Invitation
	teams         map[string]*organization.Team
	teamMembers   map[string]*organization.TeamMember // key: teamID + ":" + userID
	orgRoles      map[string]*organization.OrganizationRole
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
		orgs:          make(map[string]*organization.Organization),
		orgsBySlug:    make(map[string]string),
		members:       make(map[string]*organization.Member),
		membersByID:   make(map[string]*organization.Member),
		invitations:   make(map[string]*organization.Invitation),
		teams:         make(map[string]*organization.Team),
		teamMembers:   make(map[string]*organization.TeamMember),
		orgRoles:      make(map[string]*organization.OrganizationRole),
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

