package admin

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"slices"
	"strings"
	"time"

	"github.com/BladiCreator/go-modular-auth/domain/dto"
	"github.com/BladiCreator/go-modular-auth/domain/entity"
	"github.com/BladiCreator/go-modular-auth/plugin"
	"golang.org/x/crypto/bcrypt"
)

// PluginID is the unique string identifier for the Admin plugin ("admin").
const PluginID = "admin"

// Plugin provides governance, role-based access control (RBAC), user moderation, and session impersonation.
type Plugin struct {
	repo   Repository
	config Config
	ctx    *plugin.Context
}

// New creates a new Admin plugin instance configured with a repository and functional options.
func New(repo Repository, opts ...Option) *Plugin {
	cfg := DefaultConfig()
	for _, opt := range opts {
		opt(&cfg)
	}
	return &Plugin{
		repo:   repo,
		config: cfg,
	}
}

// ID returns the unique string identifier for the Admin plugin ("admin").
func (p *Plugin) ID() string {
	return PluginID
}

// Init initializes the plugin within the global GoModularAuth runtime context.
func (p *Plugin) Init(ctx *plugin.Context) error {
	p.ctx = ctx
	return nil
}

// Config returns the active configuration settings of the Admin plugin.
func (p *Plugin) Config() Config {
	return p.config
}

// Repository returns the underlying storage repository instance.
func (p *Plugin) Repository() Repository {
	return p.repo
}

// publishEvent safely publishes an event to the EventBus if initialized.
func (p *Plugin) publishEvent(topic string, payload any) {
	if p.ctx != nil && p.ctx.Events() != nil {
		p.ctx.Events().Publish(topic, payload)
	}
}

// hashPassword securely hashes a password using CryptoUtils from context or fallback bcrypt.
func (p *Plugin) hashPassword(password string) (string, error) {
	if p.ctx != nil && p.ctx.Crypto() != nil {
		return p.ctx.Crypto().HashPassword(password)
	}
	b, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(b), err
}

// generateToken generates a cryptographically secure hex token.
func (p *Plugin) generateToken(length int) (string, error) {
	if p.ctx != nil && p.ctx.Crypto() != nil {
		return p.ctx.Crypto().GenerateRandomToken(length)
	}
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// hasPermission checks if the caller satisfies the requested permissions.
func (p *Plugin) hasPermission(caller CallerContext, perms Permissions, connector Connector) bool {
	return HasPermission(HasPermissionInput{
		UserID:       caller.UserID,
		Role:         caller.Role,
		AdminUserIDs: p.config.AdminUserIDs,
		RolesConfig:  p.config.Roles,
		DefaultRole:  p.config.DefaultRole,
		Permissions:  perms,
		Connector:    connector,
	})
}

// isUserAdmin checks if a user is classified as an administrator.
func (p *Plugin) isUserAdmin(user *entity.User) bool {
	if user == nil {
		return false
	}
	if slices.Contains(p.config.AdminUserIDs, user.ID) {
		return true
	}
	roleParts := strings.SplitSeq(user.Role, ",")
	for part := range roleParts {
		r := strings.TrimSpace(part)
		for _, adminRole := range p.config.AdminRoles {
			if strings.EqualFold(r, adminRole) {
				return true
			}
		}
	}
	return false
}

// CreateUser provisions a new user record with optional password hashing and role assignment.
func (p *Plugin) CreateUser(ctx context.Context, params CreateUserParams) (*entity.User, error) {
	if !p.hasPermission(params.Caller, Permissions{ResourceUser: {ActionCreate}}, ConnectorAND) {
		return nil, ErrForbidden
	}

	email := strings.ToLower(strings.TrimSpace(params.Email))
	if email == "" || !strings.Contains(email, "@") {
		return nil, ErrInvalidEmail
	}

	if _, err := p.repo.GetUserByEmail(ctx, email); err == nil {
		return nil, ErrUserAlreadyExists
	}

	role := strings.TrimSpace(params.Role)
	if role == "" {
		role = p.config.DefaultRole
	}

	var passwordHash string
	if params.Password != "" {
		if len(params.Password) < p.config.MinPasswordLength {
			return nil, ErrPasswordTooShort
		}
		if len(params.Password) > p.config.MaxPasswordLength {
			return nil, ErrPasswordTooLong
		}
		hash, err := p.hashPassword(params.Password)
		if err != nil {
			return nil, err
		}
		passwordHash = hash
	}

	createParams := &dto.CreateUserParams{
		Name:           strings.TrimSpace(params.Name),
		Email:          email,
		PasswordHash:   passwordHash,
		Role:           role,
		ExtraContainer: params.ExtraContainer,
	}

	user, err := p.repo.CreateUser(ctx, createParams)
	if err != nil {
		return nil, err
	}

	if passwordHash != "" {
		_ = p.repo.LinkCredentialAccount(ctx, user.ID, passwordHash)
	}

	p.publishEvent(EventUserCreated, &UserCreatedEventPayload{
		CallerID:       params.Caller.UserID,
		CallerRole:     params.Caller.Role,
		User:           user,
		ExtraContainer: params.ExtraContainer,
	})

	return user, nil
}

// GetUser retrieves a user profile by ID after verifying administrative access.
func (p *Plugin) GetUser(ctx context.Context, params GetUserParams) (*entity.User, error) {
	if params.UserID == "" {
		return nil, ErrInvalidParameter
	}

	if !p.hasPermission(params.Caller, Permissions{ResourceUser: {ActionGet}}, ConnectorAND) &&
		!p.hasPermission(params.Caller, Permissions{ResourceUser: {ActionList}}, ConnectorAND) {
		return nil, ErrForbidden
	}

	return p.repo.GetUserByID(ctx, params.UserID)
}

// ListUsers returns a filtered and paginated list of user accounts.
func (p *Plugin) ListUsers(ctx context.Context, params ListUsersParams) (*ListUsersResult, error) {
	if !p.hasPermission(params.Caller, Permissions{ResourceUser: {ActionList}}, ConnectorAND) {
		return nil, ErrForbidden
	}

	users, total, err := p.repo.ListUsers(ctx, params.Filter)
	if err != nil {
		return nil, err
	}

	return &ListUsersResult{
		Users:  users,
		Total:  total,
		Limit:  params.Filter.Limit,
		Offset: params.Filter.Offset,
	}, nil
}

// UpdateUser modifies specified properties on an existing user account.
func (p *Plugin) UpdateUser(ctx context.Context, params UpdateUserParams) (*entity.User, error) {
	if params.UserID == "" {
		return nil, ErrInvalidParameter
	}

	if !p.hasPermission(params.Caller, Permissions{ResourceUser: {ActionUpdate}}, ConnectorAND) {
		return nil, ErrForbidden
	}

	if params.Name == nil && params.Email == nil && params.EmailVerified == nil &&
		params.Role == nil && params.Banned == nil && params.BanReason == nil && params.BanExpires == nil {
		return nil, ErrNoDataToUpdate
	}

	user, err := p.repo.GetUserByID(ctx, params.UserID)
	if err != nil {
		return nil, err
	}

	if params.Email != nil {
		normalized := strings.ToLower(strings.TrimSpace(*params.Email))
		if normalized == "" || !strings.Contains(normalized, "@") {
			return nil, ErrInvalidEmail
		}
		if normalized != user.Email {
			if existing, err := p.repo.GetUserByEmail(ctx, normalized); err == nil && existing != nil && existing.ID != user.ID {
				return nil, ErrUserAlreadyExists
			}
			user.Email = normalized
		}
	}

	if params.Name != nil {
		user.Name = strings.TrimSpace(*params.Name)
	}

	if params.EmailVerified != nil {
		user.EmailVerified = *params.EmailVerified
	}

	if params.Role != nil {
		user.Role = strings.TrimSpace(*params.Role)
	}

	if params.Banned != nil {
		user.Banned = *params.Banned
	}

	if params.BanReason != nil {
		user.BanReason = params.BanReason
	}

	if params.BanExpires != nil {
		user.BanExpires = params.BanExpires
	}

	user.UpdatedAt = time.Now()

	if err := p.repo.UpdateUser(ctx, user); err != nil {
		return nil, err
	}

	p.publishEvent(EventUserUpdated, &UserUpdatedEventPayload{
		CallerID:       params.Caller.UserID,
		CallerRole:     params.Caller.Role,
		User:           user,
		ExtraContainer: params.ExtraContainer,
	})

	return user, nil
}

// RemoveUser permanently removes a user and terminates their active sessions.
func (p *Plugin) RemoveUser(ctx context.Context, params RemoveUserParams) error {
	if params.UserID == "" {
		return ErrInvalidParameter
	}

	if !p.hasPermission(params.Caller, Permissions{ResourceUser: {ActionDelete}}, ConnectorAND) {
		return ErrForbidden
	}

	// Prevent self-deletion
	if params.Caller.UserID != "" && params.Caller.UserID == params.UserID {
		return ErrCannotDeleteSelf
	}

	if _, err := p.repo.GetUserByID(ctx, params.UserID); err != nil {
		return err
	}

	_ = p.repo.DeleteSessionsByUserID(ctx, params.UserID)

	if err := p.repo.DeleteUser(ctx, params.UserID); err != nil {
		return err
	}

	p.publishEvent(EventUserDeleted, &UserDeletedEventPayload{
		CallerID:   params.Caller.UserID,
		CallerRole: params.Caller.Role,
		UserID:     params.UserID,
	})

	return nil
}

// SetRole updates the assigned role for a user account.
func (p *Plugin) SetRole(ctx context.Context, params SetRoleParams) (*entity.User, error) {
	if params.UserID == "" || strings.TrimSpace(params.Role) == "" {
		return nil, ErrInvalidParameter
	}

	if !p.hasPermission(params.Caller, Permissions{ResourceUser: {ActionSetRole}}, ConnectorAND) {
		return nil, ErrForbidden
	}

	targetRole := strings.TrimSpace(params.Role)

	if p.config.Roles != nil {
		parts := strings.SplitSeq(targetRole, ",")
		for part := range parts {
			clean := strings.TrimSpace(part)
			if clean == "" {
				continue
			}
			if _, ok := p.config.Roles[clean]; !ok {
				if _, ok := DefaultRoles()[clean]; !ok {
					return nil, ErrInvalidRole
				}
			}
		}
	}

	user, err := p.repo.GetUserByID(ctx, params.UserID)
	if err != nil {
		return nil, err
	}

	oldRole := user.Role
	user.Role = targetRole
	user.UpdatedAt = time.Now()

	if err := p.repo.UpdateUser(ctx, user); err != nil {
		return nil, err
	}

	p.publishEvent(EventUserRoleChanged, &UserRoleChangedEventPayload{
		CallerID:   params.Caller.UserID,
		CallerRole: params.Caller.Role,
		UserID:     params.UserID,
		OldRole:    oldRole,
		NewRole:    user.Role,
		User:       user,
	})

	return user, nil
}

// BanUser suspends a user account and immediately invalidates all active sessions.
func (p *Plugin) BanUser(ctx context.Context, params BanUserParams) (*entity.User, error) {
	if params.UserID == "" {
		return nil, ErrInvalidParameter
	}

	if !p.hasPermission(params.Caller, Permissions{ResourceUser: {ActionBan}}, ConnectorAND) {
		return nil, ErrForbidden
	}

	// Prevent self-suspension
	if params.Caller.UserID != "" && params.Caller.UserID == params.UserID {
		return nil, ErrCannotBanSelf
	}

	user, err := p.repo.GetUserByID(ctx, params.UserID)
	if err != nil {
		return nil, err
	}

	reason := strings.TrimSpace(params.BanReason)
	if reason == "" {
		reason = p.config.DefaultBanReason
	}

	var expires *time.Time
	if params.BanExpiresIn != nil && *params.BanExpiresIn > 0 {
		exp := time.Now().Add(*params.BanExpiresIn)
		expires = &exp
	} else if p.config.DefaultBanExpiresIn > 0 {
		exp := time.Now().Add(p.config.DefaultBanExpiresIn)
		expires = &exp
	}

	user.Banned = true
	user.BanReason = &reason
	user.BanExpires = expires
	user.UpdatedAt = time.Now()

	if err := p.repo.UpdateUser(ctx, user); err != nil {
		return nil, err
	}

	// Invalidate all active sessions for the suspended user
	_ = p.repo.DeleteSessionsByUserID(ctx, params.UserID)

	p.publishEvent(EventUserBanned, &UserBannedEventPayload{
		CallerID:   params.Caller.UserID,
		CallerRole: params.Caller.Role,
		UserID:     params.UserID,
		BanReason:  reason,
		BanExpires: expires,
		User:       user,
	})

	return user, nil
}

// UnbanUser lifts an account suspension and restores access.
func (p *Plugin) UnbanUser(ctx context.Context, params UnbanUserParams) (*entity.User, error) {
	if params.UserID == "" {
		return nil, ErrInvalidParameter
	}

	if !p.hasPermission(params.Caller, Permissions{ResourceUser: {ActionBan}}, ConnectorAND) {
		return nil, ErrForbidden
	}

	user, err := p.repo.GetUserByID(ctx, params.UserID)
	if err != nil {
		return nil, err
	}

	user.Banned = false
	user.BanReason = nil
	user.BanExpires = nil
	user.UpdatedAt = time.Now()

	if err := p.repo.UpdateUser(ctx, user); err != nil {
		return nil, err
	}

	p.publishEvent(EventUserUnbanned, &UserUnbannedEventPayload{
		CallerID:   params.Caller.UserID,
		CallerRole: params.Caller.Role,
		UserID:     params.UserID,
		User:       user,
	})

	return user, nil
}

// SetUserPassword directly overwrites a user's credential password with length constraint checks.
func (p *Plugin) SetUserPassword(ctx context.Context, params SetUserPasswordParams) error {
	if params.UserID == "" || params.NewPassword == "" {
		return ErrInvalidParameter
	}

	if !p.hasPermission(params.Caller, Permissions{ResourceUser: {ActionSetPassword}}, ConnectorAND) {
		return ErrForbidden
	}

	if len(params.NewPassword) < p.config.MinPasswordLength {
		return ErrPasswordTooShort
	}
	if len(params.NewPassword) > p.config.MaxPasswordLength {
		return ErrPasswordTooLong
	}

	if _, err := p.repo.GetUserByID(ctx, params.UserID); err != nil {
		return err
	}

	hash, err := p.hashPassword(params.NewPassword)
	if err != nil {
		return err
	}

	if err := p.repo.LinkCredentialAccount(ctx, params.UserID, hash); err != nil {
		return err
	}

	p.publishEvent(EventUserPasswordChanged, &UserPasswordChangedEventPayload{
		CallerID:   params.Caller.UserID,
		CallerRole: params.Caller.Role,
		UserID:     params.UserID,
	})

	return nil
}

// ImpersonateUser generates a temporary session masquerading as the target user.
func (p *Plugin) ImpersonateUser(ctx context.Context, params ImpersonateUserParams) (*ImpersonateResult, error) {
	if params.UserID == "" {
		return nil, ErrInvalidParameter
	}

	if !p.hasPermission(params.Caller, Permissions{ResourceUser: {ActionImpersonate}}, ConnectorAND) {
		return nil, ErrForbidden
	}

	// Prevent self-impersonation
	if params.Caller.UserID != "" && params.Caller.UserID == params.UserID {
		return nil, ErrCannotImpersonateSelf
	}

	targetUser, err := p.repo.GetUserByID(ctx, params.UserID)
	if err != nil {
		return nil, err
	}

	// Admin-to-admin impersonation check
	if p.isUserAdmin(targetUser) {
		canImpersonateAdmins := p.config.AllowImpersonatingAdmins ||
			p.hasPermission(params.Caller, Permissions{ResourceUser: {ActionImpersonateAdmins}}, ConnectorAND)
		if !canImpersonateAdmins {
			return nil, ErrCannotImpersonateAdmin
		}
	}

	duration := p.config.ImpersonationSessionDuration
	if params.Duration != nil && *params.Duration > 0 {
		duration = *params.Duration
	}

	token, err := p.generateToken(32)
	if err != nil {
		return nil, err
	}

	adminID := params.Caller.UserID
	var impersonatedBy *string
	if adminID != "" {
		impersonatedBy = &adminID
	}

	sessionParams := &dto.CreateSessionParams{
		UserID:         targetUser.ID,
		Token:          token,
		ExpiresAt:      time.Now().Add(duration),
		CreatedAt:      time.Now(),
		IPAddress:      params.IPAddress,
		UserAgent:      params.UserAgent,
		ImpersonatedBy: impersonatedBy,
	}

	session, err := p.repo.CreateSession(ctx, sessionParams)
	if err != nil {
		return nil, err
	}

	var adminSessionToken string
	if params.Caller.Extra != nil {
		if val, ok := params.Caller.Extra[ExtraKeyAdminSession]; ok {
			if sToken, ok := val.(string); ok {
				adminSessionToken = sToken
			}
		}
	}

	p.publishEvent(EventUserImpersonated, &UserImpersonatedEventPayload{
		CallerID:     params.Caller.UserID,
		CallerRole:   params.Caller.Role,
		TargetUserID: targetUser.ID,
		Session:      session,
	})

	return &ImpersonateResult{
		Session:           session,
		User:              targetUser,
		AdminSessionToken: adminSessionToken,
	}, nil
}

// StopImpersonating invalidates the masquerade session and returns the original administrator details.
func (p *Plugin) StopImpersonating(ctx context.Context, params StopImpersonatingParams) (*StopImpersonatingResult, error) {
	if params.ImpersonatedSessionToken == "" {
		return nil, ErrInvalidParameter
	}

	session, err := p.repo.GetSessionByToken(ctx, params.ImpersonatedSessionToken)
	if err != nil {
		return nil, err
	}

	if session.ImpersonatedBy == nil || *session.ImpersonatedBy == "" {
		return nil, ErrNotImpersonating
	}

	adminUserID := *session.ImpersonatedBy

	// Revoke the temporary impersonation session
	_ = p.repo.DeleteSession(ctx, params.ImpersonatedSessionToken)

	adminUser, err := p.repo.GetUserByID(ctx, adminUserID)
	if err != nil {
		return nil, err
	}

	var adminSession *entity.Session
	if params.AdminSessionToken != "" {
		adminSession, _ = p.repo.GetSessionByToken(ctx, params.AdminSessionToken)
	}

	p.publishEvent(EventImpersonationStopped, &ImpersonationStoppedEventPayload{
		AdminUserID:  adminUserID,
		TargetUserID: session.UserID,
		SessionToken: params.ImpersonatedSessionToken,
	})

	return &StopImpersonatingResult{
		AdminSession: adminSession,
		AdminUser:    adminUser,
	}, nil
}

// ListUserSessions retrieves all active authentication sessions for a given user.
func (p *Plugin) ListUserSessions(ctx context.Context, params ListUserSessionsParams) ([]*entity.Session, error) {
	if params.UserID == "" {
		return nil, ErrInvalidParameter
	}

	if !p.hasPermission(params.Caller, Permissions{ResourceSession: {ActionSessionList}}, ConnectorAND) {
		return nil, ErrForbidden
	}

	return p.repo.ListSessionsByUserID(ctx, params.UserID)
}

// RevokeUserSession invalidates a specific active session.
func (p *Plugin) RevokeUserSession(ctx context.Context, params RevokeUserSessionParams) error {
	if params.SessionToken == "" {
		return ErrInvalidParameter
	}

	if !p.hasPermission(params.Caller, Permissions{ResourceSession: {ActionSessionRevoke}}, ConnectorAND) {
		return ErrForbidden
	}

	if err := p.repo.DeleteSession(ctx, params.SessionToken); err != nil {
		return err
	}

	p.publishEvent(EventSessionRevoked, &SessionRevokedEventPayload{
		CallerID:     params.Caller.UserID,
		CallerRole:   params.Caller.Role,
		SessionToken: params.SessionToken,
	})

	return nil
}

// RevokeUserSessions invalidates all active sessions belonging to the given user.
func (p *Plugin) RevokeUserSessions(ctx context.Context, params RevokeUserSessionsParams) error {
	if params.UserID == "" {
		return ErrInvalidParameter
	}

	if !p.hasPermission(params.Caller, Permissions{ResourceSession: {ActionSessionRevoke}}, ConnectorAND) {
		return ErrForbidden
	}

	if err := p.repo.DeleteSessionsByUserID(ctx, params.UserID); err != nil {
		return err
	}

	p.publishEvent(EventAllSessionsRevoked, &AllSessionsRevokedEventPayload{
		CallerID:   params.Caller.UserID,
		CallerRole: params.Caller.Role,
		UserID:     params.UserID,
	})

	return nil
}

// CheckPermission evaluates whether the caller satisfies the provided permission matrix.
func (p *Plugin) CheckPermission(ctx context.Context, params CheckPermissionParams) (bool, error) {
	return p.hasPermission(params.Caller, params.Permissions, params.Connector), nil
}

// CheckUserBanStatus is a moderation hook for authentication and session verification workflows.
// If the user is currently suspended and the suspension period has expired, it automatically lifts the suspension.
// If the suspension remains active or is permanent, it returns ErrUserBanned.
func (p *Plugin) CheckUserBanStatus(ctx context.Context, user *entity.User) error {
	if user == nil || !user.Banned {
		return nil
	}

	// Automatic unban for expired suspensions
	if user.BanExpires != nil && time.Now().After(*user.BanExpires) {
		user.Banned = false
		user.BanReason = nil
		user.BanExpires = nil
		user.UpdatedAt = time.Now()
		_ = p.repo.UpdateUser(ctx, user)

		p.publishEvent(EventUserUnbanned, &UserUnbannedEventPayload{
			UserID: user.ID,
			User:   user,
		})

		return nil
	}

	return ErrUserBanned
}
