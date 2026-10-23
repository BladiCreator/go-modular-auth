package admin

import (
	"context"
	"errors"
	"strings"
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	"github.com/BladiCreator/go-modular-auth/adapter"
	sdk "github.com/BladiCreator/go-modular-auth/plugin-sdk"
	"github.com/BladiCreator/go-modular-auth/plugins/admin/cache"
	"github.com/BladiCreator/go-modular-auth/plugins/organizations"
	corestore "github.com/BladiCreator/go-modular-auth/store"
	"github.com/BladiCreator/go-modular-auth/user"
	"github.com/BladiCreator/go-modular-auth/verification"
)

type service struct {
	ctx        *sdk.Context
	cfg        Config
	usersRepo  *sdk.Repository[UserRecord]
	cache      cache.Cache
	authorizer Authorizer
	orgs       organizations.Organization
}

var _ Admin = (*service)(nil)

func newService(ctx *sdk.Context, cfg Config) *service {
	var usersRepo *sdk.Repository[UserRecord]
	if ctx != nil {
		usersRepo = sdk.Model[UserRecord](ctx, ModelAdminUsers)
	}

	s := &service{
		ctx:        ctx,
		cfg:        cfg,
		usersRepo:  usersRepo,
		cache:      cache.New(ctx.Cache()),
		authorizer: cfg.Authorizer,
		orgs:       cfg.Organizations,
	}

	s.registerHooks()
	return s
}

func (s *service) now() time.Time {
	if s.ctx != nil {
		return s.ctx.Now()
	}
	return time.Now()
}

func (s *service) publish(ctx context.Context, name auth.EventName, subject string, payload any) {
	if s.ctx != nil && s.ctx.Events() != nil {
		s.ctx.Events().Publish(ctx, auth.Event{
			Name:    name,
			Time:    s.now(),
			Subject: subject,
			Payload: payload,
		})
	}
}

func (s *service) isAdmin(ctx context.Context, userID string) (bool, error) {
	if s.usersRepo == nil {
		return false, nil
	}
	rec, err := s.usersRepo.FindOne(ctx, adapter.Eq("user_id", userID))
	if err != nil {
		if errors.Is(err, adapter.ErrNotFound) {
			return false, nil
		}
		return false, err
	}
	return rec.IsAdmin, nil
}

func (s *service) getUser(ctx context.Context, userID string) (*UserRecord, error) {
	if s.usersRepo == nil {
		return nil, ErrUserNotFound
	}
	rec, err := s.usersRepo.FindOne(ctx, adapter.Eq("user_id", userID))
	if err != nil {
		if errors.Is(err, adapter.ErrNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	return rec, nil
}

func (s *service) isUserDisabled(ctx context.Context, userID string) (bool, error) {
	if s.usersRepo == nil {
		return false, nil
	}
	rec, err := s.usersRepo.FindOne(ctx, adapter.Eq("user_id", userID))
	if err != nil {
		if errors.Is(err, adapter.ErrNotFound) {
			return false, nil
		}
		return false, err
	}
	return rec.Disabled, nil
}

func (s *service) upsertUser(ctx context.Context, rec *UserRecord) error {
	if s.usersRepo == nil {
		return nil
	}
	existing, err := s.usersRepo.FindOne(ctx, adapter.Eq("user_id", rec.UserID))
	if err == nil && existing != nil {
		_, err := s.usersRepo.Update(ctx, []adapter.Condition{adapter.Eq("user_id", rec.UserID)}, map[string]any{
			"email":           rec.Email,
			"disabled":        rec.Disabled,
			"disabled_at":     rec.DisabledAt,
			"disabled_reason": rec.DisabledReason,
			"is_admin":        rec.IsAdmin,
			"role":            rec.Role,
			"metadata":        rec.Metadata,
			"updated_at":      rec.UpdatedAt,
		})
		return err
	}
	return s.usersRepo.Create(ctx, rec)
}

func (s *service) updateUserStatus(ctx context.Context, userID string, disabled bool, reason string, at *time.Time) error {
	if s.usersRepo == nil {
		return ErrUserNotFound
	}
	affected, err := s.usersRepo.Update(ctx, []adapter.Condition{adapter.Eq("user_id", userID)}, map[string]any{
		"disabled":        disabled,
		"disabled_reason": reason,
		"disabled_at":     at,
		"updated_at":      s.now(),
	})
	if err != nil {
		return err
	}
	if affected == 0 {
		return ErrUserNotFound
	}
	return nil
}

func (s *service) deleteUser(ctx context.Context, userID string) error {
	if s.usersRepo == nil {
		return nil
	}
	_, err := s.usersRepo.Delete(ctx, adapter.Eq("user_id", userID))
	return err
}

func (s *service) setAdminRole(ctx context.Context, userID string, isAdmin bool, role string) error {
	if s.usersRepo == nil {
		return nil
	}
	affected, err := s.usersRepo.Update(ctx, []adapter.Condition{adapter.Eq("user_id", userID)}, map[string]any{
		"is_admin":   isAdmin,
		"role":       role,
		"updated_at": s.now(),
	})
	if err != nil {
		return err
	}
	if affected == 0 {
		coreUser, err := s.ctx.Store().Users().GetByID(ctx, userID)
		if err != nil {
			return err
		}
		now := s.now()
		return s.usersRepo.Create(ctx, &UserRecord{
			UserID:    coreUser.ID,
			Email:     coreUser.Email,
			IsAdmin:   isAdmin,
			Role:      role,
			CreatedAt: coreUser.CreatedAt,
			UpdatedAt: now,
		})
	}
	return nil
}

func (s *service) listUsers(ctx context.Context, filter ListFilter) ([]*UserRecord, int, error) {
	if s.usersRepo == nil {
		return []*UserRecord{}, 0, nil
	}
	var where []adapter.Condition
	if filter.Status == "active" {
		where = append(where, adapter.Eq("disabled", false))
	} else if filter.Status == "disabled" {
		where = append(where, adapter.Eq("disabled", true))
	}
	if filter.Search != "" {
		where = append(where, adapter.Condition{
			Field:    "email",
			Operator: adapter.OpLike,
			Value:    "%" + filter.Search + "%",
		})
	}
	total, err := s.usersRepo.Count(ctx, where...)
	if err != nil {
		return nil, 0, err
	}
	rows, err := s.usersRepo.FindMany(ctx, adapter.Query{
		Model:  ModelAdminUsers,
		Where:  where,
		Limit:  filter.Limit,
		Offset: filter.Offset,
		SortBy: "created_at",
		Desc:   true,
	})
	if err != nil {
		return nil, 0, err
	}
	records := make([]*UserRecord, len(rows))
	for i := range rows {
		records[i] = &rows[i]
	}
	return records, int(total), nil
}

func (s *service) transaction(ctx context.Context, fn func(txCtx context.Context) error) error {
	if s.ctx != nil && s.ctx.Adapter() != nil {
		return s.ctx.Adapter().Transaction(ctx, func(txCtx context.Context, tx adapter.Adapter) error {
			return fn(txCtx)
		})
	}
	return fn(ctx)
}

// authorize verifies that the caller principal has sufficient administrative permissions.
func (s *service) authorize(ctx context.Context, p auth.Principal, action string, targetUserID string) error {
	if p.Subject == "" {
		return ErrUnauthorized
	}

	if s.authorizer != nil {
		return s.authorizer.Authorize(ctx, p, action, targetUserID)
	}

	// Default Authorization: Principal must be registered as an Administrator in Admin Store.
	isAdmin, err := s.isAdmin(ctx, p.Subject)
	if err != nil || !isAdmin {
		return ErrUnauthorized
	}

	return nil
}

// internalLookupUser retrieves detailed user inspection data without authorization check.
func (s *service) internalLookupUser(ctx context.Context, userID string) (*UserDetail, error) {
	// Fetch core user
	coreUser, err := s.ctx.Store().Users().GetByID(ctx, userID)
	if err != nil {
		if errors.Is(err, corestore.ErrNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}

	// Fetch or synthesize admin record
	adminRec, err := s.getUser(ctx, userID)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			adminRec = &UserRecord{
				UserID:    coreUser.ID,
				Email:     coreUser.Email,
				Disabled:  false,
				CreatedAt: coreUser.CreatedAt,
				UpdatedAt: coreUser.UpdatedAt,
			}
		} else {
			return nil, err
		}
	}

	// Fetch accounts
	accts, err := s.ctx.Store().Accounts().ListByUser(ctx, userID)
	if err != nil && !errors.Is(err, corestore.ErrNotFound) {
		return nil, err
	}
	var accountDetails []AccountDetail
	for _, a := range accts {
		accountDetails = append(accountDetails, AccountDetail{
			ID:         a.ID,
			UserID:     a.UserID,
			Provider:   a.Provider,
			ProviderID: a.ProviderID,
			CreatedAt:  a.CreatedAt,
			UpdatedAt:  a.UpdatedAt,
		})
	}

	// Fetch credentials (sanitized - secrets NEVER exposed)
	creds, err := s.ctx.Store().Credentials().ListByUser(ctx, userID)
	if err != nil && !errors.Is(err, corestore.ErrNotFound) {
		return nil, err
	}
	var credDetails []CredentialDetail
	for _, c := range creds {
		credDetails = append(credDetails, CredentialDetail{
			ID:        c.ID,
			UserID:    c.UserID,
			AccountID: c.AccountID,
			Type:      string(c.Type),
			CreatedAt: c.CreatedAt,
			UpdatedAt: c.UpdatedAt,
			RevokedAt: c.RevokedAt,
		})
	}

	// Fetch active sessions
	sessions, err := s.ctx.Store().Sessions().ListByUser(ctx, userID)
	if err != nil && !errors.Is(err, corestore.ErrNotFound) {
		return nil, err
	}
	var sessionDetails []SessionDetail
	for _, sess := range sessions {
		sessionDetails = append(sessionDetails, SessionDetail{
			ID:        sess.ID,
			UserID:    sess.UserID,
			CreatedAt: sess.CreatedAt,
			ExpiresAt: sess.ExpiresAt,
			RevokedAt: sess.RevokedAt,
		})
	}

	return &UserDetail{
		User:        coreUser,
		Record:      adminRec,
		Accounts:    accountDetails,
		Credentials: credDetails,
		Sessions:    sessionDetails,
	}, nil
}

// LookupUser retrieves comprehensive administrative details for a Core User by ID.
func (s *service) LookupUser(ctx context.Context, p auth.Principal, userID string) (*UserDetail, error) {
	if strings.TrimSpace(userID) == "" {
		return nil, ErrInvalidInput
	}
	if err := s.authorize(ctx, p, ActionLookupUser, userID); err != nil {
		return nil, err
	}
	return s.internalLookupUser(ctx, userID)
}

// LookupUserByEmail retrieves comprehensive administrative details for a Core User by email.
func (s *service) LookupUserByEmail(ctx context.Context, p auth.Principal, email string) (*UserDetail, error) {
	cleanEmail, err := user.NormalizeEmail(email)
	if err != nil {
		return nil, ErrInvalidInput
	}

	coreUser, err := s.ctx.Store().Users().GetByEmail(ctx, cleanEmail)
	if err != nil {
		if errors.Is(err, corestore.ErrNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}

	return s.LookupUser(ctx, p, coreUser.ID)
}

// ListUsers returns paginated user records matching filter criteria.
func (s *service) ListUsers(ctx context.Context, p auth.Principal, filter ListFilter) (*UserListResult, error) {
	if err := s.authorize(ctx, p, ActionListUsers, ""); err != nil {
		return nil, err
	}

	if filter.Limit <= 0 {
		filter.Limit = 20
	}
	if filter.Limit > 100 {
		filter.Limit = 100
	}
	if filter.Offset < 0 {
		filter.Offset = 0
	}

	records, total, err := s.listUsers(ctx, filter)
	if err != nil {
		return nil, err
	}

	return &UserListResult{
		Users:  records,
		Total:  total,
		Limit:  filter.Limit,
		Offset: filter.Offset,
	}, nil
}

// internalDisableUser performs account disabling, session revocation, cache update, and event emission.
func (s *service) internalDisableUser(ctx context.Context, actorID, targetUserID, reason string) error {
	// Verify target user exists in Core store
	u, err := s.ctx.Store().Users().GetByID(ctx, targetUserID)
	if err != nil {
		if errors.Is(err, corestore.ErrNotFound) {
			return ErrUserNotFound
		}
		return err
	}

	// Verify current state
	disabled, err := s.isUserDisabled(ctx, targetUserID)
	if err != nil && !errors.Is(err, ErrUserNotFound) {
		return err
	}
	if disabled {
		return ErrUserAlreadyDisabled
	}

	now := s.now()

	// Atomic persistence update
	err = s.transaction(ctx, func(txCtx context.Context) error {
		// Update admin status
		if err := s.updateUserStatus(txCtx, targetUserID, true, reason, &now); err != nil {
			if errors.Is(err, ErrUserNotFound) {
				// Upsert if record was not previously indexed
				rec := &UserRecord{
					UserID:         u.ID,
					Email:          u.Email,
					Disabled:       true,
					DisabledAt:     &now,
					DisabledReason: reason,
					CreatedAt:      u.CreatedAt,
					UpdatedAt:      now,
				}
				if err := s.upsertUser(txCtx, rec); err != nil {
					return err
				}
			} else {
				return err
			}
		}

		// Revoke all active sessions in Core
		_, err := s.ctx.Store().Sessions().RevokeByUser(txCtx, targetUserID, now)
		return err
	})
	if err != nil {
		return err
	}

	// Update cache
	if s.cache != nil {
		_ = s.cache.SetDisabled(ctx, targetUserID, true, s.cfg.CacheTTL)
	}

	// Emit audit event
	s.publish(ctx, EventUserDisabled, targetUserID, UserDisabledPayload{
		ActorID:      actorID,
		TargetUserID: targetUserID,
		Reason:       reason,
		DisabledAt:   now,
	})

	return nil
}

// DisableUser disables a user account, revokes all active sessions, and emits audit events.
func (s *service) DisableUser(ctx context.Context, p auth.Principal, targetUserID string, reason string) error {
	if strings.TrimSpace(targetUserID) == "" {
		return ErrInvalidInput
	}
	if p.Subject == targetUserID {
		return ErrCannotDisableSelf
	}
	if err := s.authorize(ctx, p, ActionDisableUser, targetUserID); err != nil {
		return err
	}
	return s.internalDisableUser(ctx, p.Subject, targetUserID, reason)
}

// internalEnableUser re-enables a user account, updates cache, and emits audit events.
func (s *service) internalEnableUser(ctx context.Context, actorID, targetUserID string) error {
	// Verify target user exists in Core store
	_, err := s.ctx.Store().Users().GetByID(ctx, targetUserID)
	if err != nil {
		if errors.Is(err, corestore.ErrNotFound) {
			return ErrUserNotFound
		}
		return err
	}

	// Verify current status
	disabled, err := s.isUserDisabled(ctx, targetUserID)
	if err != nil && !errors.Is(err, ErrUserNotFound) {
		return err
	}
	if !disabled {
		return ErrUserNotDisabled
	}

	now := s.now()

	// Atomic update in admin store
	err = s.transaction(ctx, func(txCtx context.Context) error {
		return s.updateUserStatus(txCtx, targetUserID, false, "", nil)
	})
	if err != nil {
		return err
	}

	// Update cache
	if s.cache != nil {
		_ = s.cache.SetDisabled(ctx, targetUserID, false, s.cfg.CacheTTL)
	}

	// Emit audit event
	s.publish(ctx, EventUserEnabled, targetUserID, UserEnabledPayload{
		ActorID:      actorID,
		TargetUserID: targetUserID,
		EnabledAt:    now,
	})

	return nil
}

// EnableUser re-enables a disabled user account and emits audit events.
func (s *service) EnableUser(ctx context.Context, p auth.Principal, targetUserID string) error {
	if strings.TrimSpace(targetUserID) == "" {
		return ErrInvalidInput
	}
	if err := s.authorize(ctx, p, ActionEnableUser, targetUserID); err != nil {
		return err
	}
	return s.internalEnableUser(ctx, p.Subject, targetUserID)
}

// internalRevokeUserSessions revokes all sessions for target user and emits audit event.
func (s *service) internalRevokeUserSessions(ctx context.Context, actorID, targetUserID string) error {
	// Verify user exists
	_, err := s.ctx.Store().Users().GetByID(ctx, targetUserID)
	if err != nil {
		if errors.Is(err, corestore.ErrNotFound) {
			return ErrUserNotFound
		}
		return err
	}

	now := s.now()
	_, err = s.ctx.Store().Sessions().RevokeByUser(ctx, targetUserID, now)
	if err != nil {
		return err
	}

	// Emit audit event
	s.publish(ctx, EventSessionRevoked, targetUserID, SessionRevokedPayload{
		ActorID:      actorID,
		TargetUserID: targetUserID,
		RevokedAt:    now,
	})

	return nil
}

// RevokeUserSessions immediately terminates all active sessions for a target user.
func (s *service) RevokeUserSessions(ctx context.Context, p auth.Principal, targetUserID string) error {
	if strings.TrimSpace(targetUserID) == "" {
		return ErrInvalidInput
	}
	if err := s.authorize(ctx, p, ActionRevokeSessions, targetUserID); err != nil {
		return err
	}
	return s.internalRevokeUserSessions(ctx, p.Subject, targetUserID)
}

// InitiatePasswordReset generates a single-use verification token for password reset.
func (s *service) InitiatePasswordReset(ctx context.Context, p auth.Principal, targetUserID string) (string, error) {
	if strings.TrimSpace(targetUserID) == "" {
		return "", ErrInvalidInput
	}
	if err := s.authorize(ctx, p, ActionResetPassword, targetUserID); err != nil {
		return "", err
	}

	// Verify user exists
	_, err := s.ctx.Store().Users().GetByID(ctx, targetUserID)
	if err != nil {
		if errors.Is(err, corestore.ErrNotFound) {
			return "", ErrUserNotFound
		}
		return "", err
	}

	ttl := 1 * time.Hour

	// Use Core IssueToken if available
	var rawToken string
	if s.ctx != nil && s.ctx.Core() != nil {
		rawToken, err = s.ctx.Core().IssueToken(ctx, verification.PurposePasswordReset, targetUserID, ttl)
		if err != nil {
			return "", err
		}
	} else {
		// Fallback for standalone/mocked environments
		raw, hash, err := generateSecureToken()
		if err != nil {
			return "", err
		}
		now := s.now()
		_ = s.ctx.Store().Tokens().DeleteBySubject(ctx, verification.PurposePasswordReset, targetUserID)
		t := &verification.Token{
			ID:        raw[:16],
			Purpose:   verification.PurposePasswordReset,
			Subject:   targetUserID,
			TokenHash: hash,
			ExpiresAt: now.Add(ttl),
			CreatedAt: now,
		}
		if err := s.ctx.Store().Tokens().Create(ctx, t); err != nil {
			return "", err
		}
		rawToken = raw
	}

	// Emit audit event (NEVER include token in payload)
	s.publish(ctx, EventPasswordResetInitiated, targetUserID, PasswordResetInitiatedPayload{
		ActorID:      p.Subject,
		TargetUserID: targetUserID,
		InitiatedAt:  s.now(),
	})

	return rawToken, nil
}

// VerifyUserEmail marks the target user's email as verified.
func (s *service) VerifyUserEmail(ctx context.Context, p auth.Principal, targetUserID string) error {
	if strings.TrimSpace(targetUserID) == "" {
		return ErrInvalidInput
	}
	if err := s.authorize(ctx, p, ActionVerifyEmail, targetUserID); err != nil {
		return err
	}

	u, err := s.ctx.Store().Users().GetByID(ctx, targetUserID)
	if err != nil {
		if errors.Is(err, corestore.ErrNotFound) {
			return ErrUserNotFound
		}
		return err
	}

	now := s.now()
	u.EmailVerified = true
	u.UpdatedAt = now

	if err := s.ctx.Store().Users().Update(ctx, u); err != nil {
		return err
	}

	// Clean up any pending email verification tokens
	_ = s.ctx.Store().Tokens().DeleteBySubject(ctx, verification.PurposeEmailVerification, targetUserID)

	// Emit audit event
	s.publish(ctx, EventEmailVerified, targetUserID, EmailVerifiedPayload{
		ActorID:      p.Subject,
		TargetUserID: targetUserID,
		VerifiedAt:   now,
	})

	return nil
}

// internalInspectAccounts retrieves provider account linkages without authorization check.
func (s *service) internalInspectAccounts(ctx context.Context, targetUserID string) ([]AccountDetail, error) {
	// Verify user exists
	if _, err := s.ctx.Store().Users().GetByID(ctx, targetUserID); err != nil {
		if errors.Is(err, corestore.ErrNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}

	accts, err := s.ctx.Store().Accounts().ListByUser(ctx, targetUserID)
	if err != nil && !errors.Is(err, corestore.ErrNotFound) {
		return nil, err
	}

	var details []AccountDetail
	for _, a := range accts {
		details = append(details, AccountDetail{
			ID:         a.ID,
			UserID:     a.UserID,
			Provider:   a.Provider,
			ProviderID: a.ProviderID,
			CreatedAt:  a.CreatedAt,
			UpdatedAt:  a.UpdatedAt,
		})
	}
	return details, nil
}

// InspectAccounts returns external provider account linkages for a target user.
func (s *service) InspectAccounts(ctx context.Context, p auth.Principal, targetUserID string) ([]AccountDetail, error) {
	if strings.TrimSpace(targetUserID) == "" {
		return nil, ErrInvalidInput
	}
	if err := s.authorize(ctx, p, ActionInspectAccounts, targetUserID); err != nil {
		return nil, err
	}
	return s.internalInspectAccounts(ctx, targetUserID)
}

// internalInspectCredentials retrieves sanitized credential records without authorization check.
// CRITICAL: NEVER exposes secret hashes or salts.
func (s *service) internalInspectCredentials(ctx context.Context, targetUserID string) ([]CredentialDetail, error) {
	// Verify user exists
	if _, err := s.ctx.Store().Users().GetByID(ctx, targetUserID); err != nil {
		if errors.Is(err, corestore.ErrNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}

	creds, err := s.ctx.Store().Credentials().ListByUser(ctx, targetUserID)
	if err != nil && !errors.Is(err, corestore.ErrNotFound) {
		return nil, err
	}

	var details []CredentialDetail
	for _, c := range creds {
		details = append(details, CredentialDetail{
			ID:        c.ID,
			UserID:    c.UserID,
			AccountID: c.AccountID,
			Type:      string(c.Type),
			CreatedAt: c.CreatedAt,
			UpdatedAt: c.UpdatedAt,
			RevokedAt: c.RevokedAt,
		})
	}
	return details, nil
}

// InspectCredentials returns sanitized credential records for a target user.
func (s *service) InspectCredentials(ctx context.Context, p auth.Principal, targetUserID string) ([]CredentialDetail, error) {
	if strings.TrimSpace(targetUserID) == "" {
		return nil, ErrInvalidInput
	}
	if err := s.authorize(ctx, p, ActionInspectCredentials, targetUserID); err != nil {
		return nil, err
	}
	return s.internalInspectCredentials(ctx, targetUserID)
}

// DeleteUser permanently deletes a user, their credentials, accounts, sessions, and admin metadata.
func (s *service) DeleteUser(ctx context.Context, p auth.Principal, targetUserID string) error {
	if strings.TrimSpace(targetUserID) == "" {
		return ErrInvalidInput
	}
	if p.Subject == targetUserID {
		return ErrCannotDeleteSelf
	}
	if err := s.authorize(ctx, p, ActionDeleteUser, targetUserID); err != nil {
		return err
	}

	// Verify user exists
	if _, err := s.ctx.Store().Users().GetByID(ctx, targetUserID); err != nil {
		if errors.Is(err, corestore.ErrNotFound) {
			return ErrUserNotFound
		}
		return err
	}

	now := s.now()

	// Atomic deletion across stores
	err := s.ctx.Store().Transaction(ctx, func(txCtx context.Context) error {
		// Revoke sessions
		_, _ = s.ctx.Store().Sessions().RevokeByUser(txCtx, targetUserID, now)

		// Delete verification tokens
		_ = s.ctx.Store().Tokens().DeleteBySubject(txCtx, verification.PurposeEmailVerification, targetUserID)
		_ = s.ctx.Store().Tokens().DeleteBySubject(txCtx, verification.PurposePasswordReset, targetUserID)

		// Delete credentials
		creds, _ := s.ctx.Store().Credentials().ListByUser(txCtx, targetUserID)
		for _, c := range creds {
			_ = s.ctx.Store().Credentials().Revoke(txCtx, c.ID, now)
		}

		// Delete accounts
		accts, _ := s.ctx.Store().Accounts().ListByUser(txCtx, targetUserID)
		for _, a := range accts {
			_ = s.ctx.Store().Accounts().Delete(txCtx, a.ID)
		}

		// Delete user in core store
		if err := s.ctx.Store().Users().Delete(txCtx, targetUserID); err != nil {
			return err
		}

		// Delete user in admin store
		return s.deleteUser(txCtx, targetUserID)
	})
	if err != nil {
		return err
	}

	// Invalidate cache
	if s.cache != nil {
		_ = s.cache.DeleteDisabled(ctx, targetUserID)
		_ = s.cache.DeleteIsAdmin(ctx, targetUserID)
	}

	// Emit audit event
	s.publish(ctx, EventUserDeleted, targetUserID, UserDeletedPayload{
		ActorID:      p.Subject,
		TargetUserID: targetUserID,
		DeletedAt:    now,
	})

	return nil
}

// SetAdminStatus assigns or revokes administrative status and role for a user.
func (s *service) SetAdminStatus(ctx context.Context, p auth.Principal, targetUserID string, isAdmin bool, role string) error {
	if strings.TrimSpace(targetUserID) == "" {
		return ErrInvalidInput
	}
	if err := s.authorize(ctx, p, ActionSetAdmin, targetUserID); err != nil {
		return err
	}

	// Verify target user exists
	if _, err := s.ctx.Store().Users().GetByID(ctx, targetUserID); err != nil {
		if errors.Is(err, corestore.ErrNotFound) {
			return ErrUserNotFound
		}
		return err
	}

	if err := s.setAdminRole(ctx, targetUserID, isAdmin, role); err != nil {
		return err
	}

	// Invalidate cache
	if s.cache != nil {
		_ = s.cache.DeleteIsAdmin(ctx, targetUserID)
	}

	// Emit audit event
	s.publish(ctx, EventAdminRoleAssigned, targetUserID, AdminRoleAssignedPayload{
		ActorID:      p.Subject,
		TargetUserID: targetUserID,
		IsAdmin:      isAdmin,
		Role:         role,
		AssignedAt:   s.now(),
	})

	return nil
}

// IsUserDisabled checks if a user is currently disabled via cache-aside strategy.
func (s *service) IsUserDisabled(ctx context.Context, userID string) (bool, error) {
	if s.cache != nil {
		disabled, found, err := s.cache.GetDisabled(ctx, userID)
		if err == nil && found {
			return disabled, nil
		}
	}

	disabled, err := s.isUserDisabled(ctx, userID)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return false, nil
		}
		return false, err
	}

	if s.cache != nil {
		_ = s.cache.SetDisabled(ctx, userID, disabled, s.cfg.CacheTTL)
	}

	return disabled, nil
}

// ForOrg returns an organization-scoped administrative capability.
func (s *service) ForOrg(orgID string) ScopedAdmin {
	return &scopedAdminService{
		parent: s,
		orgID:  orgID,
	}
}

// scopedAdminService implements ScopedAdmin.
type scopedAdminService struct {
	parent *service
	orgID  string
}

func (s *scopedAdminService) checkOrgAdmin(ctx context.Context, p auth.Principal) error {
	if s.parent.orgs == nil {
		return ErrOrganizationsNotInstalled
	}
	if p.Subject == "" {
		return ErrUnauthorized
	}
	// Inject Principal into context if not present so organizations.Authorize can read it
	reqCtx := ctx
	if _, ok := auth.PrincipalFrom(reqCtx); !ok {
		reqCtx = auth.WithPrincipal(reqCtx, p)
	}

	// Verify calling principal has admin or owner role in the target organization
	_, err := s.parent.orgs.Authorize(reqCtx, s.orgID, organizations.RoleAdmin)
	if err != nil {
		return ErrUnauthorized
	}
	return nil
}

func (s *scopedAdminService) checkMember(ctx context.Context, targetUserID string) error {
	if s.parent.orgs == nil {
		return ErrOrganizationsNotInstalled
	}
	_, err := s.parent.orgs.GetMember(ctx, s.orgID, targetUserID)
	if err != nil {
		return ErrUserNotInOrganization
	}
	return nil
}

func (s *scopedAdminService) LookupUser(ctx context.Context, p auth.Principal, userID string) (*UserDetail, error) {
	if err := s.checkOrgAdmin(ctx, p); err != nil {
		return nil, err
	}
	if err := s.checkMember(ctx, userID); err != nil {
		return nil, err
	}
	return s.parent.internalLookupUser(ctx, userID)
}

func (s *scopedAdminService) ListUsers(ctx context.Context, p auth.Principal, filter ListFilter) (*UserListResult, error) {
	if err := s.checkOrgAdmin(ctx, p); err != nil {
		return nil, err
	}
	members, err := s.parent.orgs.ListMembers(ctx, s.orgID)
	if err != nil {
		return nil, err
	}

	var users []*UserRecord
	for _, m := range members {
		rec, err := s.parent.getUser(ctx, m.UserID)
		if err == nil {
			if filter.Status == "active" && rec.Disabled {
				continue
			}
			if filter.Status == "disabled" && !rec.Disabled {
				continue
			}
			users = append(users, rec)
		}
	}

	total := len(users)
	limit := filter.Limit
	if limit <= 0 {
		limit = 20
	}
	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}

	start := offset
	if start > total {
		start = total
	}
	end := start + limit
	if end > total {
		end = total
	}

	return &UserListResult{
		Users:  users[start:end],
		Total:  total,
		Limit:  limit,
		Offset: offset,
	}, nil
}

func (s *scopedAdminService) DisableUser(ctx context.Context, p auth.Principal, targetUserID string, reason string) error {
	if err := s.checkOrgAdmin(ctx, p); err != nil {
		return err
	}
	if p.Subject == targetUserID {
		return ErrCannotDisableSelf
	}
	if err := s.checkMember(ctx, targetUserID); err != nil {
		return err
	}
	return s.parent.internalDisableUser(ctx, p.Subject, targetUserID, reason)
}

func (s *scopedAdminService) EnableUser(ctx context.Context, p auth.Principal, targetUserID string) error {
	if err := s.checkOrgAdmin(ctx, p); err != nil {
		return err
	}
	if err := s.checkMember(ctx, targetUserID); err != nil {
		return err
	}
	return s.parent.internalEnableUser(ctx, p.Subject, targetUserID)
}

func (s *scopedAdminService) RevokeUserSessions(ctx context.Context, p auth.Principal, targetUserID string) error {
	if err := s.checkOrgAdmin(ctx, p); err != nil {
		return err
	}
	if err := s.checkMember(ctx, targetUserID); err != nil {
		return err
	}
	return s.parent.internalRevokeUserSessions(ctx, p.Subject, targetUserID)
}

func (s *scopedAdminService) InspectAccounts(ctx context.Context, p auth.Principal, targetUserID string) ([]AccountDetail, error) {
	if err := s.checkOrgAdmin(ctx, p); err != nil {
		return nil, err
	}
	if err := s.checkMember(ctx, targetUserID); err != nil {
		return nil, err
	}
	return s.parent.internalInspectAccounts(ctx, targetUserID)
}

func (s *scopedAdminService) InspectCredentials(ctx context.Context, p auth.Principal, targetUserID string) ([]CredentialDetail, error) {
	if err := s.checkOrgAdmin(ctx, p); err != nil {
		return nil, err
	}
	if err := s.checkMember(ctx, targetUserID); err != nil {
		return nil, err
	}
	return s.parent.internalInspectCredentials(ctx, targetUserID)
}

func (s *scopedAdminService) RemoveUser(ctx context.Context, p auth.Principal, targetUserID string) error {
	if err := s.checkOrgAdmin(ctx, p); err != nil {
		return err
	}
	if err := s.checkMember(ctx, targetUserID); err != nil {
		return err
	}
	return s.parent.orgs.RemoveMember(ctx, s.orgID, targetUserID)
}
