package passwordpolicy

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"unicode"

	auth "github.com/BladiCreator/go-modular-auth"
	sdk "github.com/BladiCreator/go-modular-auth/plugin-sdk"
	"github.com/BladiCreator/go-modular-auth-password-policy/store"
	"github.com/BladiCreator/go-modular-auth/credential"
	corestore "github.com/BladiCreator/go-modular-auth/store"
)

type service struct {
	ctx       *sdk.Context
	auth      *auth.Auth
	coreStore corestore.Store
	cfg       Config
}

var _ PasswordPolicy = (*service)(nil)

func newService(ctx *sdk.Context, cfg Config) *service {
	return &service{
		ctx:       ctx,
		auth:      ctx.Core(),
		coreStore: ctx.Store(),
		cfg:       cfg,
	}
}

// ValidatePassword evaluates a candidate password against the configured policy.
func (s *service) ValidatePassword(ctx context.Context, password string, userID string) error {
	res, err := s.ValidatePasswordDetailed(ctx, password, userID)
	if err != nil {
		return err
	}
	if !res.Valid {
		return res.Error
	}
	return nil
}

// ValidatePasswordDetailed evaluates a candidate password and returns structured validation status and violations.
func (s *service) ValidatePasswordDetailed(ctx context.Context, password string, userID string) (*ValidationResult, error) {
	policy := s.cfg.Policy
	var violations []string

	// 1. Length checks
	if len(password) < policy.MinLength {
		violations = append(violations, "min_length")
	}
	if policy.MaxLength > 0 && len(password) > policy.MaxLength {
		violations = append(violations, "max_length")
	}

	// 2. Complexity checks
	var hasUpper, hasLower, hasDigit, hasSymbol bool
	for _, r := range password {
		switch {
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsDigit(r):
			hasDigit = true
		case unicode.IsPunct(r) || unicode.IsSymbol(r):
			hasSymbol = true
		}
	}

	if policy.RequireUppercase && !hasUpper {
		violations = append(violations, "complexity_uppercase")
	}
	if policy.RequireLowercase && !hasLower {
		violations = append(violations, "complexity_lowercase")
	}
	if policy.RequireDigit && !hasDigit {
		violations = append(violations, "complexity_digit")
	}
	if policy.RequireSymbol && !hasSymbol {
		violations = append(violations, "complexity_symbol")
	}

	// 3. Compromised / Breached password check
	if policy.RejectCompromised && s.cfg.CompromisedChecker != nil {
		isCompromised, err := s.cfg.CompromisedChecker(ctx, password)
		if err == nil && isCompromised {
			violations = append(violations, "compromised")
		}
	}

	// 4. Password history and reuse prevention check
	if userID != "" && policy.HistoryCount > 0 {
		// A. Check against current active password credential
		if s.coreStore != nil {
			creds, _ := s.coreStore.Credentials().ListByUser(ctx, userID)
			for _, c := range creds {
				if c.Type == credential.TypePassword && c.RevokedAt == nil {
					if err := s.cfg.Hasher.Verify(ctx, c.Secret, password); err == nil {
						violations = append(violations, "reuse_current")
						break
					}
				}
			}
		}

		// B. Check against historical password hashes
		if !slices.Contains(violations, "reuse_current") && s.cfg.Store != nil {
			history, _ := s.cfg.Store.GetHistory(ctx, userID, policy.HistoryCount)
			for _, h := range history {
				if err := s.cfg.Hasher.Verify(ctx, h.PasswordHash, password); err == nil {
					violations = append(violations, "reuse_history")
					break
				}
			}
		}
	}

	now := s.cfg.Clock()
	if len(violations) > 0 {
		s.emitAudit(ctx, EventPolicyViolation, PolicyViolationPayload{
			UserID:     userID,
			Violations: violations,
			Timestamp:  now,
		})

		var primaryErr error
		switch {
		case slices.Contains(violations, "min_length"):
			primaryErr = ErrPasswordTooShort
		case slices.Contains(violations, "max_length"):
			primaryErr = ErrPasswordTooLong
		case slices.Contains(violations, "complexity_uppercase"):
			primaryErr = ErrPasswordRequiresUppercase
		case slices.Contains(violations, "complexity_lowercase"):
			primaryErr = ErrPasswordRequiresLowercase
		case slices.Contains(violations, "complexity_digit"):
			primaryErr = ErrPasswordRequiresDigit
		case slices.Contains(violations, "complexity_symbol"):
			primaryErr = ErrPasswordRequiresSymbol
		case slices.Contains(violations, "reuse_current") || slices.Contains(violations, "reuse_history"):
			primaryErr = ErrPasswordInHistory
		case slices.Contains(violations, "compromised"):
			primaryErr = ErrPasswordCompromised
		default:
			primaryErr = ErrPasswordTooShort
		}

		return &ValidationResult{
			Valid:      false,
			Violations: violations,
			Error:      primaryErr,
		}, nil
	}

	s.emitAudit(ctx, EventPolicyValidated, PolicyValidatedPayload{
		UserID:    userID,
		Timestamp: now,
	})

	return &ValidationResult{
		Valid: true,
	}, nil
}

// ChangePassword enforces policy, changes password via Core, and records password history.
func (s *service) ChangePassword(ctx context.Context, in ChangePasswordInput) error {
	if in.UserID == "" || in.NewPassword == "" {
		return ErrInvalidInput
	}

	// 1. Enforce policy and reuse check
	if err := s.ValidatePassword(ctx, in.NewPassword, in.UserID); err != nil {
		return err
	}

	// 2. Execute Core ChangePassword
	coreIn := auth.ChangePasswordInput{
		UserID:            in.UserID,
		CurrentPassword:   in.CurrentPassword,
		NewPassword:       in.NewPassword,
		CurrentSessionID:  in.CurrentSessionID,
		KeepOtherSessions: in.KeepOtherSessions,
	}

	return s.auth.ChangePassword(ctx, coreIn)
}

// ResetPassword enforces policy, resets password via Core, and records history.
func (s *service) ResetPassword(ctx context.Context, in ResetPasswordInput) error {
	if in.Token == "" || in.NewPassword == "" {
		return ErrInvalidInput
	}

	var userID string
	if s.coreStore != nil && s.coreStore.Tokens() != nil {
		sum := sha256.Sum256([]byte(in.Token))
		tokenHash := hex.EncodeToString(sum[:])
		t, err := s.coreStore.Tokens().GetByHash(ctx, tokenHash)
		if err == nil && t != nil && !t.Used() && !t.Expired(s.cfg.Clock()) {
			userID = t.Subject
		}
	}

	// 1. Policy and reuse check
	if err := s.ValidatePassword(ctx, in.NewPassword, userID); err != nil {
		return err
	}

	// 2. Execute Core ResetPassword
	coreIn := auth.ResetPasswordInput{
		Token:       in.Token,
		NewPassword: in.NewPassword,
	}

	return s.auth.ResetPassword(ctx, coreIn)
}

// RecordHistory stores a password hash in the user's password history and prunes old records.
func (s *service) RecordHistory(ctx context.Context, userID, hash string) error {
	if userID == "" || hash == "" {
		return ErrInvalidInput
	}

	// Deduplicate if already recorded as the latest entry
	recent, _ := s.cfg.Store.GetHistory(ctx, userID, 1)
	if len(recent) > 0 && recent[0].PasswordHash == hash {
		return nil
	}

	entry := &store.PasswordHistory{
		ID:           generateID("pwd_hist"),
		UserID:       userID,
		PasswordHash: hash,
		CreatedAt:    s.cfg.Clock(),
	}

	if err := s.cfg.Store.SaveHistory(ctx, entry); err != nil {
		return err
	}

	if s.cfg.Policy.HistoryCount > 0 {
		_ = s.cfg.Store.PruneHistory(ctx, userID, s.cfg.Policy.HistoryCount)
	}

	s.emitAudit(ctx, EventHistoryRecorded, HistoryRecordedPayload{
		UserID:    userID,
		HistoryID: entry.ID,
		Timestamp: entry.CreatedAt,
	})

	return nil
}

// GetHistory retrieves historical password records for a user up to limit.
func (s *service) GetHistory(ctx context.Context, userID string, limit int) ([]*PasswordHistory, error) {
	if userID == "" {
		return nil, ErrInvalidInput
	}
	return s.cfg.Store.GetHistory(ctx, userID, limit)
}

// ClearHistory removes all historical password records for a user.
func (s *service) ClearHistory(ctx context.Context, userID string) error {
	if userID == "" {
		return ErrInvalidInput
	}
	return s.cfg.Store.DeleteHistoryByUser(ctx, userID)
}

// GetPolicy returns the currently active policy configuration.
func (s *service) GetPolicy() Policy {
	return s.cfg.Policy
}

func (s *service) recordCurrentPasswordHash(ctx context.Context, userID string) {
	if s.coreStore == nil || s.cfg.Store == nil || s.cfg.Policy.HistoryCount <= 0 {
		return
	}

	creds, err := s.coreStore.Credentials().ListByUser(ctx, userID)
	if err != nil {
		return
	}

	for _, c := range creds {
		if c.Type == credential.TypePassword && c.RevokedAt == nil {
			_ = s.RecordHistory(ctx, userID, c.Secret)
			break
		}
	}
}

func (s *service) emitAudit(ctx context.Context, name auth.EventName, payload any) {
	if s.ctx != nil && s.ctx.Events() != nil {
		s.ctx.Events().Publish(ctx, auth.Event{
			Name:    name,
			Time:    s.cfg.Clock(),
			Payload: payload,
		})
	}
}

func generateID(prefix string) string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%s_%s", prefix, hex.EncodeToString(b))
}
