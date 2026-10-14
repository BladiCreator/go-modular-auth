package twofactor

import (
	"context"
	"crypto/subtle"
	"errors"
	"strings"
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	"github.com/BladiCreator/go-modular-auth/plugins/twofactor/cache"
	"github.com/BladiCreator/go-modular-auth/adapter"
	adaptermem "github.com/BladiCreator/go-modular-auth/adapter/memory"
	sdk "github.com/BladiCreator/go-modular-auth/plugin-sdk"
	"github.com/BladiCreator/go-modular-auth/schema"
)

type service struct {
	ctx        *sdk.Context
	cfg        Config
	cache      *cache.Cache
	protector  SecretProtector
	factors    *sdk.Repository[FactorRecord]
	recovery   *sdk.Repository[RecoveryCodeRecord]
	challenges *sdk.Repository[ChallengeRecord]
}

var _ TwoFactor = (*service)(nil)

func newService(ctx *sdk.Context, cfg Config) *service {
	if ctx == nil {
		memAdapter := adaptermem.New()
		s := schema.New()
		_ = RegisterSchema(s)
		_ = memAdapter.RegisterSchema(context.Background(), s)
		ctx = sdk.NewTestContext(memAdapter, nil, nil)
	}

	var c *cache.Cache
	if ctx.Cache() != nil {
		c = cache.New(ctx.Cache())
	} else {
		c = cache.New(nil)
	}

	return &service{
		ctx:        ctx,
		cfg:        cfg,
		cache:      c,
		protector:  cfg.Protector,
		factors:    sdk.Model[FactorRecord](ctx, ModelTwoFactors),
		recovery:   sdk.Model[RecoveryCodeRecord](ctx, ModelRecoveryCodes),
		challenges: sdk.Model[ChallengeRecord](ctx, ModelMFAChallenges),
	}
}

func (s *service) now() time.Time {
	if s.ctx != nil {
		return s.ctx.Now()
	}
	return time.Now().UTC()
}

func (s *service) GetStatus(ctx context.Context, userID string) (*Status, error) {
	if strings.TrimSpace(userID) == "" {
		return nil, ErrInvalidInput
	}

	records, err := s.factors.FindMany(ctx, adapter.Query{
		Where: []adapter.Condition{adapter.Eq("user_id", userID)},
	})
	if err != nil {
		return nil, err
	}

	activeCodes, err := s.recovery.FindMany(ctx, adapter.Query{
		Where: []adapter.Condition{adapter.Eq("user_id", userID), adapter.IsNull("used_at")},
	})
	if err != nil {
		return nil, err
	}

	factors := make([]Factor, 0, len(records))
	hasConfirmed := false
	var primaryType FactorType

	for _, r := range records {
		f := Factor{
			ID:          r.ID,
			UserID:      r.UserID,
			Type:        FactorType(r.Type),
			Label:       r.Label,
			Confirmed:   r.Confirmed,
			ConfirmedAt: r.ConfirmedAt,
			LastUsedAt:  r.LastUsedAt,
			CreatedAt:   r.CreatedAt,
			UpdatedAt:   r.UpdatedAt,
		}
		factors = append(factors, f)
		if f.Confirmed {
			hasConfirmed = true
			if primaryType == "" {
				primaryType = f.Type
			}
		}
	}

	return &Status{
		Enabled:            hasConfirmed,
		Factors:            factors,
		RecoveryCodesCount: len(activeCodes),
		PrimaryFactorType:  primaryType,
	}, nil
}

func (s *service) IsEnabled(ctx context.Context, userID string) (bool, error) {
	status, err := s.GetStatus(ctx, userID)
	if err != nil {
		return false, err
	}
	return status.Enabled, nil
}

func (s *service) ListFactors(ctx context.Context, userID string) ([]Factor, error) {
	status, err := s.GetStatus(ctx, userID)
	if err != nil {
		return nil, err
	}
	return status.Factors, nil
}

func (s *service) EnrollTOTP(ctx context.Context, userID string, opts ...EnrollOption) (*TOTPEnrollment, error) {
	if strings.TrimSpace(userID) == "" {
		return nil, ErrInvalidInput
	}

	enrollCfg := EnrollConfig{
		Issuer:      s.cfg.Issuer,
		AccountName: userID,
	}
	for _, opt := range opts {
		opt(&enrollCfg)
	}

	secret, err := GenerateTOTPSecret()
	if err != nil {
		return nil, err
	}

	encryptedSecret, err := s.protector.Encrypt([]byte(secret))
	if err != nil {
		return nil, err
	}

	factorID, err := GenerateRandomID(16)
	if err != nil {
		return nil, err
	}

	now := s.now()
	rec := &FactorRecord{
		ID:               factorID,
		UserID:           userID,
		Type:             string(FactorTypeTOTP),
		Label:            enrollCfg.Label,
		EncryptedSecret:  encryptedSecret,
		Confirmed:        false,
		LastUsedTimeStep: -1,
		CreatedAt:        now,
		UpdatedAt:        now,
	}

	if err := s.factors.Create(ctx, rec); err != nil {
		return nil, err
	}

	uri := BuildProvisioningURI(enrollCfg.Issuer, enrollCfg.AccountName, secret)

	return &TOTPEnrollment{
		FactorID:        factorID,
		Secret:          secret,
		ProvisioningURI: uri,
		Issuer:          enrollCfg.Issuer,
		AccountName:     enrollCfg.AccountName,
	}, nil
}

func (s *service) ConfirmTOTP(ctx context.Context, userID, factorID, code string) error {
	if strings.TrimSpace(userID) == "" || strings.TrimSpace(factorID) == "" || strings.TrimSpace(code) == "" {
		return ErrInvalidInput
	}

	rec, err := s.factors.FindOne(ctx, adapter.Eq("id", factorID))
	if err != nil {
		if errors.Is(err, adapter.ErrNotFound) {
			return ErrFactorNotFound
		}
		return err
	}

	if rec.UserID != userID {
		return ErrFactorNotFound
	}

	if rec.Confirmed {
		return ErrFactorAlreadyConfirmed
	}

	decrypted, err := s.protector.Decrypt(rec.EncryptedSecret)
	if err != nil {
		return err
	}

	now := s.now()
	matchedStep, ok := ValidateTOTP(string(decrypted), code, now, s.cfg.StepDuration, s.cfg.SkewSteps)
	if !ok {
		return ErrInvalidCode
	}

	if matchedStep <= rec.LastUsedTimeStep {
		return ErrReplayDetected
	}

	rec.Confirmed = true
	rec.ConfirmedAt = &now
	rec.LastUsedAt = &now
	rec.LastUsedTimeStep = matchedStep
	rec.UpdatedAt = now

	_, err = s.factors.Update(ctx, []adapter.Condition{adapter.Eq("id", rec.ID)}, map[string]any{
		"confirmed":           rec.Confirmed,
		"confirmed_at":        rec.ConfirmedAt,
		"last_used_at":        rec.LastUsedAt,
		"last_used_time_step": rec.LastUsedTimeStep,
		"updated_at":          rec.UpdatedAt,
	})
	if err != nil {
		return err
	}

	// Publish TwoFactorEnabled event
	if s.ctx != nil && s.ctx.Events() != nil {
		s.ctx.Events().Publish(ctx, auth.Event{
			Name:    EventTwoFactorEnabled,
			Time:    now,
			Subject: userID,
			Payload: TwoFactorEnabledPayload{
				UserID:     userID,
				FactorID:   factorID,
				FactorType: FactorTypeTOTP,
				EnabledAt:  now,
			},
		})
	}

	return nil
}

func (s *service) VerifyTOTP(ctx context.Context, userID, code string) (*VerifyResult, error) {
	if strings.TrimSpace(userID) == "" || strings.TrimSpace(code) == "" {
		return nil, ErrInvalidInput
	}

	records, err := s.factors.FindMany(ctx, adapter.Query{
		Where: []adapter.Condition{adapter.Eq("user_id", userID)},
	})
	if err != nil {
		return nil, err
	}

	var confirmed []*FactorRecord
	for i := range records {
		r := &records[i]
		if r.Confirmed && r.Type == string(FactorTypeTOTP) {
			confirmed = append(confirmed, r)
		}
	}

	if len(confirmed) == 0 {
		return nil, ErrTwoFactorNotEnabled
	}

	now := s.now()
	replayFound := false

	for _, factor := range confirmed {
		decrypted, err := s.protector.Decrypt(factor.EncryptedSecret)
		if err != nil {
			continue
		}

		matchedStep, ok := ValidateTOTP(string(decrypted), code, now, s.cfg.StepDuration, s.cfg.SkewSteps)
		if !ok {
			continue
		}

		// Replay check on persistent step
		if matchedStep <= factor.LastUsedTimeStep {
			replayFound = true
			continue
		}

		// Cache check for ephemeral distributed replay protection
		if used, _ := s.cache.IsStepUsed(ctx, factor.ID, matchedStep); used {
			replayFound = true
			continue
		}

		// Mark factor used
		factor.LastUsedAt = &now
		factor.LastUsedTimeStep = matchedStep
		factor.UpdatedAt = now

		_, err = s.factors.Update(ctx, []adapter.Condition{adapter.Eq("id", factor.ID)}, map[string]any{
			"last_used_at":        factor.LastUsedAt,
			"last_used_time_step": factor.LastUsedTimeStep,
			"updated_at":          factor.UpdatedAt,
		})
		if err != nil {
			return nil, err
		}

		// Populate cache replay flag
		_ = s.cache.MarkStepUsed(ctx, factor.ID, matchedStep, s.cfg.StepDuration*2)

		res := &VerifyResult{
			UserID:         userID,
			FactorID:       factor.ID,
			FactorType:     FactorTypeTOTP,
			AssuranceLevel: AAL2,
			VerifiedAt:     now,
		}

		if s.ctx != nil && s.ctx.Events() != nil {
			s.ctx.Events().Publish(ctx, auth.Event{
				Name:    EventTwoFactorVerified,
				Time:    now,
				Subject: userID,
				Payload: TwoFactorVerifiedPayload{
					UserID:         userID,
					FactorID:       factor.ID,
					FactorType:     FactorTypeTOTP,
					AssuranceLevel: AAL2,
					VerifiedAt:     now,
				},
			})
		}

		return res, nil
	}

	if replayFound {
		return nil, ErrReplayDetected
	}

	return nil, ErrInvalidCode
}

func (s *service) VerifyRecoveryCode(ctx context.Context, userID, code string) (*VerifyResult, error) {
	if strings.TrimSpace(userID) == "" || strings.TrimSpace(code) == "" {
		return nil, ErrInvalidInput
	}

	activeCodes, err := s.recovery.FindMany(ctx, adapter.Query{
		Where: []adapter.Condition{adapter.Eq("user_id", userID), adapter.IsNull("used_at")},
	})
	if err != nil {
		return nil, err
	}

	if len(activeCodes) == 0 {
		return nil, ErrNoActiveRecoveryCodes
	}

	inputHash := HashRecoveryCode(code)
	var matched *RecoveryCodeRecord

	for i := range activeCodes {
		c := &activeCodes[i]
		if subtle.ConstantTimeCompare([]byte(c.CodeHash), []byte(inputHash)) == 1 {
			matched = c
			break
		}
	}

	if matched == nil {
		return nil, ErrRecoveryCodeNotFound
	}

	now := s.now()
	affected, err := s.recovery.Update(ctx, []adapter.Condition{
		adapter.Eq("id", matched.ID),
		adapter.IsNull("used_at"),
	}, map[string]any{
		"used_at": now,
	})
	if err != nil {
		return nil, err
	}
	if affected == 0 {
		return nil, ErrRecoveryCodeNotFound
	}

	res := &VerifyResult{
		UserID:         userID,
		FactorID:       matched.ID,
		FactorType:     FactorTypeRecoveryCodes,
		AssuranceLevel: AAL2,
		VerifiedAt:     now,
	}

	if s.ctx != nil && s.ctx.Events() != nil {
		s.ctx.Events().Publish(ctx, auth.Event{
			Name:    EventTwoFactorVerified,
			Time:    now,
			Subject: userID,
			Payload: TwoFactorVerifiedPayload{
				UserID:         userID,
				FactorID:       matched.ID,
				FactorType:     FactorTypeRecoveryCodes,
				AssuranceLevel: AAL2,
				VerifiedAt:     now,
			},
		})
	}

	return res, nil
}

func (s *service) CreateChallenge(ctx context.Context, userID string) (*Challenge, error) {
	if strings.TrimSpace(userID) == "" {
		return nil, ErrInvalidInput
	}

	enabled, err := s.IsEnabled(ctx, userID)
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, ErrTwoFactorNotEnabled
	}

	challengeID, err := GenerateRandomID(24)
	if err != nil {
		return nil, err
	}

	now := s.now()
	expiresAt := now.Add(s.cfg.ChallengeTTL)

	rec := &ChallengeRecord{
		ID:        challengeID,
		UserID:    userID,
		ExpiresAt: expiresAt,
		CreatedAt: now,
	}
	if err := s.challenges.Create(ctx, rec); err != nil {
		return nil, err
	}

	// Also cache challenge if cache is available
	_ = s.cache.SetChallenge(ctx, &cache.ChallengeCacheEntry{
		ID:        challengeID,
		UserID:    userID,
		ExpiresAt: expiresAt,
		CreatedAt: now,
	}, s.cfg.ChallengeTTL)

	return &Challenge{
		ID:        challengeID,
		UserID:    userID,
		ExpiresAt: expiresAt,
		CreatedAt: now,
	}, nil
}

func (s *service) VerifyChallenge(ctx context.Context, challengeID, code string) (*VerifyResult, error) {
	if strings.TrimSpace(challengeID) == "" || strings.TrimSpace(code) == "" {
		return nil, ErrInvalidInput
	}

	now := s.now()
	var userID string
	var expiresAt time.Time

	// Try cache first
	entry, err := s.cache.GetChallenge(ctx, challengeID)
	if err == nil && entry != nil {
		userID = entry.UserID
		expiresAt = entry.ExpiresAt
	} else {
		// Fallback to adapter
		rec, err := s.challenges.FindOne(ctx, adapter.Eq("id", challengeID))
		if err != nil {
			if errors.Is(err, adapter.ErrNotFound) {
				return nil, ErrChallengeNotFound
			}
			return nil, err
		}
		if rec.UsedAt != nil {
			return nil, ErrChallengeAlreadyUsed
		}
		userID = rec.UserID
		expiresAt = rec.ExpiresAt
	}

	if now.After(expiresAt) {
		return nil, ErrChallengeExpired
	}

	// Verify code against TOTP factors first, then recovery codes
	res, verifyErr := s.VerifyTOTP(ctx, userID, code)
	if verifyErr != nil {
		res, verifyErr = s.VerifyRecoveryCode(ctx, userID, code)
		if verifyErr != nil {
			return nil, verifyErr
		}
	}

	// Mark challenge used in adapter
	_, _ = s.challenges.Update(ctx, []adapter.Condition{
		adapter.Eq("id", challengeID),
		adapter.IsNull("used_at"),
	}, map[string]any{
		"used_at": now,
	})
	_ = s.cache.DeleteChallenge(ctx, challengeID)

	return res, nil
}

func (s *service) GenerateRecoveryCodes(ctx context.Context, userID string, count int) ([]string, error) {
	if strings.TrimSpace(userID) == "" {
		return nil, ErrInvalidInput
	}
	if count <= 0 {
		count = s.cfg.DefaultRecoveryCodesCount
	}

	plainCodes := make([]string, 0, count)
	records := make([]*RecoveryCodeRecord, 0, count)
	now := s.now()

	for i := 0; i < count; i++ {
		code, err := GenerateRecoveryCode()
		if err != nil {
			return nil, err
		}
		codeID, err := GenerateRandomID(16)
		if err != nil {
			return nil, err
		}

		plainCodes = append(plainCodes, code)
		records = append(records, &RecoveryCodeRecord{
			ID:        codeID,
			UserID:    userID,
			CodeHash:  HashRecoveryCode(code),
			CreatedAt: now,
		})
	}

	for _, r := range records {
		if err := s.recovery.Create(ctx, r); err != nil {
			return nil, err
		}
	}

	return plainCodes, nil
}

func (s *service) RotateRecoveryCodes(ctx context.Context, userID string) ([]string, error) {
	if strings.TrimSpace(userID) == "" {
		return nil, ErrInvalidInput
	}

	// Revoke existing unused recovery codes
	if _, err := s.recovery.Delete(ctx, adapter.Eq("user_id", userID)); err != nil {
		return nil, err
	}

	return s.GenerateRecoveryCodes(ctx, userID, s.cfg.DefaultRecoveryCodesCount)
}

func (s *service) GetRemainingRecoveryCodesCount(ctx context.Context, userID string) (int, error) {
	if strings.TrimSpace(userID) == "" {
		return 0, ErrInvalidInput
	}
	codes, err := s.recovery.FindMany(ctx, adapter.Query{
		Where: []adapter.Condition{adapter.Eq("user_id", userID), adapter.IsNull("used_at")},
	})
	if err != nil {
		return 0, err
	}
	return len(codes), nil
}

func (s *service) Disable(ctx context.Context, userID string) error {
	if strings.TrimSpace(userID) == "" {
		return ErrInvalidInput
	}

	if _, err := s.factors.Delete(ctx, adapter.Eq("user_id", userID)); err != nil {
		return err
	}
	if _, err := s.recovery.Delete(ctx, adapter.Eq("user_id", userID)); err != nil {
		return err
	}

	now := s.now()
	if s.ctx != nil && s.ctx.Events() != nil {
		s.ctx.Events().Publish(ctx, auth.Event{
			Name:    EventTwoFactorDisabled,
			Time:    now,
			Subject: userID,
			Payload: TwoFactorDisabledPayload{
				UserID:     userID,
				DisabledAt: now,
				Reason:     "user_requested",
			},
		})
	}

	return nil
}

func (s *service) DisableFactor(ctx context.Context, userID, factorID string) error {
	if strings.TrimSpace(userID) == "" || strings.TrimSpace(factorID) == "" {
		return ErrInvalidInput
	}

	rec, err := s.factors.FindOne(ctx, adapter.Eq("id", factorID))
	if err != nil {
		if errors.Is(err, adapter.ErrNotFound) {
			return ErrFactorNotFound
		}
		return err
	}

	if rec.UserID != userID {
		return ErrFactorNotFound
	}

	if _, err := s.factors.Delete(ctx, adapter.Eq("id", factorID)); err != nil {
		return err
	}

	// Check if any confirmed factors remain
	status, err := s.GetStatus(ctx, userID)
	if err == nil && !status.Enabled {
		now := s.now()
		if s.ctx != nil && s.ctx.Events() != nil {
			s.ctx.Events().Publish(ctx, auth.Event{
				Name:    EventTwoFactorDisabled,
				Time:    now,
				Subject: userID,
				Payload: TwoFactorDisabledPayload{
					UserID:     userID,
					DisabledAt: now,
					Reason:     "all_factors_removed",
				},
			})
		}
	}

	return nil
}
