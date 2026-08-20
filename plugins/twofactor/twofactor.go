package twofactor

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/BladiCreator/go-modular-auth/plugin"
	"github.com/BladiCreator/go-modular-auth/plugins/emailpassword"
)

// PluginID is the unique string identifier for the TwoFactor plugin ("two-factor").
const PluginID = "two-factor"

// Plugin implements pure Go Two-Factor Authentication capabilities.
type Plugin struct {
	repo   Repository
	config Config
	ctx    *plugin.Context
}

// New creates a new TwoFactor plugin instance with the specified repository and functional options.
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

// ID returns the unique identifier for the TwoFactor plugin ("two-factor").
func (p *Plugin) ID() string {
	return PluginID
}

// Init initializes the plugin within the global GoModularAuth context.
func (p *Plugin) Init(ctx *plugin.Context) error {
	p.ctx = ctx

	// Automatic reaction following a successful email/password sign-in
	p.ctx.Events().Subscribe(emailpassword.EventSignInAfter, func(c context.Context, payload *emailpassword.SignInEventPayload) {
		if payload != nil && payload.User != nil {
			p.ctx.Set(TwoFactorPendingKey(payload.User.ID), true)
		}
	})

	return nil
}

// Enable initializes 2FA enrollment for a user, generating a secure Base32 TOTP secret and recovery backup codes.
func (p *Plugin) Enable(ctx context.Context, params EnableParams) (*EnableResult, error) {
	if p.ctx != nil && p.ctx.Events() != nil {
		p.ctx.Events().Publish(EventEnableBefore, ctx, &EnableBeforeEventPayload{
			UserID: params.UserID,
			Params: &params,
		})
	}

	secret, err := GenerateBase32Secret(20)
	if err != nil {
		return nil, err
	}

	rawBackupCodes, err := GenerateBackupCodes(p.config.BackupCodeAmount, p.config.BackupCodeLength)
	if err != nil {
		return nil, err
	}

	backupJSON, err := json.Marshal(rawBackupCodes)
	if err != nil {
		return nil, fmt.Errorf("twofactor: failed to encode backup codes: %w", err)
	}

	tf := &TwoFactor{
		UserID:      params.UserID,
		Secret:      secret,
		BackupCodes: string(backupJSON),
		Verified:    p.config.SkipVerificationOnEnable,
		Failures:    0,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	existing, _ := p.repo.FindByUserID(ctx, params.UserID)
	if existing != nil {
		tf.ID = existing.ID
		if err := p.repo.Update(ctx, tf); err != nil {
			return nil, err
		}
	} else {
		if err := p.repo.Create(ctx, tf); err != nil {
			return nil, err
		}
	}

	issuer := params.Issuer
	if issuer == "" {
		issuer = p.config.Issuer
	}

	totpURI := BuildTOTPURI(issuer, params.UserID, secret, p.config.TotpDigits, p.config.TotpPeriod, p.config.Algorithm)

	if p.ctx != nil && p.ctx.Events() != nil {
		p.ctx.Events().Publish(EventEnableAfter, ctx, &EnableAfterEventPayload{
			UserID:           params.UserID,
			BackupCodesCount: len(rawBackupCodes),
		})
		p.ctx.Events().Publish(EventTOTPGenerated, ctx, &TOTPGeneratedEventPayload{
			UserID: params.UserID,
			Secret: secret,
		})
	}

	return &EnableResult{
		TOTPURI:     totpURI,
		Secret:      secret,
		BackupCodes: rawBackupCodes,
	}, nil
}

// Disable removes 2FA configuration for the given user, revokes all trusted devices, and deactivates 2FA.
func (p *Plugin) Disable(ctx context.Context, params DisableParams) error {
	if p.ctx != nil && p.ctx.Events() != nil {
		p.ctx.Events().Publish(EventDisableBefore, ctx, &DisableBeforeEventPayload{
			UserID: params.UserID,
			Params: &params,
		})
	}

	if err := p.repo.DeleteByUserID(ctx, params.UserID); err != nil {
		return err
	}

	_ = p.repo.DeleteTrustDevicesByUserID(ctx, params.UserID)

	if p.ctx != nil && p.ctx.Events() != nil {
		p.ctx.Events().Publish(EventDisableAfter, ctx, &DisableAfterEventPayload{
			UserID: params.UserID,
		})
	}
	return nil
}

// GetTOTPURI retrieves the TOTP setup URI for an already configured user.
func (p *Plugin) GetTOTPURI(ctx context.Context, params GetTOTPURIParams) (string, error) {
	tf, err := p.repo.FindByUserID(ctx, params.UserID)
	if err != nil || tf == nil {
		return "", ErrTwoFactorNotEnabled
	}

	issuer := p.config.Issuer
	totpURI := BuildTOTPURI(issuer, params.UserID, tf.Secret, p.config.TotpDigits, p.config.TotpPeriod, p.config.Algorithm)
	return totpURI, nil
}

// VerifyTOTP validates a user-provided RFC 6238 TOTP code against their stored secret with a ±1 period drift window.
func (p *Plugin) VerifyTOTP(ctx context.Context, params VerifyTOTPParams) (*VerifyResult, error) {
	tf, err := p.repo.FindByUserID(ctx, params.UserID)
	if err != nil || tf == nil {
		return nil, ErrTwoFactorNotEnabled
	}

	if p.isLocked(tf) {
		return nil, ErrAccountLocked
	}

	valid := ValidateTOTPCode(tf.Secret, params.Code, p.config.TotpPeriod, p.config.TotpDigits, p.config.Algorithm)
	if !valid {
		p.recordFailure(ctx, tf, MethodTOTP)
		return nil, ErrInvalidCode
	}

	p.resetFailures(ctx, tf)
	if !tf.Verified {
		tf.Verified = true
		_ = p.repo.Update(ctx, tf)
	}

	var deviceToken string
	if params.TrustDevice && params.DeviceID != "" {
		token, err := p.issueTrustDevice(ctx, params.UserID, params.DeviceID)
		if err == nil {
			deviceToken = token
		}
	}

	if p.ctx != nil && p.ctx.Events() != nil {
		p.ctx.Events().Publish(EventVerifySuccess, ctx, &VerifySuccessEventPayload{
			UserID:      params.UserID,
			Method:      MethodTOTP,
			TrustDevice: params.TrustDevice,
		})
	}

	return &VerifyResult{
		Success:          true,
		UserID:           params.UserID,
		Method:           MethodTOTP,
		TrustDeviceToken: deviceToken,
	}, nil
}

// VerifyBackupCode verifies and atomically consumes a single-use backup recovery code.
func (p *Plugin) VerifyBackupCode(ctx context.Context, params VerifyBackupCodeParams) (*VerifyResult, error) {
	tf, err := p.repo.FindByUserID(ctx, params.UserID)
	if err != nil || tf == nil {
		return nil, ErrTwoFactorNotEnabled
	}

	if p.isLocked(tf) {
		return nil, ErrAccountLocked
	}

	var codes []string
	if err := json.Unmarshal([]byte(tf.BackupCodes), &codes); err != nil {
		return nil, err
	}

	idx, valid := ValidateBackupCode(codes, params.Code)
	if !valid || idx < 0 {
		p.recordFailure(ctx, tf, MethodBackupCode)
		return nil, ErrInvalidCode
	}

	// Atomically consume the matching backup code
	remaining := append(codes[:idx], codes[idx+1:]...)
	updatedJSON, _ := json.Marshal(remaining)
	tf.BackupCodes = string(updatedJSON)

	p.resetFailures(ctx, tf)
	_ = p.repo.Update(ctx, tf)

	if p.ctx != nil && p.ctx.Events() != nil {
		p.ctx.Events().Publish(EventVerifySuccess, ctx, &VerifySuccessEventPayload{
			UserID: params.UserID,
			Method: MethodBackupCode,
		})
	}

	return &VerifyResult{
		Success:        true,
		UserID:         params.UserID,
		Method:         MethodBackupCode,
		RemainingCodes: len(remaining),
	}, nil
}

// GenerateBackupCodes regenerates a fresh set of single-use recovery codes, invalidating prior ones.
func (p *Plugin) GenerateBackupCodes(ctx context.Context, params GenerateBackupCodesParams) (*BackupCodesResult, error) {
	tf, err := p.repo.FindByUserID(ctx, params.UserID)
	if err != nil || tf == nil {
		return nil, ErrTwoFactorNotEnabled
	}

	codes, err := GenerateBackupCodes(p.config.BackupCodeAmount, p.config.BackupCodeLength)
	if err != nil {
		return nil, err
	}

	backupJSON, err := json.Marshal(codes)
	if err != nil {
		return nil, err
	}

	tf.BackupCodes = string(backupJSON)
	tf.UpdatedAt = time.Now()

	if err := p.repo.Update(ctx, tf); err != nil {
		return nil, err
	}

	if p.ctx != nil && p.ctx.Events() != nil {
		p.ctx.Events().Publish(EventBackupCodesRegenerated, ctx, &BackupCodesRegeneratedEventPayload{
			UserID: params.UserID,
			Amount: len(codes),
		})
	}

	return &BackupCodesResult{BackupCodes: codes}, nil
}

// ViewBackupCodes returns the list of active unconsumed single-use backup codes.
func (p *Plugin) ViewBackupCodes(ctx context.Context, params ViewBackupCodesParams) (*BackupCodesResult, error) {
	tf, err := p.repo.FindByUserID(ctx, params.UserID)
	if err != nil || tf == nil {
		return nil, ErrTwoFactorNotEnabled
	}

	var codes []string
	if err := json.Unmarshal([]byte(tf.BackupCodes), &codes); err != nil {
		return nil, err
	}
	return &BackupCodesResult{BackupCodes: codes}, nil
}

// SendOTP generates a short-lived numeric challenge and triggers the registered SendOTP callback and EventBus.
func (p *Plugin) SendOTP(ctx context.Context, params SendOTPParams) (*SendOTPResult, error) {
	if p.config.SendOTP == nil {
		return nil, ErrOTPNotConfigured
	}

	if p.ctx != nil && p.ctx.Events() != nil {
		p.ctx.Events().Publish(EventSendOTPBefore, ctx, &SendOTPBeforeEventPayload{
			UserID: params.UserID,
			Params: &params,
		})
	}

	code, err := GenerateRandomNumericCode(p.config.OTPDigits)
	if err != nil {
		return nil, err
	}

	key := fmt.Sprintf("2fa-otp-%s", params.UserID)
	expiresAt := time.Now().Add(p.config.OTPPeriod)

	challenge := &OTPChallenge{
		Key:       key,
		UserID:    params.UserID,
		CodeHash:  code,
		Attempts:  0,
		ExpiresAt: expiresAt,
	}

	if err := p.repo.SaveOTPChallenge(ctx, challenge); err != nil {
		return nil, err
	}

	if err := p.config.SendOTP(ctx, params.UserID, code); err != nil {
		return nil, err
	}

	if p.ctx != nil && p.ctx.Events() != nil {
		p.ctx.Events().Publish(EventSendOTPAfter, ctx, &SendOTPAfterEventPayload{
			UserID:    params.UserID,
			OTPCode:   code,
			ExpiresAt: expiresAt,
		})
	}

	return &SendOTPResult{ExpiresAt: expiresAt}, nil
}

// VerifyOTP validates a user-submitted code against an active OTP challenge.
func (p *Plugin) VerifyOTP(ctx context.Context, params VerifyOTPParams) (*VerifyResult, error) {
	key := fmt.Sprintf("2fa-otp-%s", params.UserID)
	challenge, err := p.repo.GetOTPChallenge(ctx, key)
	if err != nil || challenge == nil || time.Now().After(challenge.ExpiresAt) {
		return nil, ErrOTPExpired
	}

	if challenge.Attempts >= p.config.Lockout.MaxFailedAttempts {
		_ = p.repo.DeleteOTPChallenge(ctx, key)
		return nil, ErrTooManyAttempts
	}

	if challenge.CodeHash != params.Code {
		challenge.Attempts++
		_ = p.repo.SaveOTPChallenge(ctx, challenge)
		if p.ctx != nil && p.ctx.Events() != nil {
			p.ctx.Events().Publish(EventVerifyFailed, ctx, &VerifyFailedEventPayload{
				UserID:   params.UserID,
				Method:   MethodOTP,
				Failures: challenge.Attempts,
			})
		}
		return nil, ErrInvalidCode
	}

	// Single use: delete on successful verification
	_ = p.repo.DeleteOTPChallenge(ctx, key)

	if p.ctx != nil && p.ctx.Events() != nil {
		p.ctx.Events().Publish(EventVerifySuccess, ctx, &VerifySuccessEventPayload{
			UserID: params.UserID,
			Method: MethodOTP,
		})
	}

	return &VerifyResult{
		Success: true,
		UserID:  params.UserID,
		Method:  MethodOTP,
	}, nil
}

// CreateChallenge generates a short-lived sign-in challenge token following primary credentials verification.
func (p *Plugin) CreateChallenge(ctx context.Context, params CreateChallengeParams) (*ChallengeResult, error) {
	token, err := GenerateRandomToken(32)
	if err != nil {
		return nil, err
	}

	expiresAt := time.Now().Add(p.config.ChallengeExpiry)
	rec := &ChallengeRecord{
		Token:     token,
		UserID:    params.UserID,
		ExpiresAt: expiresAt,
		CreatedAt: time.Now(),
	}

	if err := p.repo.SaveChallenge(ctx, rec); err != nil {
		return nil, err
	}

	if p.ctx != nil && p.ctx.Events() != nil {
		p.ctx.Events().Publish(EventChallengeCreated, ctx, &ChallengeCreatedEventPayload{
			Token:     token,
			UserID:    params.UserID,
			ExpiresAt: expiresAt,
		})
	}

	return &ChallengeResult{
		ChallengeToken: token,
		UserID:         params.UserID,
		ExpiresAt:      expiresAt,
	}, nil
}

// VerifyChallenge validates a sign-in challenge token using the requested method (TOTP, Backup Code, OTP).
func (p *Plugin) VerifyChallenge(ctx context.Context, params VerifyChallengeParams) (*VerifyResult, error) {
	challenge, err := p.repo.GetChallenge(ctx, params.ChallengeToken)
	if err != nil || challenge == nil {
		return nil, ErrInvalidChallengeToken
	}

	if time.Now().After(challenge.ExpiresAt) {
		_ = p.repo.DeleteChallenge(ctx, params.ChallengeToken)
		return nil, ErrChallengeExpired
	}

	var res *VerifyResult
	switch strings.ToLower(params.Method) {
	case MethodTOTP:
		res, err = p.VerifyTOTP(ctx, VerifyTOTPParams{
			UserID:         challenge.UserID,
			Code:           params.Code,
			TrustDevice:    params.TrustDevice,
			DeviceID:       params.DeviceID,
			ExtraContainer: params.ExtraContainer,
		})
	case MethodBackupCode:
		res, err = p.VerifyBackupCode(ctx, VerifyBackupCodeParams{
			UserID:         challenge.UserID,
			Code:           params.Code,
			ExtraContainer: params.ExtraContainer,
		})
	case MethodOTP, MethodSMS, MethodEmail:
		res, err = p.VerifyOTP(ctx, VerifyOTPParams{
			UserID:         challenge.UserID,
			Code:           params.Code,
			ExtraContainer: params.ExtraContainer,
		})
	default:
		return nil, fmt.Errorf("twofactor: unsupported verification method '%s'", params.Method)
	}

	if err != nil {
		return nil, err
	}

	// Consume challenge token upon successful verification
	_ = p.repo.DeleteChallenge(ctx, params.ChallengeToken)

	return res, nil
}

// TrustDevice explicitly authorizes a client device for the configured trust duration.
func (p *Plugin) TrustDevice(ctx context.Context, params TrustDeviceParams) (*TrustDeviceResult, error) {
	if params.UserID == "" || params.DeviceID == "" {
		return nil, fmt.Errorf("twofactor: user_id and device_id are required to trust a device")
	}

	token, err := p.issueTrustDevice(ctx, params.UserID, params.DeviceID)
	if err != nil {
		return nil, err
	}

	expiresAt := time.Now().Add(p.config.TrustDeviceMaxAge)
	return &TrustDeviceResult{
		Token:     token,
		ExpiresAt: expiresAt,
	}, nil
}

// VerifyTrustDevice validates whether an authorized device token is authentic and currently unexpired.
func (p *Plugin) VerifyTrustDevice(ctx context.Context, params VerifyTrustDeviceParams) (bool, error) {
	secret := p.config.TrustDeviceSecret
	if secret == "" {
		secret = "go-modular-auth-default-device-secret"
	}

	validSig := VerifyTrustDeviceToken(params.Token, params.UserID, params.DeviceID, secret)
	if !validSig {
		return false, nil
	}

	rec, err := p.repo.FindTrustDevice(ctx, params.UserID, params.DeviceID)
	if err != nil || rec == nil {
		return false, nil
	}

	if time.Now().After(rec.ExpiresAt) {
		_ = p.repo.DeleteTrustDevice(ctx, params.UserID, params.DeviceID)
		return false, nil
	}

	return true, nil
}

// RevokeTrustedDevice revokes authorization for a single trusted client device.
func (p *Plugin) RevokeTrustedDevice(ctx context.Context, params RevokeTrustedDeviceParams) error {
	return p.repo.DeleteTrustDevice(ctx, params.UserID, params.DeviceID)
}

// RevokeAllTrustedDevices invalidates all authorized devices for the specified user.
func (p *Plugin) RevokeAllTrustedDevices(ctx context.Context, userID string) error {
	return p.repo.DeleteTrustDevicesByUserID(ctx, userID)
}

// Convenience Methods
func (p *Plugin) GenerateTOTPSecret(ctx context.Context, userID string) (string, error) {
	res, err := p.Enable(ctx, EnableParams{UserID: userID})
	if err != nil {
		return "", err
	}
	return res.TOTPURI, nil
}

func (p *Plugin) VerifyCode(ctx context.Context, userID, code string) (bool, error) {
	res, err := p.VerifyTOTP(ctx, VerifyTOTPParams{UserID: userID, Code: code})
	if err != nil {
		return false, err
	}
	return res.Success, nil
}

// Internal Lockout & Security Helpers
func (p *Plugin) isLocked(tf *TwoFactor) bool {
	if tf == nil || !p.config.Lockout.Enabled {
		return false
	}
	if tf.LockedUntil != nil && tf.LockedUntil.After(time.Now()) {
		return true
	}
	return false
}

func (p *Plugin) recordFailure(ctx context.Context, tf *TwoFactor, method string) {
	if tf == nil {
		return
	}
	tf.Failures++
	if p.config.Lockout.Enabled && tf.Failures >= p.config.Lockout.MaxFailedAttempts {
		lockedUntil := time.Now().Add(p.config.Lockout.Duration)
		tf.LockedUntil = &lockedUntil

		if p.ctx != nil && p.ctx.Events() != nil {
			p.ctx.Events().Publish(EventAccountLocked, ctx, &AccountLockedEventPayload{
				UserID:      tf.UserID,
				Failures:    tf.Failures,
				LockedUntil: lockedUntil,
			})
		}
	}
	tf.UpdatedAt = time.Now()
	_ = p.repo.Update(ctx, tf)

	if p.ctx != nil && p.ctx.Events() != nil {
		p.ctx.Events().Publish(EventVerifyFailed, ctx, &VerifyFailedEventPayload{
			UserID:   tf.UserID,
			Method:   method,
			Failures: tf.Failures,
		})
	}
}

func (p *Plugin) resetFailures(ctx context.Context, tf *TwoFactor) {
	if tf == nil {
		return
	}
	if tf.Failures > 0 || tf.LockedUntil != nil {
		tf.Failures = 0
		tf.LockedUntil = nil
		tf.UpdatedAt = time.Now()
		_ = p.repo.Update(ctx, tf)
	}
}

func (p *Plugin) issueTrustDevice(ctx context.Context, userID, deviceID string) (string, error) {
	secret := p.config.TrustDeviceSecret
	if secret == "" {
		secret = "go-modular-auth-default-device-secret"
	}

	expiresAt := time.Now().Add(p.config.TrustDeviceMaxAge)
	token := GenerateTrustDeviceToken(userID, deviceID, secret, expiresAt)

	rec := &TrustDeviceRecord{
		ID:        fmt.Sprintf("td_%s_%s", userID, deviceID),
		UserID:    userID,
		DeviceID:  deviceID,
		TokenHash: token,
		ExpiresAt: expiresAt,
		CreatedAt: time.Now(),
	}

	if err := p.repo.SaveTrustDevice(ctx, rec); err != nil {
		return "", err
	}

	if p.ctx != nil && p.ctx.Events() != nil {
		p.ctx.Events().Publish(EventDeviceTrusted, ctx, &DeviceTrustedEventPayload{
			UserID:    userID,
			DeviceID:  deviceID,
			ExpiresAt: expiresAt,
		})
	}

	return token, nil
}
