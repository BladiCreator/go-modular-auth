package phonenumber

import (
	"context"
	"crypto/subtle"
	"strconv"
	"time"

	"github.com/BladiCreator/go-modular-auth/plugin"
	"github.com/google/uuid"
)

// storeOTP converts a plain text OTP into its persistent representation according to StoreOTPMode.
func (p *Plugin) storeOTP(otp string) (string, error) {
	switch p.config.StoreOTPMode {
	case StoreOTPEncrypted:
		if p.cipher != nil {
			return p.cipher.Encrypt(otp)
		}
		return otp, nil
	case StoreOTPHashed:
		if p.hasher != nil {
			return p.hasher.Hash(otp)
		}
		return DefaultSHA256Hasher{}.Hash(otp)
	case StoreOTPPlain:
		return otp, nil
	default:
		return otp, nil
	}
}

// verifyStoredOTP compares the provided OTP against the stored value in constant time.
func (p *Plugin) verifyStoredOTP(storedOtp, providedOtp string) bool {
	switch p.config.StoreOTPMode {
	case StoreOTPEncrypted:
		if p.cipher != nil {
			decrypted, err := p.cipher.Decrypt(storedOtp)
			if err != nil {
				return false
			}
			return subtle.ConstantTimeCompare([]byte(decrypted), []byte(providedOtp)) == 1
		}
		return subtle.ConstantTimeCompare([]byte(storedOtp), []byte(providedOtp)) == 1
	case StoreOTPHashed:
		if p.hasher != nil {
			return p.hasher.Verify(providedOtp, storedOtp)
		}
		return DefaultSHA256Hasher{}.Verify(providedOtp, storedOtp)
	case StoreOTPPlain:
		return subtle.ConstantTimeCompare([]byte(storedOtp), []byte(providedOtp)) == 1
	default:
		return subtle.ConstantTimeCompare([]byte(storedOtp), []byte(providedOtp)) == 1
	}
}

// retrievePlainOTP attempts to recover the plain text OTP (returns false if hashed).
func (p *Plugin) retrievePlainOTP(storedOtp string) (string, bool) {
	switch p.config.StoreOTPMode {
	case StoreOTPPlain:
		return storedOtp, true
	case StoreOTPEncrypted:
		if p.cipher != nil {
			decrypted, err := p.cipher.Decrypt(storedOtp)
			if err == nil {
				return decrypted, true
			}
		}
		return "", false
	case StoreOTPHashed:
		return "", false
	default:
		return storedOtp, true
	}
}

// tryReuseOTP attempts to reuse an existing unexpired active OTP if the storage mode permits.
func (p *Plugin) tryReuseOTP(ctx context.Context, identifier string) (string, bool) {
	record, err := p.repo.FindVerificationValue(ctx, identifier)
	if err != nil || record == nil || record.ExpiresAt.Before(time.Now()) {
		return "", false
	}

	storedValue, attemptsStr := SplitAtLastColon(record.Value)
	attempts, _ := strconv.Atoi(attemptsStr)
	if attempts >= p.config.AllowedAttempts {
		return "", false
	}

	plainOtp, ok := p.retrievePlainOTP(storedValue)
	if !ok {
		return "", false
	}

	// Extend validity window on reuse
	newExpiresAt := time.Now().Add(p.config.ExpiresIn)
	_ = p.repo.UpdateVerificationValue(ctx, identifier, record.Value, newExpiresAt)
	return plainOtp, true
}

// resolveOTP resolves whether to generate a new OTP or reuse an active one, and persists the record.
func (p *Plugin) resolveOTP(ctx context.Context, identifier, phoneNumber string, otpType OTPType) (string, time.Time, error) {
	expiresAt := time.Now().Add(p.config.ExpiresIn)

	if p.config.ResendStrategy == ResendStrategyReuse {
		if reused, ok := p.tryReuseOTP(ctx, identifier); ok {
			return reused, expiresAt, nil
		}
	}

	var rawCode string
	var err error
	if p.config.GenerateOTP != nil {
		rawCode, err = p.config.GenerateOTP(ctx, phoneNumber, otpType)
	} else {
		rawCode, err = DefaultNumericOTPGenerator(p.config.OTPLength)
	}
	if err != nil {
		return "", time.Time{}, err
	}

	storedValue, err := p.storeOTP(rawCode)
	if err != nil {
		return "", time.Time{}, err
	}

	record := &VerificationRecord{
		ID:         uuid.NewString(),
		Identifier: identifier,
		Value:      storedValue + ":0",
		ExpiresAt:  expiresAt,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	if err := p.repo.CreateVerificationValue(ctx, record); err != nil {
		// Fallback for drivers without upsert support
		_ = p.repo.DeleteVerificationValue(ctx, identifier)
		if err := p.repo.CreateVerificationValue(ctx, record); err != nil {
			return "", time.Time{}, err
		}
	}

	return rawCode, expiresAt, nil
}

// atomicVerifyOTP executes single-use OTP verification with strict race condition and attempt budget protection.
func (p *Plugin) atomicVerifyOTP(ctx context.Context, identifier, providedOTP string, otpType OTPType, phoneNumber string, extra map[string]any) error {
	// 1. Pre-check for expiration if record exists
	existing, err := p.repo.FindVerificationValue(ctx, identifier)
	if err == nil && existing != nil && existing.ExpiresAt.Before(time.Now()) {
		_ = p.repo.DeleteVerificationValue(ctx, identifier)
		p.publishEvent(EventPhoneNumberOTPExpired, &OTPFailedPayload{
			PhoneNumber:    phoneNumber,
			Type:           otpType,
			Reason:         "expired",
			ExtraContainer: plugin.ExtraContainer{Extra: extra},
		})
		return ErrOTPExpired
	}

	// 2. Atomic Single Gate: only one concurrent goroutine successfully consumes the record
	consumed, err := p.repo.ConsumeVerificationValue(ctx, identifier)
	if err != nil || consumed == nil {
		p.publishEvent(EventPhoneNumberOTPFailed, &OTPFailedPayload{
			PhoneNumber:    phoneNumber,
			Type:           otpType,
			Reason:         "invalid_or_consumed",
			ExtraContainer: plugin.ExtraContainer{Extra: extra},
		})
		return ErrInvalidOTP
	}

	// Check if the consumed record had already expired
	if consumed.ExpiresAt.Before(time.Now()) {
		p.publishEvent(EventPhoneNumberOTPExpired, &OTPFailedPayload{
			PhoneNumber:    phoneNumber,
			Type:           otpType,
			Reason:         "expired",
			ExtraContainer: plugin.ExtraContainer{Extra: extra},
		})
		return ErrOTPExpired
	}

	storedOtpValue, attemptsStr := SplitAtLastColon(consumed.Value)
	attempts, _ := strconv.Atoi(attemptsStr)

	// 3. Attempt budget check
	if attempts >= p.config.AllowedAttempts {
		p.publishEvent(EventPhoneNumberOTPAttemptsExceeded, &OTPFailedPayload{
			PhoneNumber:    phoneNumber,
			Type:           otpType,
			AttemptsUsed:   attempts,
			Reason:         "too_many_attempts",
			ExtraContainer: plugin.ExtraContainer{Extra: extra},
		})
		return ErrTooManyAttempts
	}

	// 4. Constant-time comparison
	if !p.verifyStoredOTP(storedOtpValue, providedOTP) {
		newAttempts := attempts + 1
		if newAttempts < p.config.AllowedAttempts {
			// Recreate record with incremented attempt budget
			_ = p.repo.CreateVerificationValue(ctx, &VerificationRecord{
				ID:         consumed.ID,
				Identifier: identifier,
				Value:      storedOtpValue + ":" + strconv.Itoa(newAttempts),
				ExpiresAt:  consumed.ExpiresAt,
				CreatedAt:  consumed.CreatedAt,
				UpdatedAt:  time.Now(),
			})
			p.publishEvent(EventPhoneNumberOTPFailed, &OTPFailedPayload{
				PhoneNumber:       phoneNumber,
				Type:              otpType,
				AttemptsUsed:      newAttempts,
				AttemptsRemaining: p.config.AllowedAttempts - newAttempts,
				Reason:            "invalid_code",
				ExtraContainer:    plugin.ExtraContainer{Extra: extra},
			})
			return ErrInvalidOTP
		}

		// Budget exceeded: record remains consumed/deleted
		p.publishEvent(EventPhoneNumberOTPAttemptsExceeded, &OTPFailedPayload{
			PhoneNumber:       phoneNumber,
			Type:              otpType,
			AttemptsUsed:      newAttempts,
			AttemptsRemaining: 0,
			Reason:            "too_many_attempts",
			ExtraContainer:    plugin.ExtraContainer{Extra: extra},
		})
		return ErrTooManyAttempts
	}

	return nil
}
