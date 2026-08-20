package magiclink

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"time"
)

// TokenPayload holds stored token data and metadata.
type TokenPayload struct {
	Token              string         `json:"token"`
	Email              string         `json:"email"`
	Name               string         `json:"name,omitempty"`
	CallbackURL        string         `json:"callback_url,omitempty"`
	NewUserCallbackURL string         `json:"new_user_callback_url,omitempty"`
	ErrorCallbackURL   string         `json:"error_callback_url,omitempty"`
	Extra              map[string]any `json:"extra,omitempty"`
}

// storeToken converts a plain text token into its persistent representation according to StoreTokenMode.
func (p *Plugin) storeToken(token string) (string, error) {
	switch p.config.StoreTokenMode {
	case StoreTokenEncrypted:
		if p.cipher != nil {
			return p.cipher.Encrypt(token)
		}
		return token, nil
	case StoreTokenHashed:
		if p.hasher != nil {
			return p.hasher.Hash(token)
		}
		return DefaultSHA256Hasher{}.Hash(token)
	case StoreTokenPlain:
		return token, nil
	default:
		return token, nil
	}
}

// verifyStoredToken verifies the provided token against the stored token value in constant time.
func (p *Plugin) verifyStoredToken(storedToken, providedToken string) bool {
	switch p.config.StoreTokenMode {
	case StoreTokenEncrypted:
		if p.cipher != nil {
			decrypted, err := p.cipher.Decrypt(storedToken)
			if err != nil {
				return false
			}
			return subtle.ConstantTimeCompare([]byte(decrypted), []byte(providedToken)) == 1
		}
		return subtle.ConstantTimeCompare([]byte(storedToken), []byte(providedToken)) == 1
	case StoreTokenHashed:
		if p.hasher != nil {
			return p.hasher.Verify(providedToken, storedToken)
		}
		return DefaultSHA256Hasher{}.Verify(providedToken, storedToken)
	case StoreTokenPlain:
		return subtle.ConstantTimeCompare([]byte(storedToken), []byte(providedToken)) == 1
	default:
		return subtle.ConstantTimeCompare([]byte(storedToken), []byte(providedToken)) == 1
	}
}

// atomicConsumeToken executes single-use token consumption with race condition protection.
func (p *Plugin) atomicConsumeToken(ctx context.Context, identifier, providedToken string, extra map[string]any) (*TokenPayload, error) {
	// 1. Pre-check for expiration if record exists
	existing, err := p.repo.FindVerificationValue(ctx, identifier)
	if err == nil && existing != nil && existing.ExpiresAt.Before(time.Now()) {
		_ = p.repo.DeleteVerificationValue(ctx, identifier)
		p.publishEvent(EventMagicLinkExpired, &MagicLinkFailedPayload{
			Token:  providedToken,
			Reason: "expired",
			Extra:  extra,
		})
		return nil, ErrTokenExpired
	}

	// 2. Atomic single gate consumption
	consumed, err := p.repo.ConsumeVerificationValue(ctx, identifier)
	if err != nil || consumed == nil {
		p.publishEvent(EventMagicLinkFailed, &MagicLinkFailedPayload{
			Token:  providedToken,
			Reason: "invalid_or_consumed",
			Extra:  extra,
		})
		return nil, ErrInvalidToken
	}

	// Check if consumed record had expired
	if consumed.ExpiresAt.Before(time.Now()) {
		p.publishEvent(EventMagicLinkExpired, &MagicLinkFailedPayload{
			Token:  providedToken,
			Reason: "expired",
			Extra:  extra,
		})
		return nil, ErrTokenExpired
	}

	var payload TokenPayload
	if err := json.Unmarshal([]byte(consumed.Value), &payload); err != nil {
		// Fallback for plain string token value
		payload = TokenPayload{
			Token: consumed.Value,
		}
	}

	// 3. Constant-time verification
	if !p.verifyStoredToken(payload.Token, providedToken) {
		p.publishEvent(EventMagicLinkFailed, &MagicLinkFailedPayload{
			Email:  payload.Email,
			Token:  providedToken,
			Reason: "invalid_token",
			Extra:  extra,
		})
		return nil, ErrInvalidToken
	}

	return &payload, nil
}
