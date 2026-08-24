package apikey

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"math/big"
	"time"
)

const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// DefaultKeyGenerator generates a cryptographically secure random alphanumeric string prefixed with prefix.
func DefaultKeyGenerator(length int, prefix string) (string, error) {
	if length <= 0 {
		length = 32
	}
	bytes := make([]byte, length)
	charsetLen := big.NewInt(int64(len(charset)))
	for i := 0; i < length; i++ {
		num, err := rand.Int(rand.Reader, charsetLen)
		if err != nil {
			return "", err
		}
		bytes[i] = charset[num.Int64()]
	}
	return prefix + string(bytes), nil
}

// DefaultKeyHasher computes a SHA-256 digest of the key string and formats it as Base64URL without padding.
func DefaultKeyHasher(key string) (string, error) {
	hash := sha256.Sum256([]byte(key))
	return base64.RawURLEncoding.EncodeToString(hash[:]), nil
}

// CalculateRefill checks if quota refill interval has elapsed and updates Remaining and LastRefillAt.
// Returns true if quota was refilled.
func CalculateRefill(apiKey *ApiKey, now time.Time) bool {
	if apiKey == nil || apiKey.RefillInterval == nil || apiKey.RefillAmount == nil {
		return false
	}
	intervalMs := *apiKey.RefillInterval
	if intervalMs <= 0 || *apiKey.RefillAmount <= 0 {
		return false
	}

	interval := time.Duration(intervalMs) * time.Millisecond
	lastRefill := apiKey.CreatedAt
	if apiKey.LastRefillAt != nil {
		lastRefill = *apiKey.LastRefillAt
	}

	elapsed := now.Sub(lastRefill)
	if elapsed < interval {
		return false
	}

	periods := int64(elapsed / interval)
	if periods <= 0 {
		return false
	}

	addQuota := periods * (*apiKey.RefillAmount)
	if apiKey.Remaining == nil {
		initial := int64(0)
		apiKey.Remaining = &initial
	}
	*apiKey.Remaining += addQuota

	newLastRefill := lastRefill.Add(time.Duration(periods) * interval)
	apiKey.LastRefillAt = &newLastRefill
	return true
}

// EvaluateRateLimit evaluates request rate against active sliding time window and max request limit.
// Returns true if request is permitted under rate limit guidelines.
func EvaluateRateLimit(apiKey *ApiKey, now time.Time) bool {
	if apiKey == nil || !apiKey.RateLimitEnabled {
		return true
	}
	if apiKey.RateLimitTimeWindow == nil || apiKey.RateLimitMax == nil {
		return true
	}
	windowMs := *apiKey.RateLimitTimeWindow
	maxReq := *apiKey.RateLimitMax
	if windowMs <= 0 || maxReq <= 0 {
		return true
	}

	windowDuration := time.Duration(windowMs) * time.Millisecond
	if apiKey.LastRequest != nil {
		if now.Sub(*apiKey.LastRequest) > windowDuration {
			// Window expired, reset counter for new period
			apiKey.RequestCount = 0
		}
	}

	return apiKey.RequestCount < maxReq
}

// CheckPermissions checks whether granted permissions satisfy all required permissions.
func CheckPermissions(granted map[string][]string, required map[string][]string) bool {
	if len(required) == 0 {
		return true
	}
	if len(granted) == 0 {
		return false
	}

	for res, reqScopes := range required {
		grantedScopes, exists := granted[res]
		if !exists {
			// Check wildcard category "*"
			grantedScopes, exists = granted["*"]
			if !exists {
				return false
			}
		}

		for _, reqScope := range reqScopes {
			if !hasScope(grantedScopes, reqScope) {
				return false
			}
		}
	}
	return true
}

func hasScope(grantedScopes []string, requiredScope string) bool {
	for _, scope := range grantedScopes {
		if scope == "*" || scope == requiredScope {
			return true
		}
	}
	return false
}
