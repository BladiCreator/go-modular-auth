package jwt

import (
	"encoding/json"
	"fmt"
	"math"
	"slices"
	"strconv"
	"time"
)

// NumericDate represents a JSON numeric date (seconds since Unix epoch) per RFC 7519 section 2.
type NumericDate struct {
	time.Time
}

// NewNumericDate creates a new NumericDate from a time.Time value, truncated to seconds.
func NewNumericDate(t time.Time) *NumericDate {
	if t.IsZero() {
		return nil
	}
	return &NumericDate{Time: t}
}

// MarshalJSON marshals the timestamp as a Unix integer.
func (n *NumericDate) MarshalJSON() ([]byte, error) {
	if n == nil || n.IsZero() {
		return []byte("null"), nil
	}
	return []byte(strconv.FormatInt(n.Unix(), 10)), nil
}

// UnmarshalJSON unmarshals a JSON number into a NumericDate.
func (n *NumericDate) UnmarshalJSON(data []byte) error {
	var val json.Number
	if err := json.Unmarshal(data, &val); err != nil {
		return err
	}
	f, err := val.Float64()
	if err != nil {
		return err
	}
	sec, frac := math.Modf(f)
	n.Time = time.Unix(int64(sec), int64(frac*1e9))
	return nil
}

// Audience represents the aud claim which can be a single string or an array of strings in RFC 7519.
type Audience []string

// Contains reports whether the target audience is present in the Audience slice.
func (a Audience) Contains(target string) bool {
	return slices.Contains(a, target)
}

// MarshalJSON serializes single audience as a JSON string, and multiple as an array.
func (a Audience) MarshalJSON() ([]byte, error) {
	if len(a) == 1 {
		return json.Marshal(a[0])
	}
	return json.Marshal([]string(a))
}

// UnmarshalJSON parses either a JSON string or an array of strings.
func (a *Audience) UnmarshalJSON(data []byte) error {
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*a = []string{single}
		return nil
	}
	var multiple []string
	if err := json.Unmarshal(data, &multiple); err == nil {
		*a = multiple
		return nil
	}
	return fmt.Errorf("jwt: cannot unmarshal audience from %s", string(data))
}

// Claims represents the standard and custom claims of a JWT payload.
type Claims struct {
	// Issuer (iss) identifies the principal that issued the JWT.
	Issuer string `json:"iss,omitempty"`

	// Subject (sub) identifies the principal that is the subject of the JWT.
	Subject string `json:"sub,omitempty"`

	// Audience (aud) identifies the recipients that the JWT is intended for.
	Audience Audience `json:"aud,omitempty"`

	// ExpiresAt (exp) identifies the expiration time on or after which the JWT MUST NOT be accepted.
	ExpiresAt *NumericDate `json:"exp,omitempty"`

	// NotBefore (nbf) identifies the time before which the JWT MUST NOT be accepted.
	NotBefore *NumericDate `json:"nbf,omitempty"`

	// IssuedAt (iat) identifies the time at which the JWT was issued.
	IssuedAt *NumericDate `json:"iat,omitempty"`

	// ID (jti) provides a unique identifier for the JWT.
	ID string `json:"jti,omitempty"`

	// Custom contains additional non-standard application claims.
	Custom map[string]any `json:"-"`
}

// MarshalJSON serializes standard and custom claims into a single JSON object.
func (c Claims) MarshalJSON() ([]byte, error) {
	type Alias Claims
	base, err := json.Marshal(Alias(c))
	if err != nil {
		return nil, err
	}
	if len(c.Custom) == 0 {
		return base, nil
	}

	var m map[string]any
	if err := json.Unmarshal(base, &m); err != nil {
		return nil, err
	}
	for k, v := range c.Custom {
		// Do not overwrite standard claims unless intended
		if _, exists := m[k]; !exists {
			m[k] = v
		}
	}
	return json.Marshal(m)
}

// UnmarshalJSON deserializes standard claims and captures any remaining fields into Custom.
func (c *Claims) UnmarshalJSON(data []byte) error {
	type Alias Claims
	var alias Alias
	if err := json.Unmarshal(data, &alias); err != nil {
		return err
	}
	*c = Claims(alias)

	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	// Remove standard keys
	delete(raw, "iss")
	delete(raw, "sub")
	delete(raw, "aud")
	delete(raw, "exp")
	delete(raw, "nbf")
	delete(raw, "iat")
	delete(raw, "jti")

	if len(raw) > 0 {
		c.Custom = raw
	}
	return nil
}

// Validate verifies standard claim expectations including expiration, not-before, issuer, audience, and subject.
func (c *Claims) Validate(now time.Time, cfg *verifyConfig) error {
	leeway := cfg.leeway

	// Check Expiration (exp)
	if c.ExpiresAt != nil && !c.ExpiresAt.IsZero() {
		if now.After(c.ExpiresAt.Add(leeway)) {
			return ErrTokenExpired
		}
	}

	// Check Not Before (nbf)
	if c.NotBefore != nil && !c.NotBefore.IsZero() {
		if now.Before(c.NotBefore.Add(-leeway)) {
			return ErrTokenNotYetValid
		}
	}

	// Check Issuer (iss)
	if cfg.expectedIssuer != "" && c.Issuer != cfg.expectedIssuer {
		return ErrInvalidIssuer
	}

	// Check Audience (aud)
	if cfg.expectedAudience != "" && !c.Audience.Contains(cfg.expectedAudience) {
		return ErrInvalidAudience
	}

	// Check Subject (sub)
	if cfg.expectedSubject != "" && c.Subject != cfg.expectedSubject {
		return ErrInvalidSubject
	}

	// Check Required Claims
	for _, req := range cfg.requiredClaims {
		switch req {
		case "iss":
			if c.Issuer == "" {
				return fmt.Errorf("%w: iss", ErrMissingRequiredClaim)
			}
		case "sub":
			if c.Subject == "" {
				return fmt.Errorf("%w: sub", ErrMissingRequiredClaim)
			}
		case "aud":
			if len(c.Audience) == 0 {
				return fmt.Errorf("%w: aud", ErrMissingRequiredClaim)
			}
		case "exp":
			if c.ExpiresAt == nil || c.ExpiresAt.IsZero() {
				return fmt.Errorf("%w: exp", ErrMissingRequiredClaim)
			}
		case "nbf":
			if c.NotBefore == nil || c.NotBefore.IsZero() {
				return fmt.Errorf("%w: nbf", ErrMissingRequiredClaim)
			}
		case "iat":
			if c.IssuedAt == nil || c.IssuedAt.IsZero() {
				return fmt.Errorf("%w: iat", ErrMissingRequiredClaim)
			}
		case "jti":
			if c.ID == "" {
				return fmt.Errorf("%w: jti", ErrMissingRequiredClaim)
			}
		default:
			if c.Custom == nil || c.Custom[req] == nil {
				return fmt.Errorf("%w: %s", ErrMissingRequiredClaim, req)
			}
		}
	}

	return nil
}
