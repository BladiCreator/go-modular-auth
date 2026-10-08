package phone

import (
	"strings"
	"unicode"
)

// Normalizer transforms a raw phone number input into a canonical format (E.164).
type Normalizer func(raw string) (string, error)

// Validator validates whether a normalized phone number complies with domain rules.
type Validator func(normalized string) error

const (
	// MinE164Digits is the minimum digit count for a valid international phone number.
	MinE164Digits = 7

	// MaxE164Digits is the maximum digit count defined by ITU-T E.164 recommendation.
	MaxE164Digits = 15
)

// DefaultNormalizer returns a canonical E.164 string (+[country_code][number]).
// It strips spaces, hyphens, periods, and parentheses, normalizes international exit codes (00 -> +),
// and ensures the output conforms to ITU-T E.164 format.
func DefaultNormalizer() Normalizer {
	return func(raw string) (string, error) {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			return "", ErrPhoneRequired
		}

		// Replace common international dial prefixes if present
		if strings.HasPrefix(trimmed, "00") {
			trimmed = "+" + trimmed[2:]
		}

		var b strings.Builder
		b.Grow(len(trimmed) + 1)

		hasPlus := false
		for i, r := range trimmed {
			if r == '+' {
				if i == 0 || (b.Len() == 0 && !hasPlus) {
					b.WriteRune('+')
					hasPlus = true
					continue
				}
				// '+' found inside the number is invalid
				return "", ErrInvalidPhone
			}

			// Skip common formatting separators
			if r == ' ' || r == '-' || r == '(' || r == ')' || r == '.' {
				continue
			}

			if unicode.IsDigit(r) {
				if !hasPlus {
					b.WriteRune('+')
					hasPlus = true
				}
				b.WriteRune(r)
			} else {
				// Non-digit character found
				return "", ErrInvalidPhone
			}
		}

		result := b.String()
		digits := strings.TrimPrefix(result, "+")

		if len(digits) < MinE164Digits || len(digits) > MaxE164Digits {
			return "", ErrInvalidPhone
		}

		// E.164 country codes never begin with digit 0
		if len(digits) > 0 && digits[0] == '0' {
			return "", ErrInvalidPhone
		}

		return result, nil
	}
}

// DefaultValidator checks that the normalized number meets ITU-T E.164 requirements.
func DefaultValidator() Validator {
	return func(normalized string) error {
		if !strings.HasPrefix(normalized, "+") {
			return ErrInvalidPhone
		}
		digits := normalized[1:]
		if len(digits) < MinE164Digits || len(digits) > MaxE164Digits {
			return ErrInvalidPhone
		}
		for _, r := range digits {
			if !unicode.IsDigit(r) {
				return ErrInvalidPhone
			}
		}
		if digits[0] == '0' {
			return ErrInvalidPhone
		}
		return nil
	}
}
