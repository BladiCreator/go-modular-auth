package username

import (
	"fmt"
	"regexp"
	"strings"
)

// Validator is a function that checks if a raw username satisfies syntactic and business rules.
type Validator func(username string) error

// Normalizer transforms a raw username into its canonical lookup and uniqueness key.
type Normalizer func(username string) (string, error)

var (
	// defaultUsernameRegex matches standard usernames: alphanumeric, hyphens, and underscores.
	// Must begin and end with an alphanumeric character.
	defaultUsernameRegex = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]*[a-zA-Z0-9]$`)
	singleCharRegex      = regexp.MustCompile(`^[a-zA-Z0-9]$`)
)

// DefaultReservedUsernames contains common system, routing, and administrative handles
// to prevent identity squatting and URL collision.
var DefaultReservedUsernames = map[string]struct{}{
	"admin":         {},
	"administrator": {},
	"root":          {},
	"system":        {},
	"sysadmin":      {},
	"support":       {},
	"help":          {},
	"api":           {},
	"auth":          {},
	"oauth":         {},
	"login":         {},
	"logout":        {},
	"signin":        {},
	"signup":        {},
	"register":      {},
	"security":      {},
	"staff":         {},
	"mod":           {},
	"moderator":     {},
	"guest":         {},
	"anonymous":     {},
	"null":          {},
	"undefined":     {},
	"void":          {},
	"me":            {},
	"self":          {},
	"test":          {},
	"dev":           {},
	"status":        {},
	"health":        {},
	"metrics":       {},
	"account":       {},
	"user":          {},
	"users":         {},
	"settings":      {},
	"profile":       {},
	"dashboard":     {},
	"billing":       {},
}

// DefaultNormalizer returns the trimmed, lowercase representation of a username.
// When caseSensitive is true, only leading/trailing whitespace is trimmed.
func DefaultNormalizer(caseSensitive bool) Normalizer {
	return func(raw string) (string, error) {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			return "", ErrInvalidFormat
		}
		if caseSensitive {
			return trimmed, nil
		}
		return strings.ToLower(trimmed), nil
	}
}

// DefaultValidator creates a validator verifying length constraints, character patterns,
// consecutive separators, and reserved keywords.
func DefaultValidator(minLen, maxLen int, reserved map[string]struct{}) Validator {
	return func(raw string) error {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			return ErrInvalidFormat
		}
		if len(trimmed) < minLen {
			return fmt.Errorf("%w: minimum length is %d", ErrTooShort, minLen)
		}
		if len(trimmed) > maxLen {
			return fmt.Errorf("%w: maximum length is %d", ErrTooLong, maxLen)
		}

		// Prevent consecutive underscores or hyphens to eliminate visual ambiguity
		if strings.Contains(trimmed, "--") || strings.Contains(trimmed, "__") ||
			strings.Contains(trimmed, "-_") || strings.Contains(trimmed, "_-") {
			return fmt.Errorf("%w: consecutive special characters are not allowed", ErrInvalidFormat)
		}

		if len(trimmed) == 1 {
			if !singleCharRegex.MatchString(trimmed) {
				return ErrInvalidFormat
			}
		} else if !defaultUsernameRegex.MatchString(trimmed) {
			return ErrInvalidFormat
		}

		// Check reserved names (case-insensitive check)
		lower := strings.ToLower(trimmed)
		if _, ok := reserved[lower]; ok {
			return ErrReserved
		}

		return nil
	}
}
