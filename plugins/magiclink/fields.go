package magiclink

import (
	"fmt"
	"strings"
)

// Context keys stored in plugin.Context for Magic Link state management.
const (
	ContextKeyMagicLinkPendingPrefix  = "magic_link_pending_"
	ContextKeyMagicLinkVerifiedPrefix = "magic_link_verified_"
)

// ToMagicLinkIdentifier formats the standard storage identifier for a magic link token.
// Format: "magic-link-token-<normalized_email>" (e.g. "magic-link-token-user@example.com")
func ToMagicLinkIdentifier(email string) string {
	return fmt.Sprintf("magic-link-token-%s", strings.ToLower(strings.TrimSpace(email)))
}

// ToMagicLinkTokenLookupKey formats a direct token identifier for reverse token lookup if needed.
// Format: "magic-link-rawtoken-<token>"
func ToMagicLinkTokenLookupKey(token string) string {
	return fmt.Sprintf("magic-link-rawtoken-%s", token)
}
