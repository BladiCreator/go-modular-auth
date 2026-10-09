package ratelimit

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"

	"github.com/BladiCreator/go-modular-auth/cache"
)

// Standard rate-limited action identifiers in GoModularAuth.
const (
	ActionSignIn          = "signin"
	ActionSignUp          = "signup"
	ActionPasswordReset   = "password_reset"
	ActionEmailOTP        = "email_otp"
	ActionMagicLink       = "magic_link"
	ActionPhoneOTP        = "phone_otp"
	ActionAccountRecovery = "account_recovery"
	ActionAPIKey          = "api_key"
	ActionAdmin           = "admin"
)

// Algorithm specifies the mathematical throttling model applied.
type Algorithm string

const (
	// AlgorithmSlidingWindow tracks request counts within a moving window.
	AlgorithmSlidingWindow Algorithm = "sliding_window"

	// AlgorithmTokenBucket provides burst capacity with steady token refill.
	AlgorithmTokenBucket Algorithm = "token_bucket"
)

// KeyType specifies which attributes form the rate limit counter key.
type KeyType string

const (
	// KeyTypeIP rate limits solely based on client IP address.
	KeyTypeIP KeyType = "ip"

	// KeyTypeIdentity rate limits based on user ID, email hash, or username hash.
	KeyTypeIdentity KeyType = "identity"

	// KeyTypeComposite rate limits based on both IP and Identity.
	KeyTypeComposite KeyType = "composite"
)

// FailMode determines behavior when the cache/counter infrastructure is unavailable.
type FailMode string

const (
	// FailOpen permits requests when the counter store is unreachable (prioritizes availability).
	FailOpen FailMode = "fail_open"

	// FailClosed denies requests when the counter store is unreachable (prioritizes strict defense).
	FailClosed FailMode = "fail_closed"
)

// Request defines the context and caller attributes evaluated by the rate limiter.
type Request struct {
	Action    string `json:"action"`
	IP        string `json:"ip,omitempty"`
	Identity  string `json:"identity,omitempty"`
	CustomKey string `json:"custom_key,omitempty"`
}

// Decision represents the outcome of a rate limit evaluation.
type Decision struct {
	Allowed    bool          `json:"allowed"`
	Remaining  int64         `json:"remaining"`
	Limit      int64         `json:"limit"`
	ResetAfter time.Duration `json:"reset_after"`
	RetryAfter time.Duration `json:"retry_after"`
	Action     string        `json:"action"`
	Key        string        `json:"key"`
}

// Policy defines the rate limiting parameters applied to an action.
type Policy struct {
	Action     string        `json:"action"`
	Algorithm  Algorithm     `json:"algorithm"`
	Limit      int64         `json:"limit"`
	Window     time.Duration `json:"window"`
	Capacity   int64         `json:"capacity"`
	RefillRate float64       `json:"refill_rate"`
	KeyType    KeyType       `json:"key_type"`
	FailMode   FailMode      `json:"fail_mode"`
}

// BuildKey generates a strictly namespaced, collision-resistant cache key.
// Sensitive identifiers (passwords, raw tokens, full emails) are never used
// in plaintext; identities are hashed with SHA-256 to protect privacy and prevent collisions.
func (p Policy) BuildKey(req Request) string {
	if req.CustomKey != "" {
		return cache.Key("ratelimit", p.Action, "custom", hashIdentity(req.CustomKey))
	}

	normIP := normalizeIP(req.IP)
	normIdent := hashIdentity(req.Identity)

	switch p.KeyType {
	case KeyTypeIP:
		if normIP == "" {
			normIP = "unknown_ip"
		}
		return cache.Key("ratelimit", p.Action, "ip", normIP)

	case KeyTypeIdentity:
		if normIdent == "" {
			normIdent = "anonymous"
		}
		return cache.Key("ratelimit", p.Action, "id", normIdent)

	case KeyTypeComposite:
		fallthrough
	default:
		if normIP == "" {
			normIP = "unknown_ip"
		}
		if normIdent == "" {
			normIdent = "anonymous"
		}
		return cache.Key("ratelimit", p.Action, "comp", normIP, normIdent)
	}
}

func normalizeIP(ip string) string {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return ""
	}
	// Avoid colons in raw IPv6 colliding with cache key delimiters
	return strings.ReplaceAll(ip, ":", "_")
}

func hashIdentity(id string) string {
	id = strings.ToLower(strings.TrimSpace(id))
	if id == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(id))
	return hex.EncodeToString(sum[:16]) // 128-bit truncated hash for compact keys
}
