package audit

import (
	"encoding/json"
	"strings"
)

const redactedPlaceholder = "[REDACTED]"

// sensitiveKeys contains lower-cased sub-tokens and keys that must never be recorded.
var sensitiveKeyPatterns = []string{
	"password",
	"passwd",
	"pwd",
	"secret",
	"token",
	"bearer",
	"otp",
	"totp",
	"code",
	"hash",
	"salt",
	"private_key",
	"privatekey",
	"credential",
	"auth_code",
	"access_token",
	"refresh_token",
	"session_token",
	"authorization",
	"cookie",
	"device_code",
	"user_code",
}

// SanitizeMetadata takes arbitrary metadata or payload and produces a scrubbed,
// safe map[string]any strictly free of plaintext secrets, tokens, OTPs and passwords.
func SanitizeMetadata(input any) map[string]any {
	if input == nil {
		return make(map[string]any)
	}

	var rawMap map[string]any
	switch v := input.(type) {
	case map[string]any:
		rawMap = v
	default:
		// Convert struct or typed payload through standard JSON marshaling
		data, err := json.Marshal(input)
		if err != nil {
			return map[string]any{"raw_summary": "unserializable_payload"}
		}
		if err := json.Unmarshal(data, &rawMap); err != nil {
			return map[string]any{"raw_summary": "unparsable_payload"}
		}
	}

	result := make(map[string]any, len(rawMap))
	for k, val := range rawMap {
		if isSensitiveKey(k) {
			result[k] = redactedPlaceholder
			continue
		}
		result[k] = sanitizeValue(val)
	}
	return result
}

func isSensitiveKey(key string) bool {
	lower := strings.ToLower(strings.TrimSpace(key))
	for _, pattern := range sensitiveKeyPatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}

func sanitizeValue(val any) any {
	if val == nil {
		return nil
	}

	switch v := val.(type) {
	case map[string]any:
		cleaned := make(map[string]any, len(v))
		for subKey, subVal := range v {
			if isSensitiveKey(subKey) {
				cleaned[subKey] = redactedPlaceholder
			} else {
				cleaned[subKey] = sanitizeValue(subVal)
			}
		}
		return cleaned

	case []any:
		cleanedSlice := make([]any, len(v))
		for i, elem := range v {
			cleanedSlice[i] = sanitizeValue(elem)
		}
		return cleanedSlice

	default:
		return v
	}
}
