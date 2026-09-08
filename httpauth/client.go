package httpauth

import (
	"net"
	"net/http"
	"strings"
)

// GetClientIP extracts and validates the real client IP address from an HTTP request.
// It follows the resolution hierarchy:
//  1. X-Forwarded-For header (first valid IP in a comma-separated list)
//  2. X-Real-IP header
//  3. RemoteAddr (stripping host port if present)
//
// Returns a canonical string representation of the IP, or empty string if no valid IP is detected.
func GetClientIP(r *http.Request) string {
	if r == nil {
		return ""
	}

	// 1. Check X-Forwarded-For header.
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		for _, part := range strings.Split(xff, ",") {
			candidate := strings.TrimSpace(part)
			if candidate == "" {
				continue
			}
			if ip := net.ParseIP(candidate); ip != nil {
				return ip.String()
			}
		}
	}

	// 2. Check X-Real-IP header.
	if xrip := r.Header.Get("X-Real-IP"); xrip != "" {
		candidate := strings.TrimSpace(xrip)
		if ip := net.ParseIP(candidate); ip != nil {
			return ip.String()
		}
	}

	// 3. Fallback to RemoteAddr.
	if r.RemoteAddr != "" {
		remote := strings.TrimSpace(r.RemoteAddr)
		if host, _, err := net.SplitHostPort(remote); err == nil {
			if ip := net.ParseIP(strings.TrimSpace(host)); ip != nil {
				return ip.String()
			}
		}
		if ip := net.ParseIP(remote); ip != nil {
			return ip.String()
		}
	}

	return ""
}

// GetUserAgent returns the trimmed User-Agent header value from the HTTP request.
// Returns an empty string if the request is nil or the header is not provided.
func GetUserAgent(r *http.Request) string {
	if r == nil {
		return ""
	}
	return strings.TrimSpace(r.UserAgent())
}
