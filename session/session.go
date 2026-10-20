// Package session defines the Session entity: an opaque, server-side
// persisted authentication session.
package session

import "time"

// Session is a server-side session. The plaintext token is only returned to
// the client once, at creation; the store keeps TokenHash exclusively.
type Session struct {
	ID        string     `json:"id"`
	UserID    string     `json:"user_id"`
	TokenHash string     `json:"token_hash"`
	IPAddress string     `json:"ip_address"`
	UserAgent string     `json:"user_agent"`
	ExpiresAt time.Time  `json:"expires_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

// Expired reports whether the session is expired at the given instant.
func (s *Session) Expired(now time.Time) bool {
	return !now.Before(s.ExpiresAt)
}

// Revoked reports whether the session has been revoked.
func (s *Session) Revoked() bool {
	return s.RevokedAt != nil
}

// Valid reports whether the session is neither expired nor revoked.
func (s *Session) Valid(now time.Time) bool {
	return !s.Revoked() && !s.Expired(now)
}
