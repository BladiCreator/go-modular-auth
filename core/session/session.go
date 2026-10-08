// Package session defines the Session entity: an opaque, server-side
// persisted authentication session.
package session

import "time"

// Session is a server-side session. The plaintext token is only returned to
// the client once, at creation; the store keeps TokenHash exclusively.
type Session struct {
	ID        string
	UserID    string
	TokenHash string
	IPAddress string
	UserAgent string
	ExpiresAt time.Time
	RevokedAt *time.Time
	CreatedAt time.Time
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
