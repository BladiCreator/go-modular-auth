package lastlogin

import (
	"errors"
	"time"
)

var (
	ErrNotFound      = errors.New("lastlogin: record not found")
	ErrInvalidUserID = errors.New("lastlogin: user_id is required")
	ErrInvalidMethod = errors.New("lastlogin: auth method is required")
)

// Record captures metadata of a user's latest authentication.
type Record struct {
	UserID     string    `json:"user_id"`
	AccountID  string    `json:"account_id,omitempty"`
	Method     string    `json:"method"`
	IP         string    `json:"ip,omitempty"`
	UserAgent  string    `json:"user_agent,omitempty"`
	LoggedInAt time.Time `json:"logged_in_at"`
}
