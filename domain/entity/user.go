// Package entity contains domain data models representing application domain objects.
package entity

import "time"

// User represents an authenticated application user.
type User struct {
	ID               string    `json:"id"`
	Name             string    `json:"name"`
	Email            string    `json:"email"`
	PasswordHash     string    `json:"-"`
	EmailVerified    bool      `json:"emailVerified"`
	TwoFactorEnabled bool      `json:"twoFactorEnabled"`
	Role             string     `json:"role,omitempty"`
	Banned           bool       `json:"banned"`
	BanReason        *string    `json:"banReason,omitempty"`
	BanExpires       *time.Time `json:"banExpires,omitempty"`
	CreatedAt        time.Time  `json:"createdAt"`
	UpdatedAt        time.Time  `json:"updatedAt"`
}
