package dto

import "time"

type (
	// CreateSession defines client environment details provided when creating a session.
	CreateSession struct {
		DeviceID  string `json:"device_id" binding:"required"`
		IPAddress string `json:"ip_address" binding:"required"`
		UserAgent string `json:"user_agent" binding:"required"`
	}

	// CreateSessionContext defines full session parameters passed to repository implementations.
	CreateSessionContext struct {
		UserID    string    `json:"user_id" binding:"required"`
		DeviceID  string    `json:"device_id" binding:"required"`
		Token     string    `json:"token" binding:"required"`
		IPAddress string    `json:"ip_address" binding:"required"`
		UserAgent string    `json:"user_agent" binding:"required"`
		ExpiresAt time.Time `json:"expires_at" binding:"required"`
		CreatedAt time.Time `json:"createdAt" binding:"required"`
	}
)
