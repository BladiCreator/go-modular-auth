package multisession

import (
	"context"
	"strings"
	"time"

	"github.com/BladiCreator/go-modular-auth/session"
)

// MultiSession is the strongly typed capability provided by the multisession module.
type MultiSession interface {
	// ListSessions returns all active, valid sessions for a user from Core SessionStore.
	ListSessions(ctx context.Context, userID string) ([]*session.Session, error)

	// ListDetailedSessions returns all active sessions for a user, enriched with device
	// and custom metadata, and flags the current session if currentSessionID matches.
	ListDetailedSessions(ctx context.Context, userID string, currentSessionID string) ([]*SessionDetail, error)

	// GetSession returns an active session by its ID. Returns ErrSessionNotFound if not found or expired.
	GetSession(ctx context.Context, sessionID string) (*session.Session, error)

	// GetDetailedSession returns an active session enriched with its metadata.
	GetDetailedSession(ctx context.Context, sessionID string) (*SessionDetail, error)

	// RevokeSession revokes a specific session by ID, updating the Store first,
	// invalidating relevant Cache entries, and publishing revocation events.
	RevokeSession(ctx context.Context, sessionID string) error

	// RevokeOtherSessions revokes all active sessions for userID except currentSessionID.
	RevokeOtherSessions(ctx context.Context, userID, currentSessionID string) error

	// RevokeAllSessions revokes every active session for userID.
	RevokeAllSessions(ctx context.Context, userID string) error

	// SetMetadata persists or updates device and custom metadata for a session.
	SetMetadata(ctx context.Context, sessionID string, meta MetadataInput) error

	// GetMetadata retrieves metadata associated with a session.
	GetMetadata(ctx context.Context, sessionID string) (*Metadata, error)
}

// Capability is an alias for MultiSession to support standard capability discovery conventions.
type Capability = MultiSession

// DeviceMetadata contains optional device identification information.
type DeviceMetadata struct {
	Name      string `json:"name,omitempty"`
	Type      string `json:"type,omitempty"`
	OS        string `json:"os,omitempty"`
	Browser   string `json:"browser,omitempty"`
	IPAddress string `json:"ip_address,omitempty"`
}

// Metadata represents optional session and device metadata associated with a Core Session.
type Metadata struct {
	SessionID string            `json:"session_id"`
	UserID    string            `json:"user_id"`
	Device    DeviceMetadata    `json:"device"`
	Custom    map[string]string `json:"custom,omitempty"`
	CreatedAt time.Time         `json:"created_at"`
	UpdatedAt time.Time         `json:"updated_at"`
}

// MetadataInput defines parameters for setting or updating session metadata.
type MetadataInput struct {
	Device DeviceMetadata    `json:"device"`
	Custom map[string]string `json:"custom,omitempty"`
}

// SessionDetail represents a Core session enriched with optional metadata and current status flag.
// Crucially, it reuses the Core session.Session entity and does not replace it.
type SessionDetail struct {
	Session   *session.Session `json:"session"`
	Metadata  *Metadata        `json:"metadata,omitempty"`
	IsCurrent bool             `json:"is_current"`
}

// ParseUserAgent extracts basic device metadata from a User-Agent string and IP address
// using pure Go string matching without external dependencies.
func ParseUserAgent(ua, ip string) DeviceMetadata {
	dev := DeviceMetadata{
		Type:      "desktop",
		IPAddress: ip,
	}

	if ua == "" {
		dev.Name = "Unknown Device"
		dev.OS = "Unknown"
		dev.Browser = "Unknown"
		dev.Type = "unknown"
		return dev
	}

	lowerUA := strings.ToLower(ua)

	// Detect Device Type & OS
	switch {
	case strings.Contains(lowerUA, "ipad"):
		dev.Type = "tablet"
		dev.OS = "iPadOS"
	case strings.Contains(lowerUA, "iphone"):
		dev.Type = "mobile"
		dev.OS = "iOS"
	case strings.Contains(lowerUA, "android"):
		dev.OS = "Android"
		if strings.Contains(lowerUA, "tablet") {
			dev.Type = "tablet"
		} else {
			dev.Type = "mobile"
		}
	case strings.Contains(lowerUA, "tablet"):
		dev.Type = "tablet"
		dev.OS = "Unknown"
	case strings.Contains(lowerUA, "macintosh") || strings.Contains(lowerUA, "mac os x"):
		dev.OS = "macOS"
		dev.Type = "desktop"
	case strings.Contains(lowerUA, "windows"):
		dev.OS = "Windows"
		dev.Type = "desktop"
	case strings.Contains(lowerUA, "cros"):
		dev.OS = "ChromeOS"
		dev.Type = "desktop"
	case strings.Contains(lowerUA, "linux"):
		dev.OS = "Linux"
		dev.Type = "desktop"
	case strings.Contains(lowerUA, "bot") || strings.Contains(lowerUA, "crawler") || strings.Contains(lowerUA, "spider"):
		dev.Type = "bot"
		dev.OS = "Unknown"
	default:
		dev.OS = "Unknown"
		dev.Type = "unknown"
	}

	// Detect Browser
	switch {
	case strings.Contains(lowerUA, "edg/"):
		dev.Browser = "Edge"
	case strings.Contains(lowerUA, "opr/") || strings.Contains(lowerUA, "opera"):
		dev.Browser = "Opera"
	case strings.Contains(lowerUA, "chrome") && !strings.Contains(lowerUA, "edg/"):
		dev.Browser = "Chrome"
	case strings.Contains(lowerUA, "firefox"):
		dev.Browser = "Firefox"
	case strings.Contains(lowerUA, "safari") && !strings.Contains(lowerUA, "chrome"):
		dev.Browser = "Safari"
	default:
		dev.Browser = "Unknown Browser"
	}

	if dev.OS != "Unknown" && dev.Browser != "Unknown Browser" {
		dev.Name = dev.Browser + " on " + dev.OS
	} else if dev.OS != "Unknown" {
		dev.Name = dev.OS + " Device"
	} else {
		dev.Name = dev.Browser
	}

	return dev
}
