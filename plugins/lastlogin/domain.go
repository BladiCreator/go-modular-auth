package lastlogin

import (
	"errors"
	"time"

	"github.com/BladiCreator/go-modular-auth/schema"
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

const (
	ModelLastLogins = "last_logins"
)

// RegisterSchema registers the last_logins model with the unified schema.
func RegisterSchema(s *schema.Schema) error {
	m := schema.NewModel(ModelLastLogins, ModelLastLogins, "user_id")
	_ = m.AddField(schema.Field{Name: "user_id", Type: schema.TypeString, Required: true, Unique: true})
	_ = m.AddField(schema.Field{Name: "account_id", Type: schema.TypeString})
	_ = m.AddField(schema.Field{Name: "method", Type: schema.TypeString, Required: true})
	_ = m.AddField(schema.Field{Name: "ip", Type: schema.TypeString})
	_ = m.AddField(schema.Field{Name: "user_agent", Type: schema.TypeString})
	_ = m.AddField(schema.Field{Name: "logged_in_at", Type: schema.TypeTime, Required: true})
	return s.AddModel(m)
}
