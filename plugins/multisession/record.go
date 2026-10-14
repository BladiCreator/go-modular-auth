package multisession

import (
	"time"

	"github.com/BladiCreator/go-modular-auth/schema"
)

// DeviceRecord contains persistent device identification details.
type DeviceRecord struct {
	Name      string `json:"name,omitempty"`
	Type      string `json:"type,omitempty"`
	OS        string `json:"os,omitempty"`
	Browser   string `json:"browser,omitempty"`
	IPAddress string `json:"ip_address,omitempty"`
}

// MetadataRecord is the persistent representation of session metadata.
type MetadataRecord struct {
	SessionID string            `json:"session_id"`
	UserID    string            `json:"user_id"`
	Device    DeviceRecord      `json:"device"`
	Custom    map[string]string `json:"custom,omitempty"`
	CreatedAt time.Time         `json:"created_at"`
	UpdatedAt time.Time         `json:"updated_at"`
}

const (
	ModelSessionMetadata = "session_metadata"
)

// RegisterSchema registers the session_metadata model with the unified schema.
func RegisterSchema(s *schema.Schema) error {
	m := schema.NewModel(ModelSessionMetadata, ModelSessionMetadata, "session_id")
	_ = m.AddField(schema.Field{Name: "session_id", Type: schema.TypeString, Required: true, Unique: true})
	_ = m.AddField(schema.Field{Name: "user_id", Type: schema.TypeString, Required: true})
	_ = m.AddField(schema.Field{Name: "device", Type: schema.TypeJSON})
	_ = m.AddField(schema.Field{Name: "custom", Type: schema.TypeJSON})
	_ = m.AddField(schema.Field{Name: "created_at", Type: schema.TypeTime, Required: true})
	_ = m.AddField(schema.Field{Name: "updated_at", Type: schema.TypeTime, Required: true})

	m.Indexes = []schema.Index{
		{Name: "idx_session_meta_user_id", Fields: []string{"user_id"}},
	}

	return s.AddModel(m)
}
