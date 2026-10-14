package policy

import (
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	"github.com/BladiCreator/go-modular-auth/schema"
	"github.com/BladiCreator/go-modular-auth/user"
)

// User aliases the Core User model.
type User = user.User

// Effect defines the authorization outcome.
type Effect string

const (
	// EffectAllow grants access to the requested action on the target resource.
	EffectAllow Effect = "allow"

	// EffectDeny prohibits access to the requested action.
	EffectDeny Effect = "deny"

	// EffectChallenge indicates that access is pending an additional challenge (e.g. MFA, re-auth).
	EffectChallenge Effect = "challenge"
)

// ChallengeInfo describes the specific challenge requirement when Effect is EffectChallenge.
type ChallengeInfo struct {
	Type    string         `json:"type"`              // e.g. "mfa", "step_up", "reauth", "device_verification"
	Message string         `json:"message,omitempty"` // User-friendly description of why the challenge is required
	Details map[string]any `json:"details,omitempty"` // Contextual parameters for the challenge
}

// Decision represents the structured outcome of a policy evaluation.
type Decision struct {
	Effect      Effect         `json:"effect"`
	Reason      string         `json:"reason,omitempty"`
	Challenge   *ChallengeInfo `json:"challenge,omitempty"`
	PolicyID    string         `json:"policy_id,omitempty"`
	EvaluatedAt time.Time      `json:"evaluated_at"`
}

// IsAllowed returns true if the decision granted access.
func (d Decision) IsAllowed() bool {
	return d.Effect == EffectAllow
}

// IsDenied returns true if the decision denied access.
func (d Decision) IsDenied() bool {
	return d.Effect == EffectDeny
}

// IsChallenge returns true if the decision requires a challenge.
func (d Decision) IsChallenge() bool {
	return d.Effect == EffectChallenge
}

// Resource identifies the target entity and its contextual attributes.
type Resource struct {
	Type           string     `json:"type"`
	ID             string     `json:"id"`
	OrganizationID string     `json:"organization_id,omitempty"`
	OwnerID        string     `json:"owner_id,omitempty"`
	Attributes     Attributes `json:"attributes,omitempty"`
}

// NewResource constructs a resource descriptor.
func NewResource(resType, id string) Resource {
	return Resource{
		Type:       resType,
		ID:         id,
		Attributes: make(Attributes),
	}
}

// WithOrg sets the organization boundary on the resource.
func (r Resource) WithOrg(orgID string) Resource {
	r.OrganizationID = orgID
	return r
}

// WithOwner sets the owner identifier on the resource.
func (r Resource) WithOwner(ownerID string) Resource {
	r.OwnerID = ownerID
	return r
}

// WithAttribute adds a key-value attribute to the resource.
func (r Resource) WithAttribute(key string, val any) Resource {
	if r.Attributes == nil {
		r.Attributes = make(Attributes)
	}
	r.Attributes[key] = val
	return r
}

// Attributes represents arbitrary typed attributes for ABAC evaluations.
type Attributes map[string]any

// Get returns the attribute value or nil if not present.
func (a Attributes) Get(key string) any {
	if a == nil {
		return nil
	}
	return a[key]
}

// GetString returns the string value of the attribute, or empty string.
func (a Attributes) GetString(key string) string {
	if v, ok := a.Get(key).(string); ok {
		return v
	}
	return ""
}

// GetBool returns the boolean value of the attribute, or false.
func (a Attributes) GetBool(key string) bool {
	if v, ok := a.Get(key).(bool); ok {
		return v
	}
	return false
}

// GetInt returns the integer value of the attribute, or 0.
func (a Attributes) GetInt(key string) int {
	switch v := a.Get(key).(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	default:
		return 0
	}
}

// Request bundles all parameters required for a policy evaluation.
type Request struct {
	Principal    auth.Principal `json:"principal"`
	User         *User          `json:"user,omitempty"`
	Organization string         `json:"organization,omitempty"`
	Resource     Resource       `json:"resource"`
	Action       string         `json:"action"`
	Attributes   Attributes     `json:"attributes,omitempty"`
}

// Allow creates an allow decision.
func Allow(policyID, reason string) Decision {
	return Decision{
		Effect:      EffectAllow,
		Reason:      reason,
		PolicyID:    policyID,
		EvaluatedAt: time.Now(),
	}
}

// Deny creates a deny decision.
func Deny(policyID, reason string) Decision {
	return Decision{
		Effect:      EffectDeny,
		Reason:      reason,
		PolicyID:    policyID,
		EvaluatedAt: time.Now(),
	}
}

// Challenge creates a challenge decision.
func Challenge(policyID string, ch ChallengeInfo) Decision {
	return Decision{
		Effect:      EffectChallenge,
		Reason:      ch.Message,
		Challenge:   &ch,
		PolicyID:    policyID,
		EvaluatedAt: time.Now(),
	}
}

// PolicyRecord represents a persisted policy metadata entry.
type PolicyRecord struct {
	ID          string    `json:"id"`
	Description string    `json:"description,omitempty"`
	Combinator  string    `json:"combinator,omitempty"` // e.g. "deny_overrides", "all_of", "any_of"
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

const (
	ModelPolicies = "policies"
)

// RegisterSchema registers the policy models in the compiled schema.
func RegisterSchema(s *schema.Schema) error {
	m := schema.NewModel(ModelPolicies, ModelPolicies, "id")
	_ = m.AddField(schema.Field{Name: "id", Type: schema.TypeString, Required: true})
	_ = m.AddField(schema.Field{Name: "description", Type: schema.TypeString})
	_ = m.AddField(schema.Field{Name: "combinator", Type: schema.TypeString, Required: true})
	_ = m.AddField(schema.Field{Name: "created_at", Type: schema.TypeTime, Required: true})
	_ = m.AddField(schema.Field{Name: "updated_at", Type: schema.TypeTime, Required: true})
	return s.AddModel(m)
}
