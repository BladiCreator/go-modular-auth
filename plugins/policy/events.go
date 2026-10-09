package policy

import (
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
)

const (
	EventPolicyEvaluated  auth.EventName = "policy.evaluated"
	EventPolicyRegistered auth.EventName = "policy.registered"
	EventPolicyRemoved    auth.EventName = "policy.removed"
)

// PolicyEvaluatedPayload is emitted when an authorization request is evaluated against policies.
type PolicyEvaluatedPayload struct {
	PrincipalSubject string    `json:"principal_subject"`
	PrincipalType    string    `json:"principal_type"`
	Organization     string    `json:"organization,omitempty"`
	ResourceType     string    `json:"resource_type"`
	ResourceID       string    `json:"resource_id"`
	Action           string    `json:"action"`
	Effect           Effect    `json:"effect"`
	Reason           string    `json:"reason,omitempty"`
	PolicyID         string    `json:"policy_id,omitempty"`
	Timestamp        time.Time `json:"timestamp"`
}

// PolicyRegisteredPayload is emitted when a new policy rule is registered.
type PolicyRegisteredPayload struct {
	PolicyID    string    `json:"policy_id"`
	Description string    `json:"description,omitempty"`
	Timestamp   time.Time `json:"timestamp"`
}

// PolicyRemovedPayload is emitted when a policy rule is removed.
type PolicyRemovedPayload struct {
	PolicyID  string    `json:"policy_id"`
	Timestamp time.Time `json:"timestamp"`
}
