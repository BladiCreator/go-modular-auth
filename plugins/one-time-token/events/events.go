package events

const (
	EventTokenCreated  = "one_time_token.created"
	EventTokenConsumed = "one_time_token.consumed"
	EventTokenRevoked  = "one_time_token.revoked"
)

type TokenCreatedPayload struct {
	Subject string `json:"subject"`
	Purpose string `json:"purpose"`
}

type TokenConsumedPayload struct {
	TokenID string `json:"token_id"`
	Subject string `json:"subject"`
	Purpose string `json:"purpose"`
}
