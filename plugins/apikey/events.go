package apikey

const (
	// EventApiKeyCreated is emitted after a new API Key is successfully issued.
	// Payload: *ApiKeyCreatedPayload
	EventApiKeyCreated = "apikey:created"

	// EventApiKeyVerified is emitted after an incoming API Key verification attempt completes.
	// Payload: *ApiKeyVerifiedPayload
	EventApiKeyVerified = "apikey:verified"

	// EventApiKeyUpdated is emitted when an existing API Key record is modified.
	// Payload: *ApiKeyUpdatedPayload
	EventApiKeyUpdated = "apikey:updated"

	// EventApiKeyDeleted is emitted when an API Key is deleted or revoked.
	// Payload: *ApiKeyDeletedPayload
	EventApiKeyDeleted = "apikey:deleted"

	// EventApiKeyExpired is emitted when an expired API Key is attempted or purged.
	// Payload: *ApiKeyExpiredPayload
	EventApiKeyExpired = "apikey:expired"
)

// ApiKeyCreatedPayload contains details of a newly created API Key.
type ApiKeyCreatedPayload struct {
	// ApiKey is the created API Key entity record.
	ApiKey *ApiKey

	// RawKey is the plaintext unhashed key string.
	RawKey string
}

// ApiKeyVerifiedPayload contains details of an API Key authentication check.
type ApiKeyVerifiedPayload struct {
	// ApiKey is the retrieved API Key record (if located).
	ApiKey *ApiKey

	// Valid reports whether authentication succeeded.
	Valid bool

	// Error reports reason for verification failure if Valid is false.
	Error string
}

// ApiKeyUpdatedPayload contains details of an updated API Key.
type ApiKeyUpdatedPayload struct {
	// ApiKey is the updated API Key record.
	ApiKey *ApiKey
}

// ApiKeyDeletedPayload reports an API Key deletion.
type ApiKeyDeletedPayload struct {
	// KeyID is the unique identifier of the deleted API Key.
	KeyID string
}

// ApiKeyExpiredPayload reports an expired API Key.
type ApiKeyExpiredPayload struct {
	// KeyID is the unique identifier of the expired API Key.
	KeyID string
}
