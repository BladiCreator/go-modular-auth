package customsession

import (
	"net/http"

	"github.com/BladiCreator/go-modular-auth/domain/dto"
)

// Event constants for CustomSession plugin lifecycle hooks.
const (
	// EventTransformBefore is emitted immediately before executing session transformation logic.
	EventTransformBefore = "customsession:transform:before"

	// EventTransformAfter is emitted immediately after a successful session transformation.
	EventTransformAfter = "customsession:transform:after"

	// EventTransformError is emitted when session transformation encounters an error.
	EventTransformError = "customsession:transform:error"
)

// TransformEventPayload holds event metadata dispatched across EventBus during transformation execution.
type TransformEventPayload struct {
	// SessionData is the initial session and user payload before transformation.
	SessionData *dto.SessionData `json:"sessionData"`

	// TransformedData is the resulting payload produced by TransformSessionFunc.
	TransformedData any `json:"transformedData,omitempty"`

	// Request is the active HTTP request triggering the transformation.
	Request *http.Request `json:"-"`

	// Err contains any error encountered during transformation processing.
	Err error `json:"error,omitempty"`
}
