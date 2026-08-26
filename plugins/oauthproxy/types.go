package oauthproxy

import (
	"net/http"
	"time"

	"github.com/BladiCreator/go-modular-auth/domain/entity"
)

// Config holds configuration parameters for the OAuth Proxy plugin.
type Config struct {
	// CurrentURL is the explicit URL of the preview deployment (e.g. "https://preview-123.myapp.com").
	// If empty, it will be automatically resolved from request headers or vendor environment variables.
	CurrentURL string

	// ProductionURL is the base URL of the production server (e.g. "https://myapp.com").
	ProductionURL string

	// Secret is the shared encryption key shared between preview and production environments.
	Secret string

	// MaxAge is the maximum allowed age for passthrough payloads to prevent replay attacks (default: 60s).
	MaxAge time.Duration

	// ProxyCallbackPath is the path on the preview server to handle proxy callbacks (default: "/api/auth/oauth-proxy-callback").
	ProxyCallbackPath string

	// SkipProxyHeader is the HTTP header used to bypass proxy interception (default: "X-Skip-OAuth-Proxy").
	SkipProxyHeader string

	// OnSuccess is an optional hook invoked when a preview server successfully decodes a PassthroughPayload.
	OnSuccess func(w http.ResponseWriter, r *http.Request, payload *PassthroughPayload) error
}

// StatePackage encapsulates the original state, callback URL, and preview current URL.
// It is serialized to JSON and encrypted into the state query parameter sent to the OAuth provider.
type StatePackage struct {
	State       string `json:"state"`
	StateCookie string `json:"stateCookie,omitempty"`
	CallbackURL string `json:"callbackUrl,omitempty"`
	CurrentURL  string `json:"currentUrl"`
	CreatedAt   int64  `json:"createdAt"`
}

// PassthroughPayload represents the encrypted payload transferred from Production to Preview after OAuth authentication.
type PassthroughPayload struct {
	User          entity.User    `json:"user"`
	Account       entity.Account `json:"account"`
	State         string         `json:"state,omitempty"`
	CallbackURL   string         `json:"callbackUrl,omitempty"`
	NewUserURL    string         `json:"newUserUrl,omitempty"`
	ErrorURL      string         `json:"errorUrl,omitempty"`
	DisableSignUp bool           `json:"disableSignUp,omitempty"`
	Timestamp     int64          `json:"timestamp"`
}
