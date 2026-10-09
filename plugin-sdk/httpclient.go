package sdk

import "net/http"

// HTTPClient abstracts outgoing HTTP request execution, allowing custom transports,
// telemetry decoration, and mock execution in unit tests without starting real network servers.
// It is satisfied by *http.Client.
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}
