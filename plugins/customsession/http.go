package customsession

import (
	"encoding/json"
	"net/http"

	"github.com/BladiCreator/go-modular-auth/domain/dto"
)

// ServeGetCustomSession responds to GET /get-session requests with transformed session payloads.
func (p *Plugin) ServeGetCustomSession(w http.ResponseWriter, r *http.Request, sessionData *dto.SessionData) {
	if w == nil || r == nil {
		return
	}

	transformed, err := p.TransformSession(r.Context(), sessionData, r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(transformed)
}

// PreserveResponseHeaders copies custom headers and Set-Cookie headers from a source Header map to a ResponseWriter.
func PreserveResponseHeaders(w http.ResponseWriter, src http.Header) {
	if w == nil || src == nil {
		return
	}
	for k, vv := range src {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
}
