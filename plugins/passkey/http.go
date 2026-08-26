package passkey

import (
	"encoding/json"
	"net/http"
)

// ServeRegistrationOptions is a net/http handler for generating WebAuthn passkey registration options.
func (p *Plugin) ServeRegistrationOptions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var params GenerateRegistrationOptionsParams
	if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}
	res, err := p.GenerateRegistrationOptions(r.Context(), &params)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(res)
}

// ServeVerifyRegistration is a net/http handler for verifying WebAuthn passkey registration.
func (p *Plugin) ServeVerifyRegistration(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var params VerifyRegistrationParams
	if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}
	passkey, err := p.VerifyRegistration(r.Context(), &params)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(passkey)
}

// ServeAuthenticationOptions is a net/http handler for generating WebAuthn passkey authentication options.
func (p *Plugin) ServeAuthenticationOptions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var params GenerateAuthenticationOptionsParams
	if r.Body != nil && r.ContentLength > 0 {
		_ = json.NewDecoder(r.Body).Decode(&params)
	}
	res, err := p.GenerateAuthenticationOptions(r.Context(), &params)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(res)
}

// ServeVerifyAuthentication is a net/http handler for verifying WebAuthn passkey authentication.
func (p *Plugin) ServeVerifyAuthentication(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var params VerifyAuthenticationParams
	if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}
	res, err := p.VerifyAuthentication(r.Context(), &params)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(res)
}
