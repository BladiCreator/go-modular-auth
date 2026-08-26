package deviceauth

import (
	"encoding/json"
	"net/http"
)

// ServeDeviceCode is a net/http handler for processing RFC 8628 device authorization requests.
func (p *Plugin) ServeDeviceCode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var params RequestDeviceCodeParams
	if r.Header.Get("Content-Type") == "application/x-www-form-urlencoded" {
		_ = r.ParseForm()
		params.ClientID = r.FormValue("client_id")
		if scope := r.FormValue("scope"); scope != "" {
			params.Scope = &scope
		}
	} else {
		_ = json.NewDecoder(r.Body).Decode(&params)
	}

	res, err := p.RequestDeviceCode(r.Context(), params)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(res)
}

// ServeTokenExchange is a net/http handler for polling and exchanging approved device codes for tokens.
func (p *Plugin) ServeTokenExchange(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var params ExchangeDeviceTokenParams
	if r.Header.Get("Content-Type") == "application/x-www-form-urlencoded" {
		_ = r.ParseForm()
		params.DeviceCode = r.FormValue("device_code")
		params.GrantType = r.FormValue("grant_type")
		if cid := r.FormValue("client_id"); cid != "" {
			params.ClientID = &cid
		}
	} else {
		_ = json.NewDecoder(r.Body).Decode(&params)
	}

	res, err := p.ExchangeDeviceToken(r.Context(), params)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(res)
}

// ServeApprove is a net/http handler for user approval of pending device codes.
func (p *Plugin) ServeApprove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var params ApproveDeviceCodeParams
	if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	if err := p.ApproveDeviceCode(r.Context(), params); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
}
