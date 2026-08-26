package oidcprovider

import (
	"encoding/json"
	"net/http"
)

// ServeDiscoveryMetadata is a net/http handler for serving /.well-known/openid-configuration.
func (p *Plugin) ServeDiscoveryMetadata(w http.ResponseWriter, r *http.Request) {
	meta, err := p.GetDiscoveryMetadata(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(meta)
}

// ServeJWKS is a net/http handler for serving /.well-known/jwks.json.
func (p *Plugin) ServeJWKS(w http.ResponseWriter, r *http.Request) {
	jwks, err := p.GetJWKS(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(jwks)
}
