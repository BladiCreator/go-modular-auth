package magiclink

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
)

// ServeSignIn handles HTTP POST /sign-in/magic-link requests.
func (p *Plugin) ServeSignIn(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var params SignInMagicLinkParams
	if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	res, err := p.SignInMagicLink(r.Context(), params)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": err.Error(),
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(res)
}

// ServeVerify handles HTTP GET/POST /magic-link/verify requests.
func (p *Plugin) ServeVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	q := r.URL.Query()
	token := q.Get("token")
	email := q.Get("email")
	callbackURL := q.Get("callbackURL")
	newUserCallbackURL := q.Get("newUserCallbackURL")
	errorCallbackURL := q.Get("errorCallbackURL")

	params := VerifyMagicLinkParams{
		Token:              token,
		Email:              email,
		CallbackURL:        callbackURL,
		NewUserCallbackURL: newUserCallbackURL,
		ErrorCallbackURL:   errorCallbackURL,
	}

	res, err := p.VerifyMagicLink(r.Context(), params)
	if err != nil {
		if errorCallbackURL != "" {
			targetErrURL, parseErr := url.Parse(errorCallbackURL)
			if parseErr == nil {
				eq := targetErrURL.Query()
				eq.Set("error", err.Error())
				targetErrURL.RawQuery = eq.Encode()
				http.Redirect(w, r, targetErrURL.String(), http.StatusFound)
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": err.Error(),
		})
		return
	}

	acceptHeader := r.Header.Get("Accept")
	if strings.Contains(acceptHeader, "application/json") || r.Header.Get("X-Requested-With") != "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(res)
		return
	}

	http.Redirect(w, r, res.RedirectURL, http.StatusFound)
}
