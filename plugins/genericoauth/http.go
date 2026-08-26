package genericoauth

import (
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/BladiCreator/go-modular-auth/domain/entity"
)

type SignInRequestPayload struct {
	ProviderID  string `json:"providerId"`
	CallbackURL string `json:"callbackUrl,omitempty"`
}

type LinkAccountRequestPayload struct {
	UserID       string `json:"userId"`
	ProviderID   string `json:"providerId"`
	Code         string `json:"code"`
	CodeVerifier string `json:"codeVerifier,omitempty"`
}

// ServeSignIn handles HTTP requests to initiate an OAuth2 flow.
func (p *Plugin) ServeSignIn(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var providerID string
	var callbackURL string

	if r.Method == http.MethodPost {
		var req SignInRequestPayload
		if err := json.NewDecoder(r.Body).Decode(&req); err == nil {
			providerID = req.ProviderID
			callbackURL = req.CallbackURL
		}
	}

	if providerID == "" {
		providerID = r.URL.Query().Get("provider_id")
		if providerID == "" {
			providerID = r.URL.Query().Get("providerId")
		}
	}

	if callbackURL == "" {
		callbackURL = r.URL.Query().Get("callback_url")
		if callbackURL == "" {
			callbackURL = r.URL.Query().Get("callbackUrl")
		}
	}

	if providerID == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": "provider_id or providerId parameter is required",
		})
		return
	}

	res, err := p.SignIn(r.Context(), providerID, callbackURL)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": err.Error(),
		})
		return
	}

	// Set state and verifier cookies
	p.setCookie(w, p.config.CookieConfig.Name, res.State)
	if res.CodeVerifier != "" {
		p.setCookie(w, p.config.CookieConfig.Name+"_verifier", res.CodeVerifier)
	}

	acceptHeader := r.Header.Get("Accept")
	if r.Method == http.MethodGet && (acceptHeader == "" || acceptHeader == "*/*" || acceptHeader == "text/html") {
		http.Redirect(w, r, res.URL, http.StatusFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(res)
}

// ServeCallback handles OAuth2 redirect callbacks.
func (p *Plugin) ServeCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	q := r.URL.Query()
	code := q.Get("code")
	state := q.Get("state")
	providerID := q.Get("provider_id")
	if providerID == "" {
		providerID = q.Get("providerId")
	}

	if r.Method == http.MethodPost && (code == "" || state == "") {
		_ = r.ParseForm()
		if code == "" {
			code = r.FormValue("code")
		}
		if state == "" {
			state = r.FormValue("state")
		}
		if providerID == "" {
			providerID = r.FormValue("provider_id")
		}
	}

	// Verify state from cookie
	cookieState := p.getCookie(r, p.config.CookieConfig.Name)
	if cookieState != "" && state != "" && cookieState != state {
		p.clearCookie(w, p.config.CookieConfig.Name)
		p.clearCookie(w, p.config.CookieConfig.Name+"_verifier")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": ErrInvalidState.Error(),
		})
		return
	}

	codeVerifier := p.getCookie(r, p.config.CookieConfig.Name+"_verifier")

	// Clear cookies after retrieval
	p.clearCookie(w, p.config.CookieConfig.Name)
	p.clearCookie(w, p.config.CookieConfig.Name+"_verifier")

	user, session, tokens, err := p.Callback(r.Context(), providerID, code, state, codeVerifier)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": err.Error(),
		})
		return
	}

	responsePayload := map[string]any{
		"user":   user,
		"tokens": tokens,
	}
	if session != nil {
		responsePayload["session"] = session
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(responsePayload)
}

// ServeLinkAccount handles explicit social account linking to an active user account.
func (p *Plugin) ServeLinkAccount(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req LinkAccountRequestPayload
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": "Invalid JSON payload",
		})
		return
	}

	account, err := p.LinkAccount(r.Context(), req.UserID, req.ProviderID, req.Code, req.CodeVerifier)
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
	_ = json.NewEncoder(w).Encode(map[string]any{
		"account": account,
	})
}

func (p *Plugin) setCookie(w http.ResponseWriter, name, value string) {
	cfg := p.config.CookieConfig
	cookie := &http.Cookie{
		Name:     name,
		Value:    url.QueryEscape(value),
		Path:     cfg.Path,
		Domain:   cfg.Domain,
		Secure:   cfg.Secure,
		HttpOnly: cfg.HTTPOnly,
		SameSite: cfg.SameSite,
		MaxAge:   int(cfg.MaxAge.Seconds()),
	}
	http.SetCookie(w, cookie)
}

func (p *Plugin) getCookie(r *http.Request, name string) string {
	cookie, err := r.Cookie(name)
	if err != nil || cookie == nil {
		return ""
	}
	val, err := url.QueryUnescape(cookie.Value)
	if err != nil {
		return cookie.Value
	}
	return val
}

func (p *Plugin) clearCookie(w http.ResponseWriter, name string) {
	cfg := p.config.CookieConfig
	cookie := &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     cfg.Path,
		Domain:   cfg.Domain,
		Secure:   cfg.Secure,
		HttpOnly: cfg.HTTPOnly,
		SameSite: cfg.SameSite,
		MaxAge:   -1,
	}
	http.SetCookie(w, cookie)
}

// Dummy reference to avoid unused import error
var _ *entity.User
