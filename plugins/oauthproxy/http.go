package oauthproxy

import (
	"encoding/json"
	"net/http"
	"net/url"
)

// ServeOAuthProxyCallback handles incoming HTTP requests on the preview server's proxy callback endpoint.
// It decrypts the "profile" query parameter, validates its expiration, triggers OnSuccess if configured,
// and redirects the browser to the final callback URL.
func (p *Plugin) ServeOAuthProxyCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	profileStr := r.URL.Query().Get("profile")
	if profileStr == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error": "missing profile query parameter",
		})
		return
	}

	payload, err := p.ParsePassthroughPayload(profileStr)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error": err.Error(),
		})
		return
	}

	if p.config.OnSuccess != nil {
		if err := p.config.OnSuccess(w, r, payload); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error": err.Error(),
			})
			return
		}
	}

	redirectTarget := payload.CallbackURL
	if redirectTarget == "" {
		redirectTarget = "/"
	}

	http.Redirect(w, r, redirectTarget, http.StatusFound)
}

// InterceptSignIn returns an http.Handler middleware for Preview environments.
// It intercepts social/OAuth sign-in requests, wraps and encrypts the original state parameter into a StatePackage,
// and modifies the callback redirect_uri to point to the Production server callback URL.
func (p *Plugin) InterceptSignIn(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if CheckSkipProxy(r, p.config) {
			next.ServeHTTP(w, r)
			return
		}

		currentURL, err := ResolveCurrentURL(r, p.config)
		if err != nil {
			next.ServeHTTP(w, r)
			return
		}

		q := r.URL.Query()
		origState := q.Get("state")
		callbackURL := q.Get("callback_url")
		if callbackURL == "" {
			callbackURL = q.Get("callbackUrl")
		}

		// Encrypt original state and preview URL into StatePackage
		encryptedState, err := p.CreateStatePackage(origState, callbackURL, currentURL.String())
		if err != nil {
			http.Error(w, "Failed to encode state package for proxy", http.StatusInternalServerError)
			return
		}

		// Wrap ResponseWriter to capture standard Sign-In redirect response and adjust parameters
		rec := &proxyRedirectWriter{
			ResponseWriter: w,
			plugin:         p,
			encryptedState: encryptedState,
		}

		next.ServeHTTP(rec, r)
	})
}

// InterceptCallback returns an http.Handler middleware for Production environments.
// It checks incoming provider callback requests for an encrypted proxy state.
// If present, it intercepts the response, packages the authenticated user profile, and redirects back to Preview.
func (p *Plugin) InterceptCallback(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stateStr := r.URL.Query().Get("state")
		if stateStr == "" {
			next.ServeHTTP(w, r)
			return
		}

		// Attempt to parse state as a proxy StatePackage
		pkg, err := p.ParseStatePackage(stateStr)
		if err != nil {
			// Not a proxy state package; proceed with standard production flow
			next.ServeHTTP(w, r)
			return
		}

		// Proxy state identified: capture completion and redirect back to preview
		cbWriter := &callbackCaptureWriter{
			ResponseWriter: w,
			request:        r,
			plugin:         p,
			statePackage:   pkg,
		}

		next.ServeHTTP(cbWriter, r)
	})
}

// proxyRedirectWriter wraps http.ResponseWriter to intercept Location header redirects during sign-in.
type proxyRedirectWriter struct {
	http.ResponseWriter
	plugin         *Plugin
	encryptedState string
	redirected     bool
}

func (prw *proxyRedirectWriter) WriteHeader(statusCode int) {
	if (statusCode == http.StatusFound || statusCode == http.StatusSeeOther || statusCode == http.StatusTemporaryRedirect) && !prw.redirected {
		prw.redirected = true
		location := prw.Header().Get("Location")
		if location != "" {
			u, err := url.Parse(location)
			if err == nil {
				q := u.Query()
				q.Set("state", prw.encryptedState)

				// Adjust redirect_uri query parameter if pointing to callback
				origRedirect := q.Get("redirect_uri")
				if origRedirect != "" && prw.plugin.config.ProductionURL != "" {
					prodURL := StripTrailingSlash(prw.plugin.config.ProductionURL)
					if origURL, err := url.Parse(origRedirect); err == nil {
						newRedirect := prodURL + origURL.Path
						q.Set("redirect_uri", newRedirect)
					}
				}

				u.RawQuery = q.Encode()
				prw.Header().Set("Location", u.String())
			}
		}
	}
	prw.ResponseWriter.WriteHeader(statusCode)
}

// callbackCaptureWriter intercepts production callback execution and redirects to preview callback.
type callbackCaptureWriter struct {
	http.ResponseWriter
	request      *http.Request
	plugin       *Plugin
	statePackage *StatePackage
}

func (ccw *callbackCaptureWriter) RedirectToPreview(payload *PassthroughPayload) {
	encryptedProfile, err := ccw.plugin.CreatePassthroughPayload(payload)
	if err != nil {
		http.Error(ccw.ResponseWriter, "Failed to encode passthrough payload", http.StatusInternalServerError)
		return
	}

	previewCallback := StripTrailingSlash(ccw.statePackage.CurrentURL) + ccw.plugin.config.ProxyCallbackPath
	redirectURL, err := url.Parse(previewCallback)
	if err != nil {
		http.Error(ccw.ResponseWriter, "Invalid preview callback URL", http.StatusInternalServerError)
		return
	}

	q := redirectURL.Query()
	q.Set("profile", encryptedProfile)
	redirectURL.RawQuery = q.Encode()

	http.Redirect(ccw.ResponseWriter, ccw.request, redirectURL.String(), http.StatusFound)
}
