package captcha

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Verifier handles outgoing HTTP verification requests to captcha provider APIs.
type Verifier struct{}

// NewVerifier returns a new Verifier instance.
func NewVerifier() *Verifier {
	return &Verifier{}
}

// turnstileResponse represents Cloudflare Turnstile siteverify API response.
type turnstileResponse struct {
	Success     bool     `json:"success"`
	ErrorCodes  []string `json:"error-codes"`
	ChallengeTS string   `json:"challenge_ts"`
	Hostname    string   `json:"hostname"`
	Action      string   `json:"action"`
	CData       string   `json:"cdata"`
}

// recaptchaResponse represents Google reCAPTCHA v2/v3 siteverify API response.
type recaptchaResponse struct {
	Success     bool     `json:"success"`
	Score       float64  `json:"score"`
	Action      string   `json:"action"`
	ChallengeTS string   `json:"challenge_ts"`
	Hostname    string   `json:"hostname"`
	ErrorCodes  []string `json:"error-codes"`
}

// hcaptchaResponse represents hCaptcha siteverify API response.
type hcaptchaResponse struct {
	Success     bool     `json:"success"`
	ChallengeTS string   `json:"challenge_ts"`
	Hostname    string   `json:"hostname"`
	Credit      bool     `json:"credit"`
	ErrorCodes  []string `json:"error-codes"`
}

// captchafoxResponse represents CaptchaFox siteverify API response.
type captchafoxResponse struct {
	Success    bool     `json:"success"`
	ErrorCodes []string `json:"error-codes"`
	Hostname   string   `json:"hostname"`
}

// Verify executes verification for the configured captcha provider.
func (v *Verifier) Verify(ctx context.Context, cfg Config, token string, remoteIP string) error {
	if cfg.SecretKey == "" {
		return ErrMissingSecretKey
	}

	client := cfg.HTTPClient
	if client == nil {
		timeout := cfg.Timeout
		if timeout <= 0 {
			timeout = DefaultVerifyTimeout
		}
		client = &http.Client{Timeout: timeout}
	}

	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	switch cfg.Provider {
	case ProviderCloudflareTurnstile:
		return v.verifyTurnstile(ctx, client, cfg, token, remoteIP)
	case ProviderGoogleRecaptcha:
		return v.verifyGoogleRecaptcha(ctx, client, cfg, token, remoteIP)
	case ProviderHCaptcha:
		return v.verifyHCaptcha(ctx, client, cfg, token, remoteIP)
	case ProviderCaptchaFox:
		return v.verifyCaptchaFox(ctx, client, cfg, token, remoteIP)
	default:
		return ErrInvalidProvider
	}
}

func (v *Verifier) getEndpointURL(cfg Config, provider Provider) string {
	if cfg.SiteVerifyURLOverride != "" {
		return cfg.SiteVerifyURLOverride
	}
	if u, ok := DefaultSiteVerifyURLs[provider]; ok {
		return u
	}
	return ""
}

func (v *Verifier) verifyTurnstile(ctx context.Context, client *http.Client, cfg Config, token, remoteIP string) error {
	endpoint := v.getEndpointURL(cfg, ProviderCloudflareTurnstile)
	payload := map[string]string{
		"secret":   cfg.SecretKey,
		"response": token,
	}
	if remoteIP != "" {
		payload["remoteip"] = remoteIP
	}

	jsonBytes, err := json.Marshal(payload)
	if err != nil {
		return ErrServiceUnavailable
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewBuffer(jsonBytes))
	if err != nil {
		return ErrServiceUnavailable
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return ErrServiceUnavailable
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ErrServiceUnavailable
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ErrServiceUnavailable
	}

	var result turnstileResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return ErrServiceUnavailable
	}

	if !result.Success {
		return ErrVerificationFailed
	}

	if cfg.ExpectedAction != "" && result.Action != cfg.ExpectedAction {
		return ErrActionMismatch
	}

	if len(cfg.AllowedHostnames) > 0 && !containsString(cfg.AllowedHostnames, result.Hostname) {
		return ErrHostnameMismatch
	}

	return nil
}

func (v *Verifier) verifyGoogleRecaptcha(ctx context.Context, client *http.Client, cfg Config, token, remoteIP string) error {
	endpoint := v.getEndpointURL(cfg, ProviderGoogleRecaptcha)
	formData := url.Values{}
	formData.Set("secret", cfg.SecretKey)
	formData.Set("response", token)
	if remoteIP != "" {
		formData.Set("remoteip", remoteIP)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(formData.Encode()))
	if err != nil {
		return ErrServiceUnavailable
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return ErrServiceUnavailable
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ErrServiceUnavailable
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ErrServiceUnavailable
	}

	var result recaptchaResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return ErrServiceUnavailable
	}

	if !result.Success {
		return ErrVerificationFailed
	}

	if result.Score > 0 && result.Score < cfg.MinScore {
		return ErrScoreTooLow
	}

	if cfg.ExpectedAction != "" && result.Action != "" && result.Action != cfg.ExpectedAction {
		return ErrActionMismatch
	}

	if len(cfg.AllowedHostnames) > 0 && result.Hostname != "" && !containsString(cfg.AllowedHostnames, result.Hostname) {
		return ErrHostnameMismatch
	}

	return nil
}

func (v *Verifier) verifyHCaptcha(ctx context.Context, client *http.Client, cfg Config, token, remoteIP string) error {
	endpoint := v.getEndpointURL(cfg, ProviderHCaptcha)
	formData := url.Values{}
	formData.Set("secret", cfg.SecretKey)
	formData.Set("response", token)
	if cfg.SiteKey != "" {
		formData.Set("sitekey", cfg.SiteKey)
	}
	if remoteIP != "" {
		formData.Set("remoteip", remoteIP)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(formData.Encode()))
	if err != nil {
		return ErrServiceUnavailable
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return ErrServiceUnavailable
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ErrServiceUnavailable
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ErrServiceUnavailable
	}

	var result hcaptchaResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return ErrServiceUnavailable
	}

	if !result.Success {
		return ErrVerificationFailed
	}

	if len(cfg.AllowedHostnames) > 0 && result.Hostname != "" && !containsString(cfg.AllowedHostnames, result.Hostname) {
		return ErrHostnameMismatch
	}

	return nil
}

func (v *Verifier) verifyCaptchaFox(ctx context.Context, client *http.Client, cfg Config, token, remoteIP string) error {
	endpoint := v.getEndpointURL(cfg, ProviderCaptchaFox)
	formData := url.Values{}
	formData.Set("secret", cfg.SecretKey)
	formData.Set("response", token)
	if cfg.SiteKey != "" {
		formData.Set("sitekey", cfg.SiteKey)
	}
	if remoteIP != "" {
		formData.Set("remoteIp", remoteIP)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(formData.Encode()))
	if err != nil {
		return ErrServiceUnavailable
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return ErrServiceUnavailable
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ErrServiceUnavailable
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ErrServiceUnavailable
	}

	var result captchafoxResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return ErrServiceUnavailable
	}

	if !result.Success {
		return ErrVerificationFailed
	}

	if len(cfg.AllowedHostnames) > 0 && result.Hostname != "" && !containsString(cfg.AllowedHostnames, result.Hostname) {
		return ErrHostnameMismatch
	}

	return nil
}

func containsString(slice []string, val string) bool {
	for _, s := range slice {
		if s == val {
			return true
		}
	}
	return false
}
