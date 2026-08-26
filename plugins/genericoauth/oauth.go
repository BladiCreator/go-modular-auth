package genericoauth

import (
	"maps"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// GeneratePKCE creates a cryptographically secure random code_verifier and its S256 code_challenge.
func GeneratePKCE() (verifier string, challenge string, err error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", "", fmt.Errorf("failed to generate random bytes for PKCE: %w", err)
	}

	verifier = base64.RawURLEncoding.EncodeToString(buf)
	h := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(h[:])

	return verifier, challenge, nil
}

// GenerateState generates a random 32-byte hex state token.
func GenerateState() (string, error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("failed to generate random state: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// DecodeIDToken decodifies the JWT payload in id_token without verifying signature (for claims extraction).
func DecodeIDToken(idToken string) (*UserInfo, error) {
	parts := strings.Split(idToken, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid id_token format: expected at least header.payload")
	}

	payloadSegment := parts[1]
	// Handle padding if needed
	if m := len(payloadSegment) % 4; m != 0 {
		payloadSegment += strings.Repeat("=", 4-m)
	}

	payload, err := base64.URLEncoding.DecodeString(payloadSegment)
	if err != nil {
		// Try raw URLEncoding if padded decoding fails
		payload, err = base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			return nil, fmt.Errorf("failed to decode id_token payload: %w", err)
		}
	}

	var raw map[string]any
	if err := json.Unmarshal(payload, &raw); err != nil {
		return nil, fmt.Errorf("failed to unmarshal id_token payload: %w", err)
	}

	info := &UserInfo{Raw: raw}
	if sub, ok := raw["sub"].(string); ok {
		info.Sub = sub
		info.ID = sub
	}
	if email, ok := raw["email"].(string); ok {
		info.Email = email
	}
	if emailVerified, ok := raw["email_verified"].(bool); ok {
		info.EmailVerified = emailVerified
	}
	if name, ok := raw["name"].(string); ok {
		info.Name = name
	}
	if picture, ok := raw["picture"].(string); ok {
		info.Picture = picture
	}

	return info, nil
}

// BuildAuthorizationURL constructs the authorization URL for initiating OAuth2 login flow.
func BuildAuthorizationURL(provider *ProviderConfig, state string, codeChallenge string) (string, error) {
	if provider.AuthorizationURL == "" {
		return "", fmt.Errorf("%w: authorization_url is missing for provider %s", ErrInvalidParameter, provider.ProviderID)
	}

	u, err := url.Parse(provider.AuthorizationURL)
	if err != nil {
		return "", fmt.Errorf("invalid authorization_url: %w", err)
	}

	q := u.Query()
	q.Set("response_type", "code")
	if provider.ResponseType != "" {
		q.Set("response_type", provider.ResponseType)
	}

	q.Set("client_id", provider.ClientID)
	if provider.RedirectURI != "" {
		q.Set("redirect_uri", provider.RedirectURI)
	}
	if state != "" {
		q.Set("state", state)
	}
	if len(provider.Scopes) > 0 {
		q.Set("scope", strings.Join(provider.Scopes, " "))
	}
	if provider.Prompt != "" {
		q.Set("prompt", provider.Prompt)
	}
	if provider.ResponseMode != "" {
		q.Set("response_mode", string(provider.ResponseMode))
	}
	if provider.AccessType != "" {
		q.Set("access_type", provider.AccessType)
	}
	if provider.PKCE && codeChallenge != "" {
		q.Set("code_challenge", codeChallenge)
		q.Set("code_challenge_method", "S256")
	}

	for k, v := range provider.AuthURLParams {
		q.Set(k, v)
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}

// ExchangeCode performs standard OAuth 2.0 authorization code exchange for tokens.
func ExchangeCode(ctx context.Context, client *http.Client, provider *ProviderConfig, req ExchangeRequest) (*Tokens, error) {
	if provider.GetToken != nil {
		return provider.GetToken(ctx, req)
	}

	if provider.TokenURL == "" {
		return nil, fmt.Errorf("%w: token_url is missing for provider %s", ErrInvalidParameter, provider.ProviderID)
	}

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", req.Code)

	redirectURI := req.RedirectURI
	if redirectURI == "" {
		redirectURI = provider.RedirectURI
	}
	if redirectURI != "" {
		form.Set("redirect_uri", redirectURI)
	}

	if provider.PKCE && req.CodeVerifier != "" {
		form.Set("code_verifier", req.CodeVerifier)
	}

	if provider.Authentication != AuthMethodBasic {
		form.Set("client_id", provider.ClientID)
		if provider.ClientSecret != "" {
			form.Set("client_secret", provider.ClientSecret)
		}
	}

	bodyStr := form.Encode()
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, provider.TokenURL, strings.NewReader(bodyStr))
	if err != nil {
		return nil, fmt.Errorf("failed to create token request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	httpReq.Header.Set("Accept", "application/json")

	maps.Copy(httpReq.Header, provider.AuthorizationHeaders)

	if provider.Authentication == AuthMethodBasic {
		httpReq.SetBasicAuth(provider.ClientID, provider.ClientSecret)
	}

	if client == nil {
		client = http.DefaultClient
	}

	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCodeExchangeFailed, err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to read token response: %v", ErrCodeExchangeFailed, err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: token endpoint returned status %d: %s", ErrCodeExchangeFailed, resp.StatusCode, string(bodyBytes))
	}

	var raw map[string]any
	if err := json.Unmarshal(bodyBytes, &raw); err != nil {
		return nil, fmt.Errorf("%w: failed to parse token response JSON: %v", ErrCodeExchangeFailed, err)
	}

	tokens := &Tokens{Raw: raw}
	if accessToken, ok := raw["access_token"].(string); ok {
		tokens.AccessToken = accessToken
	}
	if refreshToken, ok := raw["refresh_token"].(string); ok {
		tokens.RefreshToken = refreshToken
	}
	if idToken, ok := raw["id_token"].(string); ok {
		tokens.IDToken = idToken
	}
	if tokenType, ok := raw["token_type"].(string); ok {
		tokens.TokenType = tokenType
	}
	if expiresIn, ok := raw["expires_in"].(float64); ok && expiresIn > 0 {
		tokens.AccessTokenExpiresAt = time.Now().Add(time.Duration(expiresIn) * time.Second)
	}

	return tokens, nil
}

// FetchUserInfo obtains profile information from provider user_info_url or decodes id_token.
func FetchUserInfo(ctx context.Context, client *http.Client, provider *ProviderConfig, tokens *Tokens) (*UserInfo, error) {
	if provider.GetUserInfo != nil {
		return provider.GetUserInfo(ctx, tokens)
	}

	// If override_user_info is false and id_token is available, attempt decoding id_token first
	if !provider.OverrideUserInfo && tokens.IDToken != "" {
		if info, err := DecodeIDToken(tokens.IDToken); err == nil && (info.ID != "" || info.Email != "") {
			return info, nil
		}
	}

	if provider.UserInfoURL == "" {
		// Fallback to id_token decoding if user_info_url is not set
		if tokens.IDToken != "" {
			return DecodeIDToken(tokens.IDToken)
		}
		return nil, fmt.Errorf("%w: user_info_url and id_token are missing for provider %s", ErrUserInfoFailed, provider.ProviderID)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, provider.UserInfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create user info request: %w", err)
	}

	httpReq.Header.Set("Authorization", fmt.Sprintf("%s %s", tokens.TokenType, tokens.AccessToken))
	if tokens.TokenType == "" {
		httpReq.Header.Set("Authorization", fmt.Sprintf("Bearer %s", tokens.AccessToken))
	}
	httpReq.Header.Set("Accept", "application/json")

	if client == nil {
		client = http.DefaultClient
	}

	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUserInfoFailed, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: userinfo endpoint returned status %d", ErrUserInfoFailed, resp.StatusCode)
	}

	var raw map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("%w: failed to decode user info JSON: %v", ErrUserInfoFailed, err)
	}

	info := &UserInfo{Raw: raw}
	if sub, ok := raw["sub"].(string); ok {
		info.Sub = sub
		info.ID = sub
	} else if id, ok := raw["id"].(string); ok {
		info.ID = id
		info.Sub = id
	} else if idNum, ok := raw["id"].(float64); ok {
		info.ID = fmt.Sprintf("%.0f", idNum)
		info.Sub = info.ID
	}

	if email, ok := raw["email"].(string); ok {
		info.Email = email
	}
	if emailVerified, ok := raw["email_verified"].(bool); ok {
		info.EmailVerified = emailVerified
	}
	if name, ok := raw["name"].(string); ok {
		info.Name = name
	}
	if picture, ok := raw["picture"].(string); ok {
		info.Picture = picture
	} else if avatarURL, ok := raw["avatar_url"].(string); ok {
		info.Picture = avatarURL
	}

	return info, nil
}
