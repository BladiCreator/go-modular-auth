package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Common provider option config struct.
type ProviderCommonConfig struct {
	ClientID            string
	ClientSecret        string
	AllowedRedirectURIs []string
	HTTPClient          HTTPClient
}

// NewGoogleProvider builds a Google OAuth 2.0 / OpenID Connect provider.
func NewGoogleProvider(cfg ProviderCommonConfig) (*GenericProvider, error) {
	return NewGenericProvider(GenericConfig{
		Name:                "google",
		ClientID:            cfg.ClientID,
		ClientSecret:        cfg.ClientSecret,
		AuthURL:             "https://accounts.google.com/o/oauth2/v2/auth",
		TokenURL:            "https://oauth2.googleapis.com/token",
		UserInfoURL:         "https://openidconnect.googleapis.com/v1/userinfo",
		Scopes:              []string{"openid", "email", "profile"},
		AllowedRedirectURIs: cfg.AllowedRedirectURIs,
		HTTPClient:          cfg.HTTPClient,
	})
}

// NewGitHubProvider builds a GitHub OAuth provider with automatic email discovery.
func NewGitHubProvider(cfg ProviderCommonConfig) (*GenericProvider, error) {
	client := cfg.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}

	extractor := func(ctx context.Context, rawBody []byte, token *TokenResponse) (*ProviderProfile, error) {
		profile, err := StandardProfileExtractor("github")(ctx, rawBody, token)
		if err != nil {
			return nil, err
		}

		// If email is empty or private on primary profile, fetch from /user/emails
		if profile.Email == "" && token.AccessToken != "" {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/user/emails", nil)
			if err == nil {
				req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token.AccessToken))
				req.Header.Set("Accept", "application/vnd.github+json")
				resp, err := client.Do(req)
				if err == nil {
					defer resp.Body.Close()
					if resp.StatusCode == http.StatusOK {
						var emails []struct {
							Email    string `json:"email"`
							Primary  bool   `json:"primary"`
							Verified bool   `json:"verified"`
						}
						b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<18))
						if json.Unmarshal(b, &emails) == nil {
							for _, e := range emails {
								if e.Primary {
									profile.Email = strings.ToLower(strings.TrimSpace(e.Email))
									profile.EmailVerified = e.Verified
									break
								}
							}
						}
					}
				}
			}
		}

		return profile, nil
	}

	return NewGenericProvider(GenericConfig{
		Name:                "github",
		ClientID:            cfg.ClientID,
		ClientSecret:        cfg.ClientSecret,
		AuthURL:             "https://github.com/login/oauth/authorize",
		TokenURL:            "https://github.com/login/oauth/access_token",
		UserInfoURL:         "https://api.github.com/user",
		Scopes:              []string{"read:user", "user:email"},
		AllowedRedirectURIs: cfg.AllowedRedirectURIs,
		HTTPClient:          cfg.HTTPClient,
		ProfileExtractor:    extractor,
	})
}

// NewGitLabProvider builds a GitLab OAuth / OIDC provider.
func NewGitLabProvider(baseURL string, cfg ProviderCommonConfig) (*GenericProvider, error) {
	if baseURL == "" {
		baseURL = "https://gitlab.com"
	}
	baseURL = strings.TrimRight(baseURL, "/")

	return NewGenericProvider(GenericConfig{
		Name:                "gitlab",
		ClientID:            cfg.ClientID,
		ClientSecret:        cfg.ClientSecret,
		AuthURL:             baseURL + "/oauth/authorize",
		TokenURL:            baseURL + "/oauth/token",
		UserInfoURL:         baseURL + "/oauth/userinfo",
		Scopes:              []string{"openid", "profile", "email"},
		AllowedRedirectURIs: cfg.AllowedRedirectURIs,
		HTTPClient:          cfg.HTTPClient,
	})
}

// NewDiscordProvider builds a Discord OAuth 2.0 provider.
func NewDiscordProvider(cfg ProviderCommonConfig) (*GenericProvider, error) {
	extractor := func(ctx context.Context, rawBody []byte, token *TokenResponse) (*ProviderProfile, error) {
		profile, err := StandardProfileExtractor("discord")(ctx, rawBody, token)
		if err != nil {
			return nil, err
		}
		// Discord avatar format: https://cdn.discordapp.com/avatars/{user_id}/{avatar_hash}.png
		if avatarHash, ok := profile.Raw["avatar"].(string); ok && avatarHash != "" && profile.ProviderID != "" {
			profile.AvatarURL = fmt.Sprintf("https://cdn.discordapp.com/avatars/%s/%s.png", profile.ProviderID, avatarHash)
		}
		return profile, nil
	}

	return NewGenericProvider(GenericConfig{
		Name:                "discord",
		ClientID:            cfg.ClientID,
		ClientSecret:        cfg.ClientSecret,
		AuthURL:             "https://discord.com/api/oauth2/authorize",
		TokenURL:            "https://discord.com/api/oauth2/token",
		UserInfoURL:         "https://discord.com/api/users/@me",
		Scopes:              []string{"identify", "email"},
		AllowedRedirectURIs: cfg.AllowedRedirectURIs,
		HTTPClient:          cfg.HTTPClient,
		ProfileExtractor:    extractor,
	})
}

// NewMicrosoftProvider builds a Microsoft Entra ID (Azure AD) OAuth 2.0 / OIDC provider.
func NewMicrosoftProvider(tenant string, cfg ProviderCommonConfig) (*GenericProvider, error) {
	if tenant == "" {
		tenant = "common"
	}
	return NewGenericProvider(GenericConfig{
		Name:                "microsoft",
		ClientID:            cfg.ClientID,
		ClientSecret:        cfg.ClientSecret,
		AuthURL:             fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/authorize", tenant),
		TokenURL:            fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", tenant),
		UserInfoURL:         "https://graph.microsoft.com/oidc/userinfo",
		Scopes:              []string{"openid", "profile", "email"},
		AllowedRedirectURIs: cfg.AllowedRedirectURIs,
		HTTPClient:          cfg.HTTPClient,
	})
}
