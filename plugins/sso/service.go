package sso

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	auth "github.com/BladiCreator/go-modular-auth"
	"github.com/BladiCreator/go-modular-auth-organizations"
	"github.com/BladiCreator/go-modular-auth-sso/oidc"
	"github.com/BladiCreator/go-modular-auth-sso/saml"
	"github.com/BladiCreator/go-modular-auth-sso/store"
	"github.com/BladiCreator/go-modular-auth/account"
	sdk "github.com/BladiCreator/go-modular-auth/plugin-sdk"
	corestore "github.com/BladiCreator/go-modular-auth/store"
	"github.com/BladiCreator/go-modular-auth/user"
)

type service struct {
	ctx        *sdk.Context
	cfg        Config
	logger     *slog.Logger
	oidcClient *oidc.Client
}

var _ SSO = (*service)(nil)

func newService(ctx *sdk.Context, cfg Config) *service {
	var logger *slog.Logger
	if ctx != nil {
		logger = ctx.Logger()
	} else {
		logger = slog.Default()
	}

	return &service{
		ctx:        ctx,
		cfg:        cfg,
		logger:     logger,
		oidcClient: oidc.NewClient(cfg.HTTPClient),
	}
}

func generateID(prefix string) string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return prefix + "_" + hex.EncodeToString(b)
}

// CreateConfig provisions a new organization-scoped SSO Identity Provider configuration.
func (s *service) CreateConfig(ctx context.Context, in CreateConfigInput) (*SSOConfig, error) {
	if in.OrganizationID == "" || in.Name == "" {
		return nil, fmt.Errorf("%w: organization_id and name required", ErrInvalidInput)
	}
	if in.Protocol != ProtocolOIDC && in.Protocol != ProtocolSAML {
		return nil, fmt.Errorf("%w: protocol must be 'oidc' or 'saml'", ErrInvalidProtocol)
	}
	if len(in.Domains) == 0 {
		return nil, fmt.Errorf("%w: at least one domain must be configured", ErrInvalidInput)
	}

	// Validate protocol-specific configuration
	if in.Protocol == ProtocolOIDC {
		if in.OIDC == nil || in.OIDC.Issuer == "" || in.OIDC.ClientID == "" {
			return nil, fmt.Errorf("%w: oidc issuer and client_id required", ErrIdPValidationFailed)
		}
	} else {
		if in.SAML == nil || in.SAML.EntityID == "" || in.SAML.SSOURL == "" {
			return nil, fmt.Errorf("%w: saml entity_id and sso_url required", ErrIdPValidationFailed)
		}
	}

	now := s.cfg.Clock()
	cfgID := generateID("sso_cfg")

	attrMapping := AttributeMapping{
		EmailAttr:     "email",
		NameAttr:      "name",
		FirstNameAttr: "given_name",
		LastNameAttr:  "family_name",
		GroupsAttr:    "groups",
	}
	if in.AttributeMapping != nil {
		if in.AttributeMapping.EmailAttr != "" {
			attrMapping.EmailAttr = in.AttributeMapping.EmailAttr
		}
		if in.AttributeMapping.NameAttr != "" {
			attrMapping.NameAttr = in.AttributeMapping.NameAttr
		}
		if in.AttributeMapping.FirstNameAttr != "" {
			attrMapping.FirstNameAttr = in.AttributeMapping.FirstNameAttr
		}
		if in.AttributeMapping.LastNameAttr != "" {
			attrMapping.LastNameAttr = in.AttributeMapping.LastNameAttr
		}
		if in.AttributeMapping.GroupsAttr != "" {
			attrMapping.GroupsAttr = in.AttributeMapping.GroupsAttr
		}
		attrMapping.Custom = in.AttributeMapping.Custom
	}

	var cleanDomains []string
	for _, d := range in.Domains {
		cd := strings.ToLower(strings.TrimSpace(d))
		if cd != "" {
			cleanDomains = append(cleanDomains, cd)
		}
	}

	record := &store.SSOConfig{
		ID:               cfgID,
		OrganizationID:   in.OrganizationID,
		Name:             in.Name,
		Protocol:         in.Protocol,
		Enabled:          in.Enabled,
		Domains:          cleanDomains,
		JITEnabled:       in.JITEnabled,
		DefaultRole:      in.DefaultRole,
		AutoLink:         in.AutoLink,
		OIDC:             in.OIDC,
		SAML:             in.SAML,
		AttributeMapping: attrMapping,
		CreatedAt:        now,
		UpdatedAt:        now,
	}

	if err := s.cfg.Store.SaveConfig(ctx, record); err != nil {
		if errors.Is(err, store.ErrDomainClaimed) {
			return nil, ErrDomainConflict
		}
		return nil, err
	}

	s.emitAudit(ctx, EventConfigCreated, ConfigAuditPayload{
		OrganizationID: in.OrganizationID,
		ConfigID:       cfgID,
		ConfigName:     in.Name,
		Protocol:       in.Protocol,
		Domains:        cleanDomains,
		Action:         "create",
		Timestamp:      now,
	})

	return record, nil
}

// GetConfig retrieves a specific SSO configuration belonging to an organization.
func (s *service) GetConfig(ctx context.Context, orgID, configID string) (*SSOConfig, error) {
	if orgID == "" || configID == "" {
		return nil, ErrInvalidInput
	}
	cfg, err := s.cfg.Store.GetConfig(ctx, orgID, configID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, ErrConfigNotFound
		}
		return nil, err
	}
	return cfg, nil
}

// ListConfigsByOrganization returns all SSO configurations for a given organization.
func (s *service) ListConfigsByOrganization(ctx context.Context, orgID string) ([]*SSOConfig, error) {
	if orgID == "" {
		return nil, ErrInvalidInput
	}
	return s.cfg.Store.ListConfigsByOrganization(ctx, orgID)
}

// UpdateConfig modifies an existing organization SSO configuration.
func (s *service) UpdateConfig(ctx context.Context, in UpdateConfigInput) (*SSOConfig, error) {
	if in.OrganizationID == "" || in.ConfigID == "" {
		return nil, ErrInvalidInput
	}

	existing, err := s.GetConfig(ctx, in.OrganizationID, in.ConfigID)
	if err != nil {
		return nil, err
	}

	if in.Name != nil {
		existing.Name = *in.Name
	}
	if in.Enabled != nil {
		existing.Enabled = *in.Enabled
	}
	if in.Domains != nil {
		var cleanDomains []string
		for _, d := range in.Domains {
			cd := strings.ToLower(strings.TrimSpace(d))
			if cd != "" {
				cleanDomains = append(cleanDomains, cd)
			}
		}
		existing.Domains = cleanDomains
	}
	if in.JITEnabled != nil {
		existing.JITEnabled = *in.JITEnabled
	}
	if in.DefaultRole != nil {
		existing.DefaultRole = *in.DefaultRole
	}
	if in.AutoLink != nil {
		existing.AutoLink = *in.AutoLink
	}
	if in.OIDC != nil {
		existing.OIDC = in.OIDC
	}
	if in.SAML != nil {
		existing.SAML = in.SAML
	}
	if in.AttributeMapping != nil {
		existing.AttributeMapping = *in.AttributeMapping
	}
	existing.UpdatedAt = s.cfg.Clock()

	if err := s.cfg.Store.UpdateConfig(ctx, existing); err != nil {
		if errors.Is(err, store.ErrDomainClaimed) {
			return nil, ErrDomainConflict
		}
		return nil, err
	}

	s.emitAudit(ctx, EventConfigUpdated, ConfigAuditPayload{
		OrganizationID: in.OrganizationID,
		ConfigID:       in.ConfigID,
		ConfigName:     existing.Name,
		Protocol:       existing.Protocol,
		Domains:        existing.Domains,
		Action:         "update",
		Timestamp:      existing.UpdatedAt,
	})

	return existing, nil
}

// DeleteConfig removes an organization SSO configuration and cleans up domain mappings.
func (s *service) DeleteConfig(ctx context.Context, orgID, configID string) error {
	if orgID == "" || configID == "" {
		return ErrInvalidInput
	}

	cfg, err := s.GetConfig(ctx, orgID, configID)
	if err != nil {
		return err
	}

	if err := s.cfg.Store.DeleteConfig(ctx, orgID, configID); err != nil {
		return err
	}

	s.emitAudit(ctx, EventConfigDeleted, ConfigAuditPayload{
		OrganizationID: orgID,
		ConfigID:       configID,
		ConfigName:     cfg.Name,
		Protocol:       cfg.Protocol,
		Domains:        cfg.Domains,
		Action:         "delete",
		Timestamp:      s.cfg.Clock(),
	})

	return nil
}

// DiscoverByDomain looks up the tenant SSO provider configured for a raw domain.
func (s *service) DiscoverByDomain(ctx context.Context, domain string) (*DomainDiscoveryResult, error) {
	d := strings.ToLower(strings.TrimSpace(domain))
	if d == "" {
		return nil, fmt.Errorf("%w: domain cannot be empty", ErrInvalidInput)
	}

	cfg, err := s.cfg.Store.GetConfigByDomain(ctx, d)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, ErrDomainNotFound
		}
		return nil, err
	}

	endpoint := ""
	if cfg.Protocol == ProtocolOIDC && cfg.OIDC != nil {
		endpoint = cfg.OIDC.Issuer
	} else if cfg.Protocol == ProtocolSAML && cfg.SAML != nil {
		endpoint = cfg.SAML.SSOURL
	}

	return &DomainDiscoveryResult{
		Domain:         d,
		OrganizationID: cfg.OrganizationID,
		ConfigID:       cfg.ID,
		ConfigName:     cfg.Name,
		Protocol:       cfg.Protocol,
		SSOEndpoint:    endpoint,
	}, nil
}

// DiscoverByEmail resolves the tenant SSO provider configured for the user's email domain.
func (s *service) DiscoverByEmail(ctx context.Context, email string) (*DomainDiscoveryResult, error) {
	parts := strings.Split(email, "@")
	if len(parts) != 2 || parts[1] == "" {
		return nil, fmt.Errorf("%w: invalid email address", ErrInvalidInput)
	}
	return s.DiscoverByDomain(ctx, parts[1])
}

// InitiateSSO starts an enterprise federated login ceremony, returning redirect URL and tracking state.
func (s *service) InitiateSSO(ctx context.Context, in InitiateSSOInput) (*InitiateSSOResult, error) {
	var targetCfg *SSOConfig
	var err error

	if in.ConfigID != "" && in.OrganizationID != "" {
		targetCfg, err = s.GetConfig(ctx, in.OrganizationID, in.ConfigID)
	} else if in.Email != "" {
		discovery, discErr := s.DiscoverByEmail(ctx, in.Email)
		if discErr != nil {
			return nil, discErr
		}
		targetCfg, err = s.GetConfig(ctx, discovery.OrganizationID, discovery.ConfigID)
	} else if in.OrganizationID != "" {
		configs, listErr := s.ListConfigsByOrganization(ctx, in.OrganizationID)
		if listErr != nil {
			return nil, listErr
		}
		for _, c := range configs {
			if c.Enabled {
				targetCfg = c
				break
			}
		}
		if targetCfg == nil {
			return nil, ErrConfigNotFound
		}
	} else {
		return nil, fmt.Errorf("%w: must supply email, organization_id, or config_id", ErrInvalidInput)
	}

	if err != nil {
		return nil, err
	}
	if !targetCfg.Enabled {
		return nil, ErrConfigDisabled
	}

	now := s.cfg.Clock()
	stateToken := generateID("sso_st")
	nonce := oidc.GenerateNonce()
	expiresAt := now.Add(s.cfg.StateTTL)

	var redirectURL string
	var codeVerifier string

	if targetCfg.Protocol == ProtocolOIDC {
		verifier, challenge, pkceErr := oidc.GeneratePKCE()
		if pkceErr != nil {
			return nil, fmt.Errorf("generate pkce: %w", pkceErr)
		}
		codeVerifier = verifier

		// OIDC Discovery
		disc, discErr := s.oidcClient.Discover(ctx, targetCfg.OIDC.Issuer, targetCfg.OIDC.DiscoveryURL)
		if discErr != nil {
			return nil, discErr
		}

		redURI := in.RedirectURI
		if redURI == "" {
			redURI = targetCfg.OIDC.RedirectURI
		}

		redirectURL = s.oidcClient.BuildAuthURL(disc.AuthorizationEndpoint, targetCfg.OIDC, stateToken, nonce, challenge)
	} else if targetCfg.Protocol == ProtocolSAML {
		spEntityID := targetCfg.SAML.SPEntityID
		if spEntityID == "" {
			spEntityID = s.cfg.SPEntityID
		}
		acsURL := targetCfg.SAML.SPACSURL
		if acsURL == "" {
			acsURL = in.RedirectURI
		}
		if acsURL == "" {
			acsURL = s.cfg.SPACSURL
		}

		samlURL, _, samlErr := saml.BuildAuthnRequest(spEntityID, acsURL, targetCfg.SAML.SSOURL, stateToken)
		if samlErr != nil {
			return nil, samlErr
		}
		redirectURL = samlURL
	} else {
		return nil, ErrInvalidProtocol
	}

	stateSession := &store.SSOStateSession{
		State:          stateToken,
		OrganizationID: targetCfg.OrganizationID,
		ConfigID:       targetCfg.ID,
		Protocol:       targetCfg.Protocol,
		RedirectURI:    in.RedirectURI,
		RelayState:     in.RelayState,
		Nonce:          nonce,
		CodeVerifier:   codeVerifier,
		ExpiresAt:      expiresAt,
		CreatedAt:      now,
	}

	if err := s.cfg.Store.SaveState(ctx, stateSession); err != nil {
		return nil, err
	}

	return &InitiateSSOResult{
		RedirectURL:    redirectURL,
		State:          stateToken,
		OrganizationID: targetCfg.OrganizationID,
		ConfigID:       targetCfg.ID,
		Protocol:       targetCfg.Protocol,
		ExpiresAt:      expiresAt,
	}, nil
}

// ProcessSSOCallback validates the returned IdP assertion/token and issues a Core authenticated session.
func (s *service) ProcessSSOCallback(ctx context.Context, in ProcessSSOCallbackInput) (*SSOAuthResult, error) {
	if in.State == "" {
		return nil, fmt.Errorf("%w: state token required", ErrInvalidState)
	}

	now := s.cfg.Clock()

	// 1. Consume state session atomically
	stateSess, err := s.cfg.Store.ConsumeState(ctx, in.State, now)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, ErrInvalidState
		}
		if errors.Is(err, store.ErrStateConsumed) {
			return nil, ErrStateConsumed
		}
		return nil, err
	}

	if stateSess.Expired(now) {
		return nil, ErrStateExpired
	}

	// 2. Fetch target config strictly bounded to OrganizationID from state session
	cfg, err := s.GetConfig(ctx, stateSess.OrganizationID, stateSess.ConfigID)
	if err != nil {
		return nil, err
	}
	if !cfg.Enabled {
		return nil, ErrConfigDisabled
	}

	var subjectID string
	var extractedEmail string
	var extractedName string
	userAttrs := make(map[string]string)
	rawClaims := make(map[string]any)

	// 3. Protocol assertion parsing and validation
	if stateSess.Protocol == ProtocolOIDC {
		if in.Code == "" {
			return nil, fmt.Errorf("%w: code required for OIDC callback", ErrInvalidInput)
		}

		disc, err := s.oidcClient.Discover(ctx, cfg.OIDC.Issuer, cfg.OIDC.DiscoveryURL)
		if err != nil {
			return nil, err
		}

		redURI := in.RedirectURI
		if redURI == "" {
			redURI = stateSess.RedirectURI
		}
		if redURI == "" {
			redURI = cfg.OIDC.RedirectURI
		}

		tokenResp, err := s.oidcClient.ExchangeCode(ctx, disc.TokenEndpoint, cfg.OIDC, in.Code, stateSess.CodeVerifier, redURI)
		if err != nil {
			return nil, err
		}

		jwks, err := s.oidcClient.FetchJWKS(ctx, disc.JWKSUri)
		if err != nil {
			return nil, err
		}

		claims, err := s.oidcClient.VerifyIDToken(tokenResp.IDToken, jwks, cfg.OIDC, stateSess.Nonce, now)
		if err != nil {
			return nil, err
		}

		subjectID = claims.Subject
		extractedEmail = claims.Email
		extractedName = claims.Name
		rawClaims = claims.Raw

		// Apply custom attribute mappings if configured
		if val, ok := claims.Raw[cfg.AttributeMapping.EmailAttr].(string); ok && val != "" {
			extractedEmail = val
		}
		if val, ok := claims.Raw[cfg.AttributeMapping.NameAttr].(string); ok && val != "" {
			extractedName = val
		}
		for k, rawV := range claims.Raw {
			if strVal, ok := rawV.(string); ok {
				userAttrs[k] = strVal
			}
		}
	} else if stateSess.Protocol == ProtocolSAML {
		if in.SAMLResponse == "" {
			return nil, fmt.Errorf("%w: saml_response required", ErrInvalidInput)
		}

		expectedAud := cfg.SAML.SPEntityID
		if expectedAud == "" {
			expectedAud = s.cfg.SPEntityID
		}

		assertion, err := saml.ParseAndValidateResponse(in.SAMLResponse, cfg.SAML, expectedAud, now)
		if err != nil {
			return nil, err
		}

		subjectID = assertion.Subject
		rawClaims["subject"] = assertion.Subject
		rawClaims["issuer"] = assertion.Issuer

		for k, v := range assertion.Attributes {
			if len(v) > 0 {
				userAttrs[k] = v[0]
				rawClaims[k] = v
			}
		}

		// Apply AttributeMapping
		if vals, ok := assertion.Attributes[cfg.AttributeMapping.EmailAttr]; ok && len(vals) > 0 {
			extractedEmail = vals[0]
		} else if strings.Contains(subjectID, "@") {
			// Subject NameID format emailAddress
			extractedEmail = subjectID
		}
		if vals, ok := assertion.Attributes[cfg.AttributeMapping.NameAttr]; ok && len(vals) > 0 {
			extractedName = vals[0]
		}
	} else {
		return nil, ErrInvalidProtocol
	}

	if extractedName != "" {
		userAttrs["name"] = extractedName
	}

	extractedEmail = strings.ToLower(strings.TrimSpace(extractedEmail))
	if extractedEmail == "" {
		s.emitLoginAudit(ctx, cfg.OrganizationID, cfg.ID, "", "", cfg.Protocol, false, false, "missing email attribute")
		return nil, ErrMissingEmailAttribute
	}

	// 4. Verify domain belongs to organization (prevent cross-tenant identity injection)
	parts := strings.Split(extractedEmail, "@")
	if len(parts) != 2 {
		return nil, ErrInvalidInput
	}
	emailDomain := parts[1]

	domainAllowed := false
	for _, d := range cfg.Domains {
		if strings.EqualFold(d, emailDomain) {
			domainAllowed = true
			break
		}
	}
	if !domainAllowed {
		s.emitLoginAudit(ctx, cfg.OrganizationID, cfg.ID, "", extractedEmail, cfg.Protocol, false, false, "cross-tenant domain violation")
		return nil, fmt.Errorf("%w: domain %s not registered to organization %s", ErrCrossTenantViolation, emailDomain, cfg.OrganizationID)
	}

	// 5. Reconcile user identity in Core
	providerKey := fmt.Sprintf("sso:%s", cfg.OrganizationID)
	existingAccount, accErr := s.ctx.Store().Accounts().GetByProvider(ctx, providerKey, subjectID)

	var targetUser *user.User
	var targetAccount *account.Account
	isNewUser := false

	if accErr == nil && existingAccount != nil {
		// Existing linked account found
		targetAccount = existingAccount
		u, err := s.ctx.Store().Users().GetByID(ctx, targetAccount.UserID)
		if err != nil {
			return nil, err
		}
		targetUser = u
	} else if errors.Is(accErr, corestore.ErrNotFound) {
		// No account link exists yet. Check if a User exists with this email.
		existingUser, uErr := s.ctx.Store().Users().GetByEmail(ctx, extractedEmail)
		if uErr == nil && existingUser != nil {
			// User exists in Core
			if !cfg.AutoLink {
				s.emitLoginAudit(ctx, cfg.OrganizationID, cfg.ID, existingUser.ID, extractedEmail, cfg.Protocol, false, false, "auto-link disabled for existing user")
				return nil, ErrAccountConflict
			}

			// Link account to existing user
			acc := &account.Account{
				ID:         generateID("acc"),
				UserID:     existingUser.ID,
				Provider:   providerKey,
				ProviderID: subjectID,
				CreatedAt:  now,
				UpdatedAt:  now,
			}
			if err := s.ctx.Store().Accounts().Create(ctx, acc); err != nil {
				return nil, err
			}
			targetUser = existingUser
			targetAccount = acc
			s.emitAudit(ctx, EventAccountLinked, map[string]any{
				"organization_id": cfg.OrganizationID,
				"user_id":         existingUser.ID,
				"provider":        providerKey,
				"provider_id":     subjectID,
			})
		} else if errors.Is(uErr, corestore.ErrNotFound) {
			// User does NOT exist in Core: check JIT provisioning
			if !cfg.JITEnabled {
				s.emitLoginAudit(ctx, cfg.OrganizationID, cfg.ID, "", extractedEmail, cfg.Protocol, false, false, "jit disabled")
				return nil, ErrJITDisabled
			}

			// JIT Provision new Core User
			newUser := &user.User{
				ID:            generateID("usr"),
				Email:         extractedEmail,
				EmailVerified: true,
				CreatedAt:     now,
				UpdatedAt:     now,
			}
			if err := s.ctx.Store().Users().Create(ctx, newUser); err != nil {
				return nil, err
			}

			// Create Core Account link
			newAccount := &account.Account{
				ID:         generateID("acc"),
				UserID:     newUser.ID,
				Provider:   providerKey,
				ProviderID: subjectID,
				CreatedAt:  now,
				UpdatedAt:  now,
			}
			if err := s.ctx.Store().Accounts().Create(ctx, newAccount); err != nil {
				return nil, err
			}

			// Assign organization membership if Organizations plugin is available
			if s.cfg.Organizations != nil && cfg.DefaultRole != "" {
				_, _ = s.cfg.Organizations.AddMember(ctx, organizations.AddMemberInput{
					OrganizationID: cfg.OrganizationID,
					UserID:         newUser.ID,
					Role:           organizations.Role(cfg.DefaultRole),
				})
			}

			targetUser = newUser
			targetAccount = newAccount
			isNewUser = true

			s.emitAudit(ctx, EventJITProvisioned, map[string]any{
				"organization_id": cfg.OrganizationID,
				"user_id":         newUser.ID,
				"email":           extractedEmail,
				"role":            cfg.DefaultRole,
			})
		} else {
			return nil, uErr
		}
	} else {
		return nil, accErr
	}

	// 6. Issue Core Session
	issuedSession, err := s.ctx.Core().CreateSession(ctx, targetUser.ID, in.Session)
	if err != nil {
		return nil, err
	}

	s.emitLoginAudit(ctx, cfg.OrganizationID, cfg.ID, targetUser.ID, extractedEmail, cfg.Protocol, isNewUser, true, "")

	return &SSOAuthResult{
		User:           targetUser,
		Account:        targetAccount,
		Session:        issuedSession.Session,
		Token:          issuedSession.Token,
		IsNewUser:      isNewUser,
		OrganizationID: cfg.OrganizationID,
		ConfigID:       cfg.ID,
		Protocol:       cfg.Protocol,
		Attributes:     userAttrs,
		RawClaims:      rawClaims,
	}, nil
}

// LinkAccount explicitly associates an existing Core User with an enterprise SSO provider.
func (s *service) LinkAccount(ctx context.Context, in LinkAccountInput) (*account.Account, error) {
	if in.OrganizationID == "" || in.UserID == "" || in.ConfigID == "" || in.ProviderID == "" {
		return nil, ErrInvalidInput
	}

	cfg, err := s.GetConfig(ctx, in.OrganizationID, in.ConfigID)
	if err != nil {
		return nil, err
	}

	now := s.cfg.Clock()
	providerKey := fmt.Sprintf("sso:%s", cfg.OrganizationID)
	acc := &account.Account{
		ID:         generateID("acc"),
		UserID:     in.UserID,
		Provider:   providerKey,
		ProviderID: in.ProviderID,
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	if err := s.ctx.Store().Accounts().Create(ctx, acc); err != nil {
		return nil, err
	}

	s.emitAudit(ctx, EventAccountLinked, map[string]any{
		"organization_id": in.OrganizationID,
		"user_id":         in.UserID,
		"provider":        providerKey,
		"provider_id":     in.ProviderID,
	})

	return acc, nil
}

// UnlinkAccount removes the federated link between a user and an organization SSO provider.
func (s *service) UnlinkAccount(ctx context.Context, orgID, userID, providerID string) error {
	if orgID == "" || userID == "" || providerID == "" {
		return ErrInvalidInput
	}
	providerKey := fmt.Sprintf("sso:%s", orgID)
	acc, err := s.ctx.Store().Accounts().GetByProvider(ctx, providerKey, providerID)
	if err != nil {
		return err
	}
	if acc.UserID != userID {
		return ErrInvalidInput
	}
	return s.ctx.Store().Accounts().Delete(ctx, acc.ID)
}

// ListLinkedAccounts returns all federated accounts for a user within an organization.
func (s *service) ListLinkedAccounts(ctx context.Context, orgID, userID string) ([]*account.Account, error) {
	if orgID == "" || userID == "" {
		return nil, ErrInvalidInput
	}
	providerKey := fmt.Sprintf("sso:%s", orgID)
	accounts, err := s.ctx.Store().Accounts().ListByUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	var filtered []*account.Account
	for _, a := range accounts {
		if a.Provider == providerKey {
			filtered = append(filtered, a)
		}
	}
	return filtered, nil
}

func (s *service) emitAudit(ctx context.Context, eventType auth.EventName, payload any) {
	if s.ctx != nil && s.ctx.Events() != nil {
		s.ctx.Events().Publish(ctx, auth.Event{
			Name:    eventType,
			Time:    s.cfg.Clock(),
			Payload: payload,
		})
	}
}

func (s *service) emitLoginAudit(ctx context.Context, orgID, cfgID, userID, email string, proto Protocol, isNewUser, success bool, reason string) {
	payload := LoginAuditPayload{
		OrganizationID: orgID,
		ConfigID:       cfgID,
		UserID:         userID,
		Email:          email,
		Protocol:       proto,
		IsNewUser:      isNewUser,
		Success:        success,
		ErrorReason:    reason,
		Timestamp:      s.cfg.Clock(),
	}
	eventType := EventLoginSuccess
	if !success {
		eventType = EventLoginFailed
	}
	s.emitAudit(ctx, eventType, payload)
}
