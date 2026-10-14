package saml

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	"github.com/BladiCreator/go-modular-auth/account"
	"github.com/BladiCreator/go-modular-auth/adapter"
	sdk "github.com/BladiCreator/go-modular-auth/plugin-sdk"
	corestore "github.com/BladiCreator/go-modular-auth/store"
	"github.com/BladiCreator/go-modular-auth/user"
)

type service struct {
	ctx        *sdk.Context
	cfg        Config
	logger     *slog.Logger
	idps       *sdk.Repository[IdPConfig]
	requests   *sdk.Repository[RequestSession]
	assertions *sdk.Repository[AssertionRecord]
}

var _ SAML = (*service)(nil)

func newService(ctx *sdk.Context, cfg Config) *service {
	var logger *slog.Logger
	var idps *sdk.Repository[IdPConfig]
	var requests *sdk.Repository[RequestSession]
	var assertions *sdk.Repository[AssertionRecord]
	if ctx != nil {
		logger = ctx.Logger()
		idps = sdk.Model[IdPConfig](ctx, ModelSAMLIdPs)
		requests = sdk.Model[RequestSession](ctx, ModelSAMLRequests)
		assertions = sdk.Model[AssertionRecord](ctx, ModelSAMLAssertions)
	} else {
		logger = slog.Default()
	}

	return &service{
		ctx:        ctx,
		cfg:        cfg,
		logger:     logger,
		idps:       idps,
		requests:   requests,
		assertions: assertions,
	}
}

func generateID(prefix string) string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return prefix + "_" + hex.EncodeToString(b)
}

// RegisterIdP provisions a new SAML Identity Provider configuration.
func (s *service) RegisterIdP(ctx context.Context, in RegisterIdPInput) (*IdPConfig, error) {
	if in.ID == "" || in.EntityID == "" || in.SSOURL == "" {
		return nil, fmt.Errorf("%w: id, entity_id, and sso_url are required", ErrInvalidInput)
	}

	now := s.cfg.Clock()
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

	cfg := &IdPConfig{
		ID:               in.ID,
		OrganizationID:   in.OrganizationID,
		EntityID:         in.EntityID,
		SSOURL:           in.SSOURL,
		SLOURL:           in.SLOURL,
		Certificates:     in.Certificates,
		SPEntityID:       in.SPEntityID,
		ACSURL:           in.ACSURL,
		NameIDFormat:     in.NameIDFormat,
		SignRequest:      in.SignRequest,
		AllowUnsolicited: in.AllowUnsolicited,
		ClockSkew:        in.ClockSkew,
		AttributeMapping: attrMapping,
		Enabled:          in.Enabled,
		CreatedAt:        now,
		UpdatedAt:        now,
	}

	if err := s.idps.Create(ctx, cfg); err != nil {
		return nil, err
	}

	s.emitAudit(ctx, EventIdPRegistered, map[string]any{
		"provider_id": in.ID,
		"entity_id":   in.EntityID,
		"org_id":      in.OrganizationID,
	})

	return cfg, nil
}

// RegisterIdPFromMetadata parses and registers an IdP directly from its EntityDescriptor XML.
func (s *service) RegisterIdPFromMetadata(ctx context.Context, id, orgID string, metadataXML []byte) (*IdPConfig, error) {
	if id == "" || len(metadataXML) == 0 {
		return nil, ErrInvalidInput
	}

	parsed, err := ParseIdPMetadata(metadataXML)
	if err != nil {
		return nil, err
	}

	return s.RegisterIdP(ctx, RegisterIdPInput{
		ID:             id,
		OrganizationID: orgID,
		EntityID:       parsed.EntityID,
		SSOURL:         parsed.SSOURL,
		SLOURL:         parsed.SLOURL,
		Certificates:   parsed.Certificates,
		Enabled:        true,
	})
}

// GetIdP retrieves an IdP configuration by its provider identifier.
func (s *service) GetIdP(ctx context.Context, id string) (*IdPConfig, error) {
	if id == "" {
		return nil, ErrInvalidInput
	}
	cfg, err := s.idps.FindOne(ctx, adapter.Eq("id", id))
	if err != nil {
		if errors.Is(err, adapter.ErrNotFound) {
			return nil, ErrProviderNotFound
		}
		return nil, err
	}
	return cfg, nil
}

// GetIdPByEntityID retrieves an IdP configuration by its unique SAML EntityID.
func (s *service) GetIdPByEntityID(ctx context.Context, entityID string) (*IdPConfig, error) {
	if entityID == "" {
		return nil, ErrInvalidInput
	}
	cfg, err := s.idps.FindOne(ctx, adapter.Eq("entity_id", entityID))
	if err != nil {
		if errors.Is(err, adapter.ErrNotFound) {
			return nil, ErrProviderNotFound
		}
		return nil, err
	}
	return cfg, nil
}

// ListIdPs returns registered IdPs, optionally scoped to an organization.
func (s *service) ListIdPs(ctx context.Context, orgID string) ([]*IdPConfig, error) {
	q := adapter.Query{Model: ModelSAMLIdPs}
	if orgID != "" {
		q.Where = []adapter.Condition{adapter.Eq("organization_id", orgID)}
	}
	items, err := s.idps.FindMany(ctx, q)
	if err != nil {
		return nil, err
	}
	results := make([]*IdPConfig, len(items))
	for i := range items {
		results[i] = &items[i]
	}
	return results, nil
}

// UpdateIdP updates an existing IdP configuration.
func (s *service) UpdateIdP(ctx context.Context, in UpdateIdPInput) (*IdPConfig, error) {
	if in.ID == "" {
		return nil, ErrInvalidInput
	}

	existing, err := s.GetIdP(ctx, in.ID)
	if err != nil {
		return nil, err
	}

	if in.EntityID != nil {
		existing.EntityID = *in.EntityID
	}
	if in.SSOURL != nil {
		existing.SSOURL = *in.SSOURL
	}
	if in.SLOURL != nil {
		existing.SLOURL = *in.SLOURL
	}
	if in.Certificates != nil {
		existing.Certificates = in.Certificates
	}
	if in.SPEntityID != nil {
		existing.SPEntityID = *in.SPEntityID
	}
	if in.ACSURL != nil {
		existing.ACSURL = *in.ACSURL
	}
	if in.NameIDFormat != nil {
		existing.NameIDFormat = *in.NameIDFormat
	}
	if in.SignRequest != nil {
		existing.SignRequest = *in.SignRequest
	}
	if in.AllowUnsolicited != nil {
		existing.AllowUnsolicited = *in.AllowUnsolicited
	}
	if in.ClockSkew != nil {
		existing.ClockSkew = *in.ClockSkew
	}
	if in.AttributeMapping != nil {
		existing.AttributeMapping = *in.AttributeMapping
	}
	if in.Enabled != nil {
		existing.Enabled = *in.Enabled
	}
	existing.UpdatedAt = s.cfg.Clock()

	// Update by saving modified record
	_, _ = s.idps.Delete(ctx, adapter.Eq("id", in.ID))
	if err := s.idps.Create(ctx, existing); err != nil {
		return nil, err
	}

	s.emitAudit(ctx, EventIdPUpdated, map[string]any{
		"provider_id": in.ID,
		"entity_id":   existing.EntityID,
	})

	return existing, nil
}

// DeleteIdP removes an IdP configuration.
func (s *service) DeleteIdP(ctx context.Context, id string) error {
	if id == "" {
		return ErrInvalidInput
	}
	if _, err := s.idps.Delete(ctx, adapter.Eq("id", id)); err != nil {
		return err
	}
	s.emitAudit(ctx, EventIdPDeleted, map[string]any{"provider_id": id})
	return nil
}

// GetSPMetadata generates the Service Provider EntityDescriptor XML.
func (s *service) GetSPMetadata(ctx context.Context) ([]byte, error) {
	return GenerateSPMetadata(s.cfg.SPEntityID, s.cfg.SPACSURL, s.cfg.SPSLOURL, s.cfg.SPCertificatePEM)
}

// InitiateAuth begins an SP-initiated SAML flow, generating AuthnRequest redirect URL and tracking state.
func (s *service) InitiateAuth(ctx context.Context, in InitiateAuthInput) (*InitiateAuthResult, error) {
	if in.ProviderID == "" {
		return nil, fmt.Errorf("%w: provider_id required", ErrInvalidInput)
	}

	idp, err := s.GetIdP(ctx, in.ProviderID)
	if err != nil {
		return nil, err
	}
	if !idp.Enabled {
		return nil, ErrProviderDisabled
	}

	now := s.cfg.Clock()
	relayState := in.RelayState
	if relayState == "" {
		relayState = generateID("s_rs")
	}

	spEntityID := idp.SPEntityID
	if spEntityID == "" {
		spEntityID = s.cfg.SPEntityID
	}
	acsURL := idp.ACSURL
	if acsURL == "" {
		acsURL = s.cfg.SPACSURL
	}

	redirectURL, requestID, err := BuildAuthnRequest(spEntityID, acsURL, idp.SSOURL, relayState, idp.NameIDFormat, in.ForceAuthn, now)
	if err != nil {
		return nil, err
	}

	expiresAt := now.Add(s.cfg.RequestTTL)
	reqSess := &RequestSession{
		ID:             requestID,
		RelayState:     relayState,
		ProviderID:     idp.ID,
		OrganizationID: idp.OrganizationID,
		RedirectURI:    in.RedirectURI,
		ExpiresAt:      expiresAt,
		CreatedAt:      now,
	}

	if err := s.requests.Create(ctx, reqSess); err != nil {
		return nil, err
	}

	return &InitiateAuthResult{
		RedirectURL: redirectURL,
		RequestID:   requestID,
		RelayState:  relayState,
		Binding:     BindingHTTPRedirect,
		ExpiresAt:   expiresAt,
	}, nil
}

// ProcessACS processes and verifies an incoming SAMLResponse assertion, issuing a Core Session.
func (s *service) ProcessACS(ctx context.Context, in ProcessACSInput) (*AuthResult, error) {
	if in.SAMLResponse == "" {
		return nil, fmt.Errorf("%w: saml_response is required", ErrInvalidInput)
	}

	now := s.cfg.Clock()

	// 1. Resolve in-flight request session via RelayState if present
	var (
		reqSess  *RequestSession
		targetID string
	)

	if in.RelayState != "" {
		rs, err := s.requests.FindOne(ctx, adapter.Eq("relay_state", in.RelayState))
		if err == nil && rs != nil {
			reqSess = rs
			targetID = rs.ProviderID
		}
	}

	// If not matched by RelayState, try resolving via InResponseTo if present
	if reqSess == nil {
		inRespTo := ExtractInResponseTo(in.SAMLResponse)
		if inRespTo != "" {
			rs, err := s.requests.FindOne(ctx, adapter.Eq("id", inRespTo))
			if err == nil && rs != nil {
				reqSess = rs
				targetID = rs.ProviderID
			}
		}
	}

	// 2. Resolve IdP configuration
	var idp *IdPConfig
	var err error
	if targetID != "" {
		idp, err = s.GetIdP(ctx, targetID)
		if err != nil {
			return nil, err
		}
	} else {
		// Attempt resolution via XML Issuer
		issuer := ExtractIssuer(in.SAMLResponse)
		if issuer != "" {
			cfg, err := s.idps.FindOne(ctx, adapter.Eq("entity_id", issuer))
			if err == nil && cfg != nil {
				idp = cfg
			}
		}
		if idp == nil {
			list, _ := s.ListIdPs(ctx, "")
			for _, c := range list {
				if c.Enabled && c.AllowUnsolicited {
					idp = c
					break
				}
			}
			if idp == nil {
				if len(list) == 1 && list[0].Enabled {
					idp = list[0]
				} else {
					return nil, ErrProviderNotFound
				}
			}
		}
	}

	if !idp.Enabled {
		return nil, ErrProviderDisabled
	}

	// 3. Atomically consume Request Session if matched
	if reqSess != nil {
		consumed, err := s.consumeRequest(ctx, reqSess.ID, now)
		if err != nil {
			return nil, err
		}
		if consumed.Expired(now) {
			return nil, ErrStateExpired
		}
	} else if !idp.AllowUnsolicited {
		return nil, ErrUnsolicitedNotAllowed
	}

	// 4. Parse & Verify SAML Response
	expectedAud := idp.SPEntityID
	if expectedAud == "" {
		expectedAud = s.cfg.SPEntityID
	}
	expectedACS := idp.ACSURL
	if expectedACS == "" {
		expectedACS = s.cfg.SPACSURL
	}

	parsed, err := ParseAndVerifyResponse(in.SAMLResponse, idp, expectedAud, expectedACS, now)
	if err != nil {
		s.emitAudit(ctx, EventAuthenticationFailed, FailedPayload{
			ProviderID:  idp.ID,
			ErrorReason: err.Error(),
			OccurredAt:  now,
		})
		return nil, err
	}

	// 5. Replay Protection: Check & Record Assertion ID
	if err := s.recordAssertion(ctx, parsed.Assertion.ID, idp.ID, parsed.ExpiresAt, now); err != nil {
		return nil, err
	}

	// 6. Extract Email Attribute
	email := extractEmail(parsed.Assertion, idp.AttributeMapping)
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return nil, ErrMissingEmail
	}

	// 7. Reconcile Core User & Account
	providerKey := fmt.Sprintf("saml:%s", idp.ID)
	subjectID := parsed.Assertion.Subject

	existingAccount, accErr := s.ctx.Store().Accounts().GetByProvider(ctx, providerKey, subjectID)

	var targetUser *user.User
	var targetAccount *account.Account
	isNewUser := false

	if accErr == nil && existingAccount != nil {
		targetAccount = existingAccount
		u, err := s.ctx.Store().Users().GetByID(ctx, targetAccount.UserID)
		if err != nil {
			return nil, err
		}
		targetUser = u
	} else if errors.Is(accErr, corestore.ErrNotFound) {
		// Account does not exist yet. Check if User exists by email.
		existingUser, uErr := s.ctx.Store().Users().GetByEmail(ctx, email)
		if uErr == nil && existingUser != nil {
			// Link account
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
				"user_id":     existingUser.ID,
				"provider":    providerKey,
				"provider_id": subjectID,
			})
		} else if errors.Is(uErr, corestore.ErrNotFound) {
			if !s.cfg.AutoProvision {
				return nil, ErrAccountConflict
			}

			// JIT Provision User
			newUser := &user.User{
				ID:            generateID("usr"),
				Email:         email,
				EmailVerified: true,
				CreatedAt:     now,
				UpdatedAt:     now,
			}
			if err := s.ctx.Store().Users().Create(ctx, newUser); err != nil {
				return nil, err
			}

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

			targetUser = newUser
			targetAccount = newAccount
			isNewUser = true
		} else {
			return nil, uErr
		}
	} else {
		return nil, accErr
	}

	// 8. Issue Core Session
	issuedSession, err := s.ctx.Core().CreateSession(ctx, targetUser.ID, in.Session)
	if err != nil {
		return nil, err
	}

	redirectURI := ""
	if reqSess != nil {
		redirectURI = reqSess.RedirectURI
	}

	s.emitAudit(ctx, EventAuthenticated, AuthenticatedPayload{
		UserID:         targetUser.ID,
		AccountID:      targetAccount.ID,
		ProviderID:     idp.ID,
		OrganizationID: idp.OrganizationID,
		Subject:        subjectID,
		IsNewUser:      isNewUser,
		OccurredAt:     now,
	})

	return &AuthResult{
		User:        targetUser,
		Account:     targetAccount,
		Session:     issuedSession.Session,
		Token:       issuedSession.Token,
		IsNewUser:   isNewUser,
		ProviderID:  idp.ID,
		Assertion:   parsed.Assertion,
		RedirectURI: redirectURI,
	}, nil
}

// ListLinkedAccounts returns all SAML accounts linked to a user.
func (s *service) ListLinkedAccounts(ctx context.Context, userID string) ([]*account.Account, error) {
	if userID == "" {
		return nil, ErrInvalidInput
	}
	accounts, err := s.ctx.Store().Accounts().ListByUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	var filtered []*account.Account
	for _, a := range accounts {
		if strings.HasPrefix(a.Provider, "saml:") {
			filtered = append(filtered, a)
		}
	}
	return filtered, nil
}

// UnlinkAccount detaches a SAML provider from a user.
func (s *service) UnlinkAccount(ctx context.Context, userID, providerID string) error {
	if userID == "" || providerID == "" {
		return ErrInvalidInput
	}
	providerKey := fmt.Sprintf("saml:%s", providerID)
	accounts, err := s.ctx.Store().Accounts().ListByUser(ctx, userID)
	if err != nil {
		return err
	}
	for _, a := range accounts {
		if a.Provider == providerKey {
			return s.ctx.Store().Accounts().Delete(ctx, a.ID)
		}
	}
	return ErrProviderNotFound
}

func extractEmail(assertion *SAMLAssertion, mapping AttributeMapping) string {
	if mapping.EmailAttr != "" {
		if vals, ok := assertion.Attributes[mapping.EmailAttr]; ok && len(vals) > 0 {
			return vals[0]
		}
	}

	commonAttrs := []string{
		"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
		"urn:oid:0.9.2342.19200300.100.1.3",
		"mail",
		"email",
		"User.Email",
	}
	for _, attr := range commonAttrs {
		if vals, ok := assertion.Attributes[attr]; ok && len(vals) > 0 {
			return vals[0]
		}
	}

	if strings.Contains(assertion.Subject, "@") {
		return assertion.Subject
	}

	return ""
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

func (s *service) consumeRequest(ctx context.Context, id string, now time.Time) (*RequestSession, error) {
	if s.requests == nil {
		return nil, ErrInvalidState
	}
	req, err := s.requests.FindOne(ctx, adapter.Eq("id", id))
	if errors.Is(err, adapter.ErrNotFound) || req == nil {
		return nil, ErrInvalidState
	}
	if req.IsConsumed() {
		return nil, ErrStateConsumed
	}
	if req.Expired(now) {
		return nil, ErrStateExpired
	}

	n, err := s.requests.Update(ctx, []adapter.Condition{
		adapter.Eq("id", id),
		adapter.IsNull("consumed_at"),
	}, map[string]any{
		"consumed_at": now,
	})
	if err != nil || n == 0 {
		return nil, ErrStateConsumed
	}
	req.ConsumedAt = &now
	return req, nil
}

func (s *service) recordAssertion(ctx context.Context, assertionID, providerID string, expiresAt, now time.Time) error {
	if s.assertions == nil {
		return nil
	}
	existing, err := s.assertions.FindOne(ctx, adapter.Eq("id", assertionID))
	if err == nil && existing != nil {
		if !now.After(existing.ExpiresAt) {
			return ErrAssertionReplayed
		}
	}
	return s.assertions.Create(ctx, &AssertionRecord{
		ID:         assertionID,
		ProviderID: providerID,
		ExpiresAt:  expiresAt,
		CreatedAt:  now,
	})
}
