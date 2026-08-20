package jwt

import (
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/BladiCreator/go-modular-auth/plugin"
)

// PluginID is the unique string identifier for the JWT plugin ("jwt").
const PluginID = "jwt"

type cachedKey struct {
	record  *JWKRecord
	pubKey  crypto.PublicKey
	privKey crypto.PrivateKey
}

// Plugin implements RFC 7519 JSON Web Token issuance, verification, and JWKS key management.
type Plugin struct {
	repo       Repository
	config     Config
	ctx        *plugin.Context
	mu         sync.RWMutex
	activeKey  *JWKRecord
	activePriv crypto.PrivateKey
	cachedKeys map[string]*cachedKey
}

// New creates a new JWT plugin instance configured with a key repository and functional options.
//
// Arguments:
//   - repo: Implementation of jwt.Repository interface (can be in-memory or database).
//   - opts: Functional configuration options (WithIssuer, WithAlgorithm, WithSecret, etc.).
//
// Returns:
//   - *Plugin: The configured JWT plugin instance.
func New(repo Repository, opts ...Option) *Plugin {
	cfg := DefaultConfig()
	for _, opt := range opts {
		opt(&cfg)
	}
	return &Plugin{
		repo:       repo,
		config:     cfg,
		cachedKeys: make(map[string]*cachedKey),
	}
}

// ID returns the unique identifier for the JWT plugin ("jwt").
func (p *Plugin) ID() string {
	return PluginID
}

// Init initializes the plugin within the global GoModularAuth context and ensures an active signing key exists.
func (p *Plugin) Init(ctx *plugin.Context) error {
	p.ctx = ctx
	_, err := p.ensureActiveKey(context.Background())
	return err
}

// Config returns the active configuration settings of the JWT plugin.
func (p *Plugin) Config() Config {
	return p.config
}

// GetJWKS retrieves the public JSON Web Key Set (RFC 7517) containing active and grace-period keys.
//
// Brief Explanation:
//
//	Queries the repository for all persisted keys, filters out keys expired beyond the configured GracePeriod
//	(unless IncludeExpired is true), parses their public JWKs, and returns the assembled JWKS structure.
//
// Arguments:
//   - ctx: Request cancellation context.
//   - params: GetJWKSParams specifying whether to include fully expired keys.
//
// Returns:
//   - *GetJWKSResult: Assembled JWKS containing public keys and count.
//   - error: Database retrieval error.
//
// Example:
//
//	res, err := jwtPlugin.GetJWKS(ctx, jwt.GetJWKSParams{})
//	if err != nil {
//		log.Fatalf("Failed to retrieve JWKS: %v", err)
//	}
//	for _, k := range res.JWKS.Keys {
//		fmt.Printf("Public Key ID: %s, Alg: %s\n", k.Kid, k.Alg)
//	}
func (p *Plugin) GetJWKS(ctx context.Context, params GetJWKSParams) (*GetJWKSResult, error) {
	if p.repo == nil {
		p.mu.RLock()
		defer p.mu.RUnlock()
		if p.activeKey == nil {
			return &GetJWKSResult{JWKS: &JWKS{Keys: []JWK{}}, KeysCount: 0}, nil
		}
		var jwk JWK
		if err := json.Unmarshal([]byte(p.activeKey.PublicKey), &jwk); err != nil {
			return nil, err
		}
		return &GetJWKSResult{
			JWKS:      &JWKS{Keys: []JWK{jwk}},
			KeysCount: 1,
		}, nil
	}

	records, err := p.repo.GetAllKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("jwt: failed to fetch keys from repository: %w", err)
	}

	now := time.Now()
	var keys []JWK

	for _, rec := range records {
		if !params.IncludeExpired && rec.ExpiresAt != nil {
			if now.Sub(*rec.ExpiresAt) > p.config.GracePeriod {
				continue
			}
		}

		var jwk JWK
		if err := json.Unmarshal([]byte(rec.PublicKey), &jwk); err != nil {
			continue
		}
		keys = append(keys, jwk)
	}

	return &GetJWKSResult{
		JWKS:      &JWKS{Keys: keys},
		KeysCount: len(keys),
	}, nil
}

// Sign creates and cryptographically signs a compact serialized JWT (RFC 7519) with the active private key.
//
// Brief Explanation:
//
//	Emits EventJWTSignBefore, populates standard claims ("iss", "sub", "aud", "exp", "nbf", "iat", "jti")
//	along with custom claims, signs the token via the active cryptographic key, and emits EventJWTSignAfter.
//
// Arguments:
//   - ctx: Request cancellation context.
//   - params: SignParams containing payload, subject, issuer, audience, and expiry overrides.
//
// Returns:
//   - *SignResult: Serialized token string, key metadata, and formatted header values.
//   - error: Key resolution, serialization, or signing error.
//
// Example:
//
//	res, err := jwtPlugin.Sign(ctx, jwt.SignParams{
//		Subject: "user_12345",
//		Payload: map[string]any{
//			"role": "admin",
//			"tenant": "org_987",
//		},
//		ExpiresIn: 1 * time.Hour,
//	})
//	if err != nil {
//		log.Fatalf("Failed to sign token: %v", err)
//	}
//	fmt.Println("JWT:", res.Token)
func (p *Plugin) Sign(ctx context.Context, params SignParams) (*SignResult, error) {
	activeRecord, privKey, err := p.resolveSigningKey(ctx, params.KeyID)
	if err != nil {
		return nil, err
	}

	now := time.Now()

	claims := make(map[string]any)
	for k, v := range params.Payload {
		claims[k] = v
	}

	subject := params.Subject
	if subject != "" {
		claims["sub"] = subject
	}

	issuer := p.config.Issuer
	if params.Issuer != "" {
		issuer = params.Issuer
	}
	if issuer != "" {
		claims["iss"] = issuer
	}

	audience := p.config.Audience
	if len(params.Audience) > 0 {
		audience = params.Audience
	}
	if len(audience) == 1 {
		claims["aud"] = audience[0]
	} else if len(audience) > 1 {
		claims["aud"] = audience
	}

	claims["iat"] = now.Unix()

	if params.NotBefore != nil {
		claims["nbf"] = params.NotBefore.Unix()
	}

	expiresIn := p.config.ExpirationTime
	if params.ExpiresIn != 0 {
		expiresIn = params.ExpiresIn
	}
	expiresAt := now.Add(expiresIn)
	claims["exp"] = expiresAt.Unix()

	if _, ok := claims["jti"]; !ok {
		kid, _ := generateRandomKID()
		claims["jti"] = kid
	}

	p.publishEvent(EventJWTSignBefore, ctx, &JWTSignBeforeEventPayload{
		Params:  &params,
		Subject: subject,
		Claims:  claims,
	})

	header := JWTHeader{
		Alg: string(activeRecord.Algorithm),
		Typ: "JWT",
		Kid: activeRecord.ID,
	}

	tokenStr, err := SignJWT(header, claims, privKey, activeRecord.Algorithm)
	if err != nil {
		return nil, fmt.Errorf("jwt: failed to sign token: %w", err)
	}

	p.publishEvent(EventJWTSignAfter, ctx, &JWTSignAfterEventPayload{
		Token:     tokenStr,
		KeyID:     activeRecord.ID,
		Algorithm: activeRecord.Algorithm,
		ExpiresAt: expiresAt,
	})

	return &SignResult{
		Token:         tokenStr,
		KeyID:         activeRecord.ID,
		Algorithm:     activeRecord.Algorithm,
		ExpiresAt:     expiresAt,
		HeaderValue:   BearerSchemePrefix + tokenStr,
		AuthJWTHeader: HeaderSetAuthJWT,
	}, nil
}

// Verify parses and verifies the cryptographic signature and standard claims of a JWT.
//
// Brief Explanation:
//
//	Strips any "Bearer " scheme prefix, extracts the header to obtain the Key ID ("kid"),
//	retrieves the matching public key from cache or repository, verifies the signature in constant time,
//	validates "exp", "nbf", "iss", and "aud" against configuration, and returns the claims map.
//
// Arguments:
//   - ctx: Request cancellation context.
//   - params: VerifyParams containing the token string and optional validation overrides.
//
// Returns:
//   - *VerifyResult: Contains valid status, subject, claims, and parsed timestamps.
//   - error: ErrInvalidToken, ErrMissingKid, ErrKeyNotFound, ErrInvalidSignature, or ErrTokenExpired.
//
// Example:
//
//	res, err := jwtPlugin.Verify(ctx, jwt.VerifyParams{
//		Token: "eyJhbGciOiJFZERTQSI...",
//	})
//	if err != nil {
//		log.Fatalf("Token validation failed: %v", err)
//	}
//	fmt.Println("Verified subject:", res.Subject)
//	fmt.Println("Role claim:", res.Claims["role"])
func (p *Plugin) Verify(ctx context.Context, params VerifyParams) (*VerifyResult, error) {
	tokenStr := strings.TrimSpace(params.Token)
	if strings.HasPrefix(strings.ToLower(tokenStr), BearerSchemePrefix) {
		tokenStr = strings.TrimSpace(tokenStr[len(BearerSchemePrefix):])
	}
	if tokenStr == "" {
		return nil, ErrInvalidToken
	}

	p.publishEvent(EventJWTVerifyBefore, ctx, &JWTVerifyBeforeEventPayload{
		Token:  tokenStr,
		Params: &params,
	})

	header, err := ExtractUnverifiedHeader(tokenStr)
	if err != nil {
		p.publishVerifyAfter(ctx, tokenStr, false, nil, "", err)
		return nil, err
	}

	if header.Kid == "" {
		p.publishVerifyAfter(ctx, tokenStr, false, nil, "", ErrMissingKid)
		return nil, ErrMissingKid
	}

	pubKey, alg, err := p.resolvePublicKey(ctx, header.Kid)
	if err != nil {
		p.publishVerifyAfter(ctx, tokenStr, false, nil, header.Kid, err)
		return nil, err
	}

	if header.Alg != string(alg) {
		p.publishVerifyAfter(ctx, tokenStr, false, nil, header.Kid, ErrInvalidSignature)
		return nil, ErrInvalidSignature
	}

	_, claims, err := ParseAndVerifySignature(tokenStr, pubKey, alg)
	if err != nil {
		p.publishVerifyAfter(ctx, tokenStr, false, nil, header.Kid, err)
		return nil, err
	}

	now := time.Now()
	leeway := p.config.ClockSkewLeeway
	if params.Leeway > 0 {
		leeway = params.Leeway
	}

	// Validate exp
	var expiresAt *time.Time
	if expVal, ok := claims["exp"]; ok {
		expUnix, err := extractUnixTime(expVal)
		if err != nil {
			p.publishVerifyAfter(ctx, tokenStr, false, nil, header.Kid, ErrInvalidToken)
			return nil, ErrInvalidToken
		}
		t := time.Unix(expUnix, 0)
		expiresAt = &t
		if now.Add(-leeway).After(t) {
			p.publishVerifyAfter(ctx, tokenStr, false, claims, header.Kid, ErrTokenExpired)
			return nil, ErrTokenExpired
		}
	}

	// Validate nbf
	var notBefore *time.Time
	if nbfVal, ok := claims["nbf"]; ok {
		nbfUnix, err := extractUnixTime(nbfVal)
		if err != nil {
			p.publishVerifyAfter(ctx, tokenStr, false, nil, header.Kid, ErrInvalidToken)
			return nil, ErrInvalidToken
		}
		t := time.Unix(nbfUnix, 0)
		notBefore = &t
		if now.Add(leeway).Before(t) {
			p.publishVerifyAfter(ctx, tokenStr, false, claims, header.Kid, ErrTokenNotValidYet)
			return nil, ErrTokenNotValidYet
		}
	}

	// Validate iat
	var issuedAt *time.Time
	if iatVal, ok := claims["iat"]; ok {
		if iatUnix, err := extractUnixTime(iatVal); err == nil {
			t := time.Unix(iatUnix, 0)
			issuedAt = &t
		}
	}

	// Validate iss
	expectedIssuer := p.config.Issuer
	if params.Issuer != "" {
		expectedIssuer = params.Issuer
	}
	if expectedIssuer != "" {
		if tokenIss, ok := claims["iss"].(string); !ok || tokenIss != expectedIssuer {
			p.publishVerifyAfter(ctx, tokenStr, false, claims, header.Kid, ErrInvalidToken)
			return nil, ErrInvalidToken
		}
	}

	// Validate aud
	expectedAudience := p.config.Audience
	if len(params.Audience) > 0 {
		expectedAudience = params.Audience
	}
	if len(expectedAudience) > 0 {
		if !validateAudience(claims["aud"], expectedAudience) {
			p.publishVerifyAfter(ctx, tokenStr, false, claims, header.Kid, ErrInvalidToken)
			return nil, ErrInvalidToken
		}
	}

	var subject string
	if subVal, ok := claims["sub"].(string); ok {
		subject = subVal
	}

	if p.ctx != nil {
		p.ctx.Set(JWKCacheKey(header.Kid), tokenStr)
	}

	p.publishVerifyAfter(ctx, tokenStr, true, claims, header.Kid, nil)

	return &VerifyResult{
		Valid:     true,
		Subject:   subject,
		Claims:    claims,
		KeyID:     header.Kid,
		Algorithm: alg,
		ExpiresAt: expiresAt,
		IssuedAt:  issuedAt,
		NotBefore: notBefore,
	}, nil
}

// GetToken generates a signed JWT representing the provided session and user entity.
//
// Brief Explanation:
//
//	Validates session parameters, resolves the token subject via GetSubject or session.UserID,
//	computes custom claims via DefinePayload, delegates to Sign, and emits EventJWTIssued.
//
// Arguments:
//   - ctx: Request cancellation context.
//   - params: GetTokenParams containing the active session, user, and optional expiry override.
//
// Returns:
//   - *GetTokenResult: Issued JWT string, key identifier, algorithm, and formatted response headers.
//   - error: ErrSessionNotFound, ErrSessionExpired, or signing error.
//
// Example:
//
//	res, err := jwtPlugin.GetToken(ctx, jwt.GetTokenParams{
//		Session: activeSession,
//		User:    activeUser,
//	})
//	if err != nil {
//		log.Fatalf("Failed to generate session JWT: %v", err)
//	}
//	w.Header().Set(res.AuthJWTHeader, res.Token)
func (p *Plugin) GetToken(ctx context.Context, params GetTokenParams) (*GetTokenResult, error) {
	if params.Session == nil {
		return nil, ErrSessionNotFound
	}
	if !params.Session.ExpiresAt.IsZero() && time.Now().After(params.Session.ExpiresAt) {
		return nil, ErrSessionExpired
	}

	subject := params.Session.UserID
	if p.config.GetSubject != nil {
		customSub, err := p.config.GetSubject(params.Session, params.User)
		if err != nil {
			return nil, fmt.Errorf("jwt: custom GetSubject failed: %w", err)
		}
		if customSub != "" {
			subject = customSub
		}
	}

	payload := make(map[string]any)
	payload["session_id"] = params.Session.ID
	payload["user_id"] = params.Session.UserID

	if params.User != nil {
		if params.User.Email != "" {
			payload["email"] = params.User.Email
		}
		if params.User.Name != "" {
			payload["name"] = params.User.Name
		}
	}

	if p.config.DefinePayload != nil {
		customClaims, err := p.config.DefinePayload(params.Session, params.User)
		if err != nil {
			return nil, fmt.Errorf("jwt: custom DefinePayload failed: %w", err)
		}
		for k, v := range customClaims {
			payload[k] = v
		}
	}

	signParams := SignParams{
		Subject:   subject,
		Payload:   payload,
		ExpiresIn: params.ExpiresIn,
	}

	signRes, err := p.Sign(ctx, signParams)
	if err != nil {
		return nil, err
	}

	var userID string
	if params.User != nil {
		userID = params.User.ID
	} else {
		userID = params.Session.UserID
	}

	p.publishEvent(EventJWTIssued, ctx, &JWTIssuedEventPayload{
		Token:     signRes.Token,
		KeyID:     signRes.KeyID,
		Subject:   subject,
		SessionID: params.Session.ID,
		UserID:    userID,
	})

	return &GetTokenResult{
		Token:         signRes.Token,
		KeyID:         signRes.KeyID,
		Algorithm:     signRes.Algorithm,
		ExpiresAt:     signRes.ExpiresAt,
		HeaderValue:   signRes.HeaderValue,
		AuthJWTHeader: signRes.AuthJWTHeader,
	}, nil
}

// RotateKeys forces the generation of a fresh active key pair, storing it in the repository.
//
// Brief Explanation:
//
//	Generates a new key pair with the specified or configured algorithm, encrypts the private key
//	(if encryption is enabled), persists it to the repository, updates internal active references,
//	and emits EventJWTRotateAfter.
//
// Arguments:
//   - ctx: Request cancellation context.
//   - params: RotateKeysParams containing optional algorithm or RSA bit size overrides.
//
// Returns:
//   - *RotateKeysResult: Details of the newly created and active key pair.
//   - error: Key generation, encryption, or database write error.
//
// Example:
//
//	res, err := jwtPlugin.RotateKeys(ctx, jwt.RotateKeysParams{})
//	if err != nil {
//		log.Fatalf("Failed to rotate keys: %v", err)
//	}
//	fmt.Println("New active Key ID:", res.NewKey.ID)
func (p *Plugin) RotateKeys(ctx context.Context, params RotateKeysParams) (*RotateKeysResult, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	var oldKeyID string
	if p.activeKey != nil {
		oldKeyID = p.activeKey.ID
	}

	p.publishEvent(EventJWTRotateBefore, ctx, &JWTRotateBeforeEventPayload{
		CurrentKeyID: oldKeyID,
		Params:       &params,
	})

	alg := p.config.Algorithm
	if params.Algorithm != "" {
		alg = params.Algorithm
	}

	rsaBits := p.config.RSABits
	if params.RSABits >= 2048 {
		rsaBits = params.RSABits
	}

	record, privKey, err := GenerateKeyPair(alg, rsaBits)
	if err != nil {
		return nil, fmt.Errorf("jwt: failed to generate key pair: %w", err)
	}

	if !p.config.DisablePrivateKeyEncryption {
		secret := p.config.Secret
		if secret == "" {
			return nil, ErrSecretRequired
		}
		rawPrivBytes, err := base64.RawURLEncoding.DecodeString(record.PrivateKey)
		if err != nil {
			return nil, err
		}
		encryptedPriv, err := EncryptPrivateKey(rawPrivBytes, secret)
		if err != nil {
			return nil, fmt.Errorf("jwt: failed to encrypt private key: %w", err)
		}
		record.PrivateKey = encryptedPriv
	}

	if p.repo != nil {
		if err := p.repo.CreateKey(ctx, record); err != nil {
			return nil, fmt.Errorf("jwt: failed to save rotated key: %w", err)
		}
	}

	p.activeKey = record
	p.activePriv = privKey

	var jwk JWK
	_ = json.Unmarshal([]byte(record.PublicKey), &jwk)

	p.publishEvent(EventJWTRotateAfter, ctx, &JWTRotateAfterEventPayload{
		NewKeyID:  record.ID,
		Algorithm: record.Algorithm,
		CreatedAt: record.CreatedAt,
	})

	return &RotateKeysResult{
		NewKey:   record,
		JWK:      &jwk,
		OldKeyID: oldKeyID,
	}, nil
}

// Internal Helper Methods

func (p *Plugin) ensureActiveKey(ctx context.Context) (*JWKRecord, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.activeKey != nil && p.activePriv != nil {
		return p.activeKey, nil
	}

	if p.repo != nil {
		latest, err := p.repo.GetLatestKey(ctx)
		if err == nil && latest != nil {
			privKey, err := p.decryptAndParsePrivateKey(latest)
			if err == nil {
				p.activeKey = latest
				p.activePriv = privKey
				return latest, nil
			}
		}
	}

	// Generate new initial key
	record, privKey, err := GenerateKeyPair(p.config.Algorithm, p.config.RSABits)
	if err != nil {
		return nil, fmt.Errorf("jwt: failed to bootstrap initial key pair: %w", err)
	}

	if !p.config.DisablePrivateKeyEncryption {
		secret := p.config.Secret
		if secret == "" {
			return nil, ErrSecretRequired
		}
		rawPrivBytes, err := base64.RawURLEncoding.DecodeString(record.PrivateKey)
		if err != nil {
			return nil, err
		}
		encryptedPriv, err := EncryptPrivateKey(rawPrivBytes, secret)
		if err != nil {
			return nil, fmt.Errorf("jwt: failed to encrypt bootstrap private key: %w", err)
		}
		record.PrivateKey = encryptedPriv
	}

	if p.repo != nil {
		if err := p.repo.CreateKey(ctx, record); err != nil {
			return nil, fmt.Errorf("jwt: failed to persist bootstrap key: %w", err)
		}
	}

	p.activeKey = record
	p.activePriv = privKey
	return record, nil
}

func (p *Plugin) resolveSigningKey(ctx context.Context, keyID string) (*JWKRecord, crypto.PrivateKey, error) {
	p.mu.RLock()
	if keyID == "" || (p.activeKey != nil && p.activeKey.ID == keyID) {
		if p.activeKey != nil && p.activePriv != nil {
			rec, priv := p.activeKey, p.activePriv
			p.mu.RUnlock()
			return rec, priv, nil
		}
	}
	p.mu.RUnlock()

	if keyID == "" {
		rec, err := p.ensureActiveKey(ctx)
		if err != nil {
			return nil, nil, err
		}
		p.mu.RLock()
		priv := p.activePriv
		p.mu.RUnlock()
		return rec, priv, nil
	}

	if p.repo == nil {
		return nil, nil, ErrKeyNotFound
	}

	rec, err := p.repo.GetKeyByID(ctx, keyID)
	if err != nil {
		return nil, nil, ErrKeyNotFound
	}

	privKey, err := p.decryptAndParsePrivateKey(rec)
	if err != nil {
		return nil, nil, err
	}

	return rec, privKey, nil
}

func (p *Plugin) resolvePublicKey(ctx context.Context, keyID string) (crypto.PublicKey, Algorithm, error) {
	p.mu.RLock()
	if entry, ok := p.cachedKeys[keyID]; ok {
		pub, alg := entry.pubKey, entry.record.Algorithm
		p.mu.RUnlock()
		return pub, alg, nil
	}
	if p.activeKey != nil && p.activeKey.ID == keyID {
		var jwk JWK
		if err := json.Unmarshal([]byte(p.activeKey.PublicKey), &jwk); err == nil {
			if pubKey, err := ParsePublicKeyFromJWK(&jwk); err == nil {
				alg := p.activeKey.Algorithm
				p.mu.RUnlock()
				return pubKey, alg, nil
			}
		}
	}
	p.mu.RUnlock()

	if p.repo == nil {
		return nil, "", ErrKeyNotFound
	}

	rec, err := p.repo.GetKeyByID(ctx, keyID)
	if err != nil {
		return nil, "", ErrKeyNotFound
	}

	var jwk JWK
	if err := json.Unmarshal([]byte(rec.PublicKey), &jwk); err != nil {
		return nil, "", ErrInvalidToken
	}

	pubKey, err := ParsePublicKeyFromJWK(&jwk)
	if err != nil {
		return nil, "", err
	}

	p.mu.Lock()
	p.cachedKeys[keyID] = &cachedKey{
		record: rec,
		pubKey: pubKey,
	}
	p.mu.Unlock()

	return pubKey, rec.Algorithm, nil
}

func (p *Plugin) decryptAndParsePrivateKey(record *JWKRecord) (crypto.PrivateKey, error) {
	if p.config.DisablePrivateKeyEncryption {
		derBytes, err := base64.RawURLEncoding.DecodeString(record.PrivateKey)
		if err != nil {
			return nil, err
		}
		return ParsePrivateKeyFromBytes(derBytes)
	}

	secret := p.config.Secret
	if secret == "" {
		return nil, ErrSecretRequired
	}

	decryptedBytes, err := DecryptPrivateKey(record.PrivateKey, secret)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	return ParsePrivateKeyFromBytes(decryptedBytes)
}

func (p *Plugin) publishEvent(eventName string, ctx context.Context, payload any) {
	if p.ctx != nil && p.ctx.Events() != nil {
		p.ctx.Events().Publish(eventName, ctx, payload)
	}
}

func (p *Plugin) publishVerifyAfter(ctx context.Context, token string, valid bool, claims map[string]any, kid string, err error) {
	p.publishEvent(EventJWTVerifyAfter, ctx, &JWTVerifyAfterEventPayload{
		Token:  token,
		Valid:  valid,
		Claims: claims,
		KeyID:  kid,
		Error:  err,
	})
}

func extractUnixTime(val any) (int64, error) {
	switch v := val.(type) {
	case float64:
		return int64(v), nil
	case int64:
		return v, nil
	case int:
		return int64(v), nil
	case json.Number:
		return v.Int64()
	default:
		return 0, errors.New("invalid time format")
	}
}

func validateAudience(tokenAud any, expected []string) bool {
	if tokenAud == nil {
		return false
	}
	switch v := tokenAud.(type) {
	case string:
		for _, exp := range expected {
			if v == exp {
				return true
			}
		}
	case []any:
		for _, item := range v {
			if strItem, ok := item.(string); ok {
				for _, exp := range expected {
					if strItem == exp {
						return true
					}
				}
			}
		}
	case []string:
		for _, item := range v {
			for _, exp := range expected {
				if item == exp {
					return true
				}
			}
		}
	}
	return false
}
