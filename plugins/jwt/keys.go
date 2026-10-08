package jwt

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"
	"sync"
	"time"
)

// Key represents a cryptographic key for JWT signing or verification.
type Key struct {
	// ID uniquely identifies the key (kid).
	ID string

	// Algorithm declares the single cryptographic algorithm permitted for this key (alg).
	Algorithm Algorithm

	// Use defines the intended use of the key (typically "sig").
	Use string

	// PrivateKey contains the private key material (*rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey, or []byte).
	// May be nil for verification-only keys.
	PrivateKey any

	// PublicKey contains the public key material (*rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey, or []byte for HMAC).
	PublicKey any

	// CreatedAt records when the key was created or added.
	CreatedAt time.Time
}

// CanSign reports whether the key possesses private key material to sign tokens.
func (k Key) CanSign() bool {
	return k.PrivateKey != nil
}

// NewHMACKey constructs a symmetric key for HMAC algorithms.
func NewHMACKey(id string, alg Algorithm, secret []byte) (Key, error) {
	if id == "" {
		return Key{}, fmt.Errorf("%w: key ID (kid) cannot be empty", ErrInvalidKey)
	}
	if !alg.IsSymmetric() {
		return Key{}, fmt.Errorf("%w: algorithm %s is not an HMAC algorithm", ErrInvalidKey, alg)
	}
	if len(secret) < 32 {
		return Key{}, fmt.Errorf("%w: HMAC secret must be at least 32 bytes for secure signing", ErrInvalidKey)
	}
	secretCopy := make([]byte, len(secret))
	copy(secretCopy, secret)

	return Key{
		ID:         id,
		Algorithm:  alg,
		Use:        "sig",
		PrivateKey: secretCopy,
		PublicKey:  secretCopy,
		CreatedAt:  time.Now(),
	}, nil
}

// NewRSAKey constructs an asymmetric RSA signing key.
func NewRSAKey(id string, alg Algorithm, privKey *rsa.PrivateKey) (Key, error) {
	if id == "" {
		return Key{}, fmt.Errorf("%w: key ID (kid) cannot be empty", ErrInvalidKey)
	}
	if privKey == nil {
		return Key{}, fmt.Errorf("%w: private key cannot be nil", ErrInvalidKey)
	}
	switch alg {
	case RS256, RS384, RS512, PS256, PS384, PS512:
	default:
		return Key{}, fmt.Errorf("%w: algorithm %s is not an RSA algorithm", ErrInvalidKey, alg)
	}
	if privKey.N.BitLen() < 2048 {
		return Key{}, fmt.Errorf("%w: RSA key must be at least 2048 bits", ErrInvalidKey)
	}

	return Key{
		ID:         id,
		Algorithm:  alg,
		Use:        "sig",
		PrivateKey: privKey,
		PublicKey:  &privKey.PublicKey,
		CreatedAt:  time.Now(),
	}, nil
}

// NewRSAPublicKey constructs an asymmetric RSA verification-only key.
func NewRSAPublicKey(id string, alg Algorithm, pubKey *rsa.PublicKey) (Key, error) {
	if id == "" {
		return Key{}, fmt.Errorf("%w: key ID (kid) cannot be empty", ErrInvalidKey)
	}
	if pubKey == nil {
		return Key{}, fmt.Errorf("%w: public key cannot be nil", ErrInvalidKey)
	}
	switch alg {
	case RS256, RS384, RS512, PS256, PS384, PS512:
	default:
		return Key{}, fmt.Errorf("%w: algorithm %s is not an RSA algorithm", ErrInvalidKey, alg)
	}
	if pubKey.N.BitLen() < 2048 {
		return Key{}, fmt.Errorf("%w: RSA key must be at least 2048 bits", ErrInvalidKey)
	}

	return Key{
		ID:        id,
		Algorithm: alg,
		Use:       "sig",
		PublicKey: pubKey,
		CreatedAt: time.Now(),
	}, nil
}

// NewECDSAKey constructs an asymmetric ECDSA signing key.
func NewECDSAKey(id string, alg Algorithm, privKey *ecdsa.PrivateKey) (Key, error) {
	if id == "" {
		return Key{}, fmt.Errorf("%w: key ID (kid) cannot be empty", ErrInvalidKey)
	}
	if privKey == nil {
		return Key{}, fmt.Errorf("%w: private key cannot be nil", ErrInvalidKey)
	}
	if err := validateECDSACurve(alg, privKey.Curve); err != nil {
		return Key{}, err
	}

	return Key{
		ID:         id,
		Algorithm:  alg,
		Use:        "sig",
		PrivateKey: privKey,
		PublicKey:  &privKey.PublicKey,
		CreatedAt:  time.Now(),
	}, nil
}

// NewECDSAPublicKey constructs an asymmetric ECDSA verification-only key.
func NewECDSAPublicKey(id string, alg Algorithm, pubKey *ecdsa.PublicKey) (Key, error) {
	if id == "" {
		return Key{}, fmt.Errorf("%w: key ID (kid) cannot be empty", ErrInvalidKey)
	}
	if pubKey == nil {
		return Key{}, fmt.Errorf("%w: public key cannot be nil", ErrInvalidKey)
	}
	if err := validateECDSACurve(alg, pubKey.Curve); err != nil {
		return Key{}, err
	}

	return Key{
		ID:        id,
		Algorithm: alg,
		Use:       "sig",
		PublicKey: pubKey,
		CreatedAt: time.Now(),
	}, nil
}

func validateECDSACurve(alg Algorithm, curve elliptic.Curve) error {
	switch alg {
	case ES256:
		if curve != elliptic.P256() {
			return fmt.Errorf("%w: ES256 requires P-256 curve", ErrInvalidKey)
		}
	case ES384:
		if curve != elliptic.P384() {
			return fmt.Errorf("%w: ES384 requires P-384 curve", ErrInvalidKey)
		}
	case ES512:
		if curve != elliptic.P521() {
			return fmt.Errorf("%w: ES512 requires P-521 curve", ErrInvalidKey)
		}
	default:
		return fmt.Errorf("%w: algorithm %s is not an ECDSA algorithm", ErrInvalidKey, alg)
	}
	return nil
}

// NewEd25519Key constructs an Ed25519 signing key.
func NewEd25519Key(id string, privKey ed25519.PrivateKey) (Key, error) {
	if id == "" {
		return Key{}, fmt.Errorf("%w: key ID (kid) cannot be empty", ErrInvalidKey)
	}
	if len(privKey) != ed25519.PrivateKeySize {
		return Key{}, fmt.Errorf("%w: invalid Ed25519 private key length", ErrInvalidKey)
	}

	return Key{
		ID:         id,
		Algorithm:  EdDSA,
		Use:        "sig",
		PrivateKey: privKey,
		PublicKey:  privKey.Public().(ed25519.PublicKey),
		CreatedAt:  time.Now(),
	}, nil
}

// NewEd25519PublicKey constructs an Ed25519 verification-only key.
func NewEd25519PublicKey(id string, pubKey ed25519.PublicKey) (Key, error) {
	if id == "" {
		return Key{}, fmt.Errorf("%w: key ID (kid) cannot be empty", ErrInvalidKey)
	}
	if len(pubKey) != ed25519.PublicKeySize {
		return Key{}, fmt.Errorf("%w: invalid Ed25519 public key length", ErrInvalidKey)
	}

	return Key{
		ID:        id,
		Algorithm: EdDSA,
		Use:       "sig",
		PublicKey: pubKey,
		CreatedAt: time.Now(),
	}, nil
}

// KeyManager manages multiple keys, rotation, and active signing key designation.
type KeyManager interface {
	// AddKey registers a key.
	AddKey(key Key) error

	// SetActiveSigningKey designates the default key ID used for signing.
	SetActiveSigningKey(keyID string) error

	// RotateSigningKey registers a new signing key and immediately designates it as active.
	RotateSigningKey(newKey Key) error

	// GetKey retrieves a key by its ID.
	GetKey(keyID string) (Key, error)

	// GetActiveSigningKey returns the active signing key.
	GetActiveSigningKey() (Key, error)

	// GetVerificationKey retrieves the matching key and enforces algorithm compatibility.
	GetVerificationKey(kid string, requestedAlg Algorithm) (Key, error)

	// ListKeys returns all registered keys.
	ListKeys() []Key

	// RemoveKey removes a key by ID.
	RemoveKey(keyID string) error
}

type memoryKeyManager struct {
	mu           sync.RWMutex
	keys         map[string]Key
	activeKeyID  string
	singleKey    *Key
}

// NewKeyManager initializes an empty, thread-safe KeyManager.
func NewKeyManager() KeyManager {
	return &memoryKeyManager{
		keys: make(map[string]Key),
	}
}

func (m *memoryKeyManager) AddKey(key Key) error {
	if key.ID == "" {
		return fmt.Errorf("%w: key ID cannot be empty", ErrInvalidKey)
	}
	if !key.Algorithm.IsValid() {
		return fmt.Errorf("%w: unsupported algorithm %s", ErrInvalidKey, key.Algorithm)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.keys[key.ID] = key
	if len(m.keys) == 1 {
		m.activeKeyID = key.ID
		kCopy := key
		m.singleKey = &kCopy
	} else {
		m.singleKey = nil
	}
	return nil
}

func (m *memoryKeyManager) SetActiveSigningKey(keyID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	k, exists := m.keys[keyID]
	if !exists {
		return fmt.Errorf("%w: %s", ErrKeyNotFound, keyID)
	}
	if !k.CanSign() {
		return fmt.Errorf("%w: key %s has no private key material", ErrInvalidKey, keyID)
	}
	m.activeKeyID = keyID
	return nil
}

func (m *memoryKeyManager) RotateSigningKey(newKey Key) error {
	if !newKey.CanSign() {
		return fmt.Errorf("%w: cannot rotate to key without private key material", ErrInvalidKey)
	}
	if err := m.AddKey(newKey); err != nil {
		return err
	}
	return m.SetActiveSigningKey(newKey.ID)
}

func (m *memoryKeyManager) GetKey(keyID string) (Key, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	k, exists := m.keys[keyID]
	if !exists {
		return Key{}, fmt.Errorf("%w: %s", ErrKeyNotFound, keyID)
	}
	return k, nil
}

func (m *memoryKeyManager) GetActiveSigningKey() (Key, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.activeKeyID == "" {
		return Key{}, ErrNoActiveSigningKey
	}
	k, exists := m.keys[m.activeKeyID]
	if !exists || !k.CanSign() {
		return Key{}, ErrNoActiveSigningKey
	}
	return k, nil
}

func (m *memoryKeyManager) GetVerificationKey(kid string, requestedAlg Algorithm) (Key, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var targetKey Key
	if kid != "" {
		k, exists := m.keys[kid]
		if !exists {
			return Key{}, fmt.Errorf("%w: %s", ErrKeyNotFound, kid)
		}
		targetKey = k
	} else {
		// When kid is not specified in the token header:
		if m.singleKey != nil {
			targetKey = *m.singleKey
		} else if len(m.keys) == 1 {
			for _, k := range m.keys {
				targetKey = k
				break
			}
		} else if len(m.keys) == 0 {
			return Key{}, ErrKeyNotFound
		} else {
			return Key{}, ErrKeyIDRequired
		}
	}

	// Strictly prevent algorithm confusion:
	// 1. The token header's declared alg MUST match the registered key's algorithm exactly.
	if targetKey.Algorithm != requestedAlg {
		return Key{}, fmt.Errorf("%w: token declared %s but key %s requires %s",
			ErrAlgorithmMismatch, requestedAlg, targetKey.ID, targetKey.Algorithm)
	}

	// 2. Reject symmetric HMAC algorithm if key is an asymmetric public key.
	if requestedAlg.IsSymmetric() {
		if _, ok := targetKey.PublicKey.([]byte); !ok {
			return Key{}, fmt.Errorf("%w: HMAC algorithm attempted with asymmetric key", ErrAlgorithmMismatch)
		}
	} else {
		// 3. Reject asymmetric algorithm if key is symmetric bytes.
		if _, ok := targetKey.PublicKey.([]byte); ok {
			return Key{}, fmt.Errorf("%w: asymmetric algorithm attempted with HMAC secret", ErrAlgorithmMismatch)
		}
	}

	return targetKey, nil
}

func (m *memoryKeyManager) ListKeys() []Key {
	m.mu.RLock()
	defer m.mu.RUnlock()

	res := make([]Key, 0, len(m.keys))
	for _, k := range m.keys {
		res = append(res, k)
	}
	return res
}

func (m *memoryKeyManager) RemoveKey(keyID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.keys[keyID]; !exists {
		return fmt.Errorf("%w: %s", ErrKeyNotFound, keyID)
	}
	delete(m.keys, keyID)
	if m.activeKeyID == keyID {
		m.activeKeyID = ""
	}
	if len(m.keys) == 1 {
		for _, k := range m.keys {
			kCopy := k
			m.singleKey = &kCopy
			break
		}
	} else {
		m.singleKey = nil
	}
	return nil
}
