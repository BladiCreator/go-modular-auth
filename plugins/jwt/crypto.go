package jwt

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// JWTHeader represents the JWS header structure conforming to RFC 7515 / RFC 7519.
type JWTHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

// GenerateKeyPair generates a new cryptographic key pair for the specified algorithm,
// creating a JWKRecord and returning the private key.
func GenerateKeyPair(alg Algorithm, rsaBits int) (*JWKRecord, crypto.PrivateKey, error) {
	kid, err := generateRandomKID()
	if err != nil {
		return nil, nil, err
	}

	now := time.Now()

	switch alg {
	case AlgEdDSA:
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("jwt: failed to generate Ed25519 key: %w", err)
		}
		jwk := JWK{
			Kty: "OKP",
			Kid: kid,
			Use: "sig",
			Alg: string(AlgEdDSA),
			Crv: "Ed25519",
			X:   base64.RawURLEncoding.EncodeToString(pub),
		}
		pubJSON, err := json.Marshal(jwk)
		if err != nil {
			return nil, nil, err
		}
		privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return nil, nil, err
		}
		record := &JWKRecord{
			ID:         kid,
			PublicKey:  string(pubJSON),
			PrivateKey: base64.RawURLEncoding.EncodeToString(privBytes),
			Algorithm:  AlgEdDSA,
			Curve:      "Ed25519",
			CreatedAt:  now,
		}
		return record, priv, nil

	case AlgES256:
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("jwt: failed to generate ES256 key: %w", err)
		}
		jwk := exportECDSAJWK(priv.Public().(*ecdsa.PublicKey), kid, AlgES256, "P-256")
		pubJSON, err := json.Marshal(jwk)
		if err != nil {
			return nil, nil, err
		}
		privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return nil, nil, err
		}
		record := &JWKRecord{
			ID:         kid,
			PublicKey:  string(pubJSON),
			PrivateKey: base64.RawURLEncoding.EncodeToString(privBytes),
			Algorithm:  AlgES256,
			Curve:      "P-256",
			CreatedAt:  now,
		}
		return record, priv, nil

	case AlgES512:
		priv, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("jwt: failed to generate ES512 key: %w", err)
		}
		jwk := exportECDSAJWK(priv.Public().(*ecdsa.PublicKey), kid, AlgES512, "P-521")
		pubJSON, err := json.Marshal(jwk)
		if err != nil {
			return nil, nil, err
		}
		privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return nil, nil, err
		}
		record := &JWKRecord{
			ID:         kid,
			PublicKey:  string(pubJSON),
			PrivateKey: base64.RawURLEncoding.EncodeToString(privBytes),
			Algorithm:  AlgES512,
			Curve:      "P-521",
			CreatedAt:  now,
		}
		return record, priv, nil

	case AlgRS256, AlgPS256:
		if rsaBits < 2048 {
			rsaBits = 2048
		}
		priv, err := rsa.GenerateKey(rand.Reader, rsaBits)
		if err != nil {
			return nil, nil, fmt.Errorf("jwt: failed to generate RSA key: %w", err)
		}
		jwk := exportRSAJWK(&priv.PublicKey, kid, alg)
		pubJSON, err := json.Marshal(jwk)
		if err != nil {
			return nil, nil, err
		}
		privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return nil, nil, err
		}
		record := &JWKRecord{
			ID:         kid,
			PublicKey:  string(pubJSON),
			PrivateKey: base64.RawURLEncoding.EncodeToString(privBytes),
			Algorithm:  alg,
			CreatedAt:  now,
		}
		return record, priv, nil

	default:
		return nil, nil, ErrUnsupportedAlgorithm
	}
}

// EncryptPrivateKey encrypts raw private key bytes using AES-256-GCM authenticated encryption.
func EncryptPrivateKey(rawKeyBytes []byte, secret string) (string, error) {
	if secret == "" {
		return "", ErrSecretRequired
	}

	keyHash := sha256.Sum256([]byte(secret))
	block, err := aes.NewCipher(keyHash[:])
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nil, nonce, rawKeyBytes, nil)
	payload := append(nonce, ciphertext...)
	return base64.RawURLEncoding.EncodeToString(payload), nil
}

// DecryptPrivateKey decrypts base64url-encoded AES-256-GCM ciphertext using the configured secret.
func DecryptPrivateKey(encryptedPayloadB64 string, secret string) ([]byte, error) {
	if secret == "" {
		return nil, ErrSecretRequired
	}

	data, err := base64.RawURLEncoding.DecodeString(encryptedPayloadB64)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	keyHash := sha256.Sum256([]byte(secret))
	block, err := aes.NewCipher(keyHash[:])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, ErrDecryptionFailed
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	return plaintext, nil
}

// ParsePrivateKeyFromBytes reconstructs a crypto.PrivateKey from PKCS#8 DER bytes.
func ParsePrivateKeyFromBytes(derBytes []byte) (crypto.PrivateKey, error) {
	key, err := x509.ParsePKCS8PrivateKey(derBytes)
	if err != nil {
		// Fallbacks for direct formats if PKCS#8 parsing fails
		if ecKey, ecErr := x509.ParseECPrivateKey(derBytes); ecErr == nil {
			return ecKey, nil
		}
		if rsaKey, rsaErr := x509.ParsePKCS1PrivateKey(derBytes); rsaErr == nil {
			return rsaKey, nil
		}
		return nil, fmt.Errorf("jwt: invalid private key format: %w", err)
	}
	return key, nil
}

// ParsePublicKeyFromJWK extracts a crypto.PublicKey from an RFC 7517 JWK.
func ParsePublicKeyFromJWK(jwk *JWK) (crypto.PublicKey, error) {
	switch jwk.Kty {
	case "OKP":
		if jwk.Crv != "Ed25519" {
			return nil, fmt.Errorf("jwt: unsupported OKP curve '%s'", jwk.Crv)
		}
		pubBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
		if err != nil {
			return nil, fmt.Errorf("jwt: invalid OKP x coordinate: %w", err)
		}
		if len(pubBytes) != ed25519.PublicKeySize {
			return nil, errors.New("jwt: invalid Ed25519 public key length")
		}
		return ed25519.PublicKey(pubBytes), nil

	case "EC":
		var (
			curve     elliptic.Curve
			ecdhCurve ecdh.Curve
			byteLen   int
		)
		switch jwk.Crv {
		case "P-256":
			curve = elliptic.P256()
			ecdhCurve = ecdh.P256()
			byteLen = 32
		case "P-521":
			curve = elliptic.P521()
			ecdhCurve = ecdh.P521()
			byteLen = 66
		default:
			return nil, fmt.Errorf("jwt: unsupported EC curve '%s'", jwk.Crv)
		}

		xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
		if err != nil {
			return nil, fmt.Errorf("jwt: invalid EC x coordinate: %w", err)
		}
		yBytes, err := base64.RawURLEncoding.DecodeString(jwk.Y)
		if err != nil {
			return nil, fmt.Errorf("jwt: invalid EC y coordinate: %w", err)
		}

		xPadded := make([]byte, byteLen)
		copy(xPadded[byteLen-len(xBytes):], xBytes)

		yPadded := make([]byte, byteLen)
		copy(yPadded[byteLen-len(yBytes):], yBytes)

		uncompressedPoint := append([]byte{0x04}, append(xPadded, yPadded...)...)
		if _, err := ecdhCurve.NewPublicKey(uncompressedPoint); err != nil {
			return nil, fmt.Errorf("jwt: invalid EC public key point: %w", err)
		}

		return &ecdsa.PublicKey{
			Curve: curve,
			X:     new(big.Int).SetBytes(xBytes),
			Y:     new(big.Int).SetBytes(yBytes),
		}, nil

	case "RSA":
		nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
		if err != nil {
			return nil, fmt.Errorf("jwt: invalid RSA n modulus: %w", err)
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
		if err != nil {
			return nil, fmt.Errorf("jwt: invalid RSA e exponent: %w", err)
		}

		n := new(big.Int).SetBytes(nBytes)
		var e int
		for _, b := range eBytes {
			e = (e << 8) | int(b)
		}

		return &rsa.PublicKey{
			N: n,
			E: e,
		}, nil

	default:
		return nil, fmt.Errorf("jwt: unsupported key type '%s'", jwk.Kty)
	}
}

// SignJWT creates and cryptographically signs a compact serialized JWT (RFC 7519).
func SignJWT(header JWTHeader, payload map[string]any, privKey crypto.PrivateKey, alg Algorithm) (string, error) {
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)
	signingInput := headerB64 + "." + payloadB64

	sigBytes, err := signMessage([]byte(signingInput), privKey, alg)
	if err != nil {
		return "", err
	}

	sigB64 := base64.RawURLEncoding.EncodeToString(sigBytes)
	return signingInput + "." + sigB64, nil
}

// ParseAndVerifySignature parses the token, checks format, and verifies signature with the public key.
func ParseAndVerifySignature(tokenStr string, pubKey crypto.PublicKey, expectedAlg Algorithm) (*JWTHeader, map[string]any, error) {
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return nil, nil, ErrInvalidToken
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, nil, ErrInvalidToken
	}

	var header JWTHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, nil, ErrInvalidToken
	}

	if header.Alg != string(expectedAlg) {
		return nil, nil, ErrInvalidSignature
	}

	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, nil, ErrInvalidSignature
	}

	signingInput := parts[0] + "." + parts[1]
	if err := verifySignature([]byte(signingInput), sigBytes, pubKey, expectedAlg); err != nil {
		return nil, nil, err
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, ErrInvalidToken
	}

	var payload map[string]any
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, nil, ErrInvalidToken
	}

	return &header, payload, nil
}

// ExtractUnverifiedHeader extracts the JWT header without signature verification to inspect kid/alg.
func ExtractUnverifiedHeader(tokenStr string) (*JWTHeader, error) {
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 || parts[0] == "" {
		return nil, ErrInvalidToken
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, ErrInvalidToken
	}

	var header JWTHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, ErrInvalidToken
	}

	return &header, nil
}

// Internal Helper Functions

func signMessage(msg []byte, privKey crypto.PrivateKey, alg Algorithm) ([]byte, error) {
	switch alg {
	case AlgEdDSA:
		edKey, ok := privKey.(ed25519.PrivateKey)
		if !ok {
			return nil, errors.New("jwt: invalid key type for EdDSA")
		}
		return ed25519.Sign(edKey, msg), nil

	case AlgES256:
		ecKey, ok := privKey.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("jwt: invalid key type for ES256")
		}
		hash := sha256.Sum256(msg)
		r, s, err := ecdsa.Sign(rand.Reader, ecKey, hash[:])
		if err != nil {
			return nil, err
		}
		return encodeECDSASignature(r, s, 32), nil

	case AlgES512:
		ecKey, ok := privKey.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("jwt: invalid key type for ES512")
		}
		hash := sha512.Sum512(msg)
		r, s, err := ecdsa.Sign(rand.Reader, ecKey, hash[:])
		if err != nil {
			return nil, err
		}
		return encodeECDSASignature(r, s, 66), nil

	case AlgRS256:
		rsaKey, ok := privKey.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("jwt: invalid key type for RS256")
		}
		hash := sha256.Sum256(msg)
		return rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, hash[:])

	case AlgPS256:
		rsaKey, ok := privKey.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("jwt: invalid key type for PS256")
		}
		hash := sha256.Sum256(msg)
		return rsa.SignPSS(rand.Reader, rsaKey, crypto.SHA256, hash[:], &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
		})

	default:
		return nil, ErrUnsupportedAlgorithm
	}
}

func verifySignature(msg, sig []byte, pubKey crypto.PublicKey, alg Algorithm) error {
	switch alg {
	case AlgEdDSA:
		edPub, ok := pubKey.(ed25519.PublicKey)
		if !ok {
			return errors.New("jwt: invalid public key for EdDSA")
		}
		if !ed25519.Verify(edPub, msg, sig) {
			return ErrInvalidSignature
		}
		return nil

	case AlgES256:
		ecPub, ok := pubKey.(*ecdsa.PublicKey)
		if !ok {
			return errors.New("jwt: invalid public key for ES256")
		}
		r, s, err := decodeECDSASignature(sig, 32)
		if err != nil {
			return ErrInvalidSignature
		}
		hash := sha256.Sum256(msg)
		if !ecdsa.Verify(ecPub, hash[:], r, s) {
			return ErrInvalidSignature
		}
		return nil

	case AlgES512:
		ecPub, ok := pubKey.(*ecdsa.PublicKey)
		if !ok {
			return errors.New("jwt: invalid public key for ES512")
		}
		r, s, err := decodeECDSASignature(sig, 66)
		if err != nil {
			return ErrInvalidSignature
		}
		hash := sha512.Sum512(msg)
		if !ecdsa.Verify(ecPub, hash[:], r, s) {
			return ErrInvalidSignature
		}
		return nil

	case AlgRS256:
		rsaPub, ok := pubKey.(*rsa.PublicKey)
		if !ok {
			return errors.New("jwt: invalid public key for RS256")
		}
		hash := sha256.Sum256(msg)
		if err := rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, hash[:], sig); err != nil {
			return ErrInvalidSignature
		}
		return nil

	case AlgPS256:
		rsaPub, ok := pubKey.(*rsa.PublicKey)
		if !ok {
			return errors.New("jwt: invalid public key for PS256")
		}
		hash := sha256.Sum256(msg)
		if err := rsa.VerifyPSS(rsaPub, crypto.SHA256, hash[:], sig, &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
		}); err != nil {
			return ErrInvalidSignature
		}
		return nil

	default:
		return ErrUnsupportedAlgorithm
	}
}

func encodeECDSASignature(r, s *big.Int, byteLen int) []byte {
	rBytes := r.Bytes()
	sBytes := s.Bytes()

	sig := make([]byte, byteLen*2)
	copy(sig[byteLen-len(rBytes):byteLen], rBytes)
	copy(sig[byteLen*2-len(sBytes):], sBytes)
	return sig
}

func decodeECDSASignature(sig []byte, byteLen int) (*big.Int, *big.Int, error) {
	if len(sig) != byteLen*2 {
		return nil, nil, errors.New("jwt: invalid ECDSA signature length")
	}
	r := new(big.Int).SetBytes(sig[:byteLen])
	s := new(big.Int).SetBytes(sig[byteLen:])
	return r, s, nil
}

func exportECDSAJWK(pub *ecdsa.PublicKey, kid string, alg Algorithm, crv string) JWK {
	byteLen := (pub.Curve.Params().BitSize + 7) / 8
	xBytes := pub.X.Bytes()
	yBytes := pub.Y.Bytes()

	xPadded := make([]byte, byteLen)
	copy(xPadded[byteLen-len(xBytes):], xBytes)

	yPadded := make([]byte, byteLen)
	copy(yPadded[byteLen-len(yBytes):], yBytes)

	return JWK{
		Kty: "EC",
		Kid: kid,
		Use: "sig",
		Alg: string(alg),
		Crv: crv,
		X:   base64.RawURLEncoding.EncodeToString(xPadded),
		Y:   base64.RawURLEncoding.EncodeToString(yPadded),
	}
}

func exportRSAJWK(pub *rsa.PublicKey, kid string, alg Algorithm) JWK {
	eBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(eBytes, uint32(pub.E))
	// Trim leading zeros
	firstNonZero := 0
	for firstNonZero < len(eBytes) && eBytes[firstNonZero] == 0 {
		firstNonZero++
	}

	return JWK{
		Kty: "RSA",
		Kid: kid,
		Use: "sig",
		Alg: string(alg),
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(eBytes[firstNonZero:]),
	}
}

func generateRandomKID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
