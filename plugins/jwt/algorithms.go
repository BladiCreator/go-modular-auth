package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"errors"
	"fmt"
	"hash"
	"math/big"
)

// Algorithm identifies a registered JWA cryptographic signing algorithm.
type Algorithm string

const (
	// HMAC using SHA-256
	HS256 Algorithm = "HS256"
	// HMAC using SHA-384
	HS384 Algorithm = "HS384"
	// HMAC using SHA-512
	HS512 Algorithm = "HS512"

	// RSASSA-PKCS1-v1_5 using SHA-256
	RS256 Algorithm = "RS256"
	// RSASSA-PKCS1-v1_5 using SHA-384
	RS384 Algorithm = "RS384"
	// RSASSA-PKCS1-v1_5 using SHA-512
	RS512 Algorithm = "RS512"

	// RSASSA-PSS using SHA-256
	PS256 Algorithm = "PS256"
	// RSASSA-PSS using SHA-384
	PS384 Algorithm = "PS384"
	// RSASSA-PSS using SHA-512
	PS512 Algorithm = "PS512"

	// ECDSA using P-256 and SHA-256
	ES256 Algorithm = "ES256"
	// ECDSA using P-384 and SHA-384
	ES384 Algorithm = "ES384"
	// ECDSA using P-521 and SHA-512
	ES512 Algorithm = "ES512"

	// EdDSA using Ed25519
	EdDSA Algorithm = "EdDSA"
)

// IsSymmetric reports whether the algorithm is symmetric (HMAC).
func (a Algorithm) IsSymmetric() bool {
	switch a {
	case HS256, HS384, HS512:
		return true
	default:
		return false
	}
}

// IsAsymmetric reports whether the algorithm is asymmetric (RSA, ECDSA, EdDSA).
func (a Algorithm) IsAsymmetric() bool {
	return !a.IsSymmetric() && a.IsValid()
}

// IsValid reports whether the algorithm is one of the supported algorithms.
func (a Algorithm) IsValid() bool {
	switch a {
	case HS256, HS384, HS512,
		RS256, RS384, RS512,
		PS256, PS384, PS512,
		ES256, ES384, ES512,
		EdDSA:
		return true
	default:
		return false
	}
}

func hashFuncForAlg(alg Algorithm) (crypto.Hash, func() hash.Hash, error) {
	switch alg {
	case HS256, RS256, PS256, ES256:
		return crypto.SHA256, sha256.New, nil
	case HS384, RS384, PS384, ES384:
		return crypto.SHA384, sha512.New384, nil
	case HS512, RS512, PS512, ES512:
		return crypto.SHA512, sha512.New, nil
	case EdDSA:
		return 0, nil, nil
	default:
		return 0, nil, fmt.Errorf("%w: %s", ErrAlgorithmNotAllowed, alg)
	}
}

func sign(alg Algorithm, key any, signingInput []byte) ([]byte, error) {
	switch alg {
	case HS256, HS384, HS512:
		secret, ok := key.([]byte)
		if !ok {
			return nil, fmt.Errorf("%w: HMAC requires []byte secret", ErrInvalidKey)
		}
		if len(secret) == 0 {
			return nil, fmt.Errorf("%w: HMAC secret cannot be empty", ErrInvalidKey)
		}
		_, newHash, err := hashFuncForAlg(alg)
		if err != nil {
			return nil, err
		}
		h := hmac.New(newHash, secret)
		h.Write(signingInput)
		return h.Sum(nil), nil

	case RS256, RS384, RS512:
		rsaPriv, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("%w: RSA signing requires *rsa.PrivateKey", ErrInvalidKey)
		}
		hashVal, newHash, err := hashFuncForAlg(alg)
		if err != nil {
			return nil, err
		}
		h := newHash()
		h.Write(signingInput)
		digest := h.Sum(nil)
		return rsa.SignPKCS1v15(rand.Reader, rsaPriv, hashVal, digest)

	case PS256, PS384, PS512:
		rsaPriv, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("%w: RSA-PSS signing requires *rsa.PrivateKey", ErrInvalidKey)
		}
		hashVal, newHash, err := hashFuncForAlg(alg)
		if err != nil {
			return nil, err
		}
		h := newHash()
		h.Write(signingInput)
		digest := h.Sum(nil)
		opts := &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       hashVal,
		}
		return rsa.SignPSS(rand.Reader, rsaPriv, hashVal, digest, opts)

	case ES256, ES384, ES512:
		ecPriv, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("%w: ECDSA signing requires *ecdsa.PrivateKey", ErrInvalidKey)
		}
		_, newHash, err := hashFuncForAlg(alg)
		if err != nil {
			return nil, err
		}
		h := newHash()
		h.Write(signingInput)
		digest := h.Sum(nil)

		r, s, err := ecdsa.Sign(rand.Reader, ecPriv, digest)
		if err != nil {
			return nil, err
		}
		return encodeECDSASignature(alg, r, s)

	case EdDSA:
		edPriv, ok := key.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("%w: EdDSA signing requires ed25519.PrivateKey", ErrInvalidKey)
		}
		return ed25519.Sign(edPriv, signingInput), nil

	default:
		return nil, fmt.Errorf("%w: %s", ErrAlgorithmNotAllowed, alg)
	}
}

func verifySignature(alg Algorithm, key any, signingInput, signature []byte) error {
	switch alg {
	case HS256, HS384, HS512:
		secret, ok := key.([]byte)
		if !ok {
			return fmt.Errorf("%w: HMAC verification requires []byte key", ErrInvalidKey)
		}
		_, newHash, err := hashFuncForAlg(alg)
		if err != nil {
			return err
		}
		h := hmac.New(newHash, secret)
		h.Write(signingInput)
		expected := h.Sum(nil)
		if subtle.ConstantTimeCompare(expected, signature) != 1 {
			return ErrInvalidSignature
		}
		return nil

	case RS256, RS384, RS512:
		var pub *rsa.PublicKey
		switch k := key.(type) {
		case *rsa.PublicKey:
			pub = k
		case *rsa.PrivateKey:
			pub = &k.PublicKey
		default:
			return fmt.Errorf("%w: RSA verification requires *rsa.PublicKey", ErrInvalidKey)
		}
		hashVal, newHash, err := hashFuncForAlg(alg)
		if err != nil {
			return err
		}
		h := newHash()
		h.Write(signingInput)
		digest := h.Sum(nil)
		if err := rsa.VerifyPKCS1v15(pub, hashVal, digest, signature); err != nil {
			return ErrInvalidSignature
		}
		return nil

	case PS256, PS384, PS512:
		var pub *rsa.PublicKey
		switch k := key.(type) {
		case *rsa.PublicKey:
			pub = k
		case *rsa.PrivateKey:
			pub = &k.PublicKey
		default:
			return fmt.Errorf("%w: RSA-PSS verification requires *rsa.PublicKey", ErrInvalidKey)
		}
		hashVal, newHash, err := hashFuncForAlg(alg)
		if err != nil {
			return err
		}
		h := newHash()
		h.Write(signingInput)
		digest := h.Sum(nil)
		opts := &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       hashVal,
		}
		if err := rsa.VerifyPSS(pub, hashVal, digest, signature, opts); err != nil {
			return ErrInvalidSignature
		}
		return nil

	case ES256, ES384, ES512:
		var pub *ecdsa.PublicKey
		switch k := key.(type) {
		case *ecdsa.PublicKey:
			pub = k
		case *ecdsa.PrivateKey:
			pub = &k.PublicKey
		default:
			return fmt.Errorf("%w: ECDSA verification requires *ecdsa.PublicKey", ErrInvalidKey)
		}
		_, newHash, err := hashFuncForAlg(alg)
		if err != nil {
			return err
		}
		h := newHash()
		h.Write(signingInput)
		digest := h.Sum(nil)

		r, s, err := decodeECDSASignature(alg, signature)
		if err != nil {
			return ErrInvalidSignature
		}
		if !ecdsa.Verify(pub, digest, r, s) {
			return ErrInvalidSignature
		}
		return nil

	case EdDSA:
		var pub ed25519.PublicKey
		switch k := key.(type) {
		case ed25519.PublicKey:
			pub = k
		case ed25519.PrivateKey:
			pub = k.Public().(ed25519.PublicKey)
		default:
			return fmt.Errorf("%w: EdDSA verification requires ed25519.PublicKey", ErrInvalidKey)
		}
		if !ed25519.Verify(pub, signingInput, signature) {
			return ErrInvalidSignature
		}
		return nil

	default:
		return fmt.Errorf("%w: %s", ErrAlgorithmNotAllowed, alg)
	}
}

func curveByteSize(alg Algorithm) int {
	switch alg {
	case ES256:
		return 32
	case ES384:
		return 48
	case ES512:
		return 66
	default:
		return 0
	}
}

func encodeECDSASignature(alg Algorithm, r, s *big.Int) ([]byte, error) {
	byteSize := curveByteSize(alg)
	if byteSize == 0 {
		return nil, errors.New("jwt: invalid ecdsa algorithm")
	}

	rBytes := r.Bytes()
	sBytes := s.Bytes()

	if len(rBytes) > byteSize || len(sBytes) > byteSize {
		return nil, errors.New("jwt: ecdsa signature component overflows curve byte size")
	}

	sig := make([]byte, 2*byteSize)
	copy(sig[byteSize-len(rBytes):byteSize], rBytes)
	copy(sig[2*byteSize-len(sBytes):], sBytes)

	return sig, nil
}

func decodeECDSASignature(alg Algorithm, signature []byte) (*big.Int, *big.Int, error) {
	byteSize := curveByteSize(alg)
	if byteSize == 0 || len(signature) != 2*byteSize {
		return nil, nil, errors.New("jwt: invalid ecdsa signature length")
	}

	r := new(big.Int).SetBytes(signature[:byteSize])
	s := new(big.Int).SetBytes(signature[byteSize:])

	return r, s, nil
}
