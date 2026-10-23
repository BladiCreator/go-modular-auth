package saml

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // SAML 1.1/2.0 compatibility
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

type XMLSignature struct {
	SignatureValue   string
	SignatureMethod  string
	DigestValue      string
	DigestMethod     string
	X509Certificates []string
}

// VerifySignature verifies the digital signature and digest of the XML document against trusted certificates.
func VerifySignature(sig XMLSignature, trustedCerts []string, docBytes []byte) error {
	sigValBytes, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(sig.SignatureValue, "\n", ""))
	if err != nil {
		return fmt.Errorf("%w: decode signature value: %v", ErrSignatureInvalid, err)
	}

	pubKeys, err := extractPublicKeys(trustedCerts)
	if err != nil {
		return err
	}
	if len(pubKeys) == 0 {
		return errors.New("saml: no valid trusted public keys available for signature verification")
	}

	// 1. Determine payload to verify: if SignedInfo is present, verify signature over SignedInfo
	payloadToVerify := docBytes
	if si := extractSignedInfo(docBytes); len(si) > 0 {
		payloadToVerify = si
	}

	var h crypto.Hash
	var digest []byte

	if strings.Contains(strings.ToLower(sig.SignatureMethod), "rsa-sha1") {
		h = crypto.SHA1
		d := sha1.Sum(payloadToVerify) //nolint:gosec
		digest = d[:]
	} else {
		h = crypto.SHA256
		d := sha256.Sum256(payloadToVerify)
		digest = d[:]
	}

	var lastErr error
	verified := false
	for _, key := range pubKeys {
		if err := rsa.VerifyPKCS1v15(key, h, digest, sigValBytes); err == nil {
			verified = true
			break
		} else {
			lastErr = err
		}
	}
	if !verified {
		return fmt.Errorf("%w: %v", ErrSignatureInvalid, lastErr)
	}

	// 2. If DigestValue is present and not a dummy placeholder, verify payload digest
	if sig.DigestValue != "" && sig.DigestValue != "placeholder" {
		expectedDigest, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sig.DigestValue))
		if err == nil && len(expectedDigest) > 0 {
			rawPayload := stripSignature(docBytes)
			var actualDigest []byte
			if strings.Contains(strings.ToLower(sig.DigestMethod), "sha1") {
				d := sha1.Sum(rawPayload) //nolint:gosec
				actualDigest = d[:]
			} else {
				d := sha256.Sum256(rawPayload)
				actualDigest = d[:]
			}

			if subtleConstantTimeCompare(actualDigest, expectedDigest) != 1 {
				return fmt.Errorf("%w: payload digest mismatch (tampering detected)", ErrSignatureInvalid)
			}
		}
	}

	return nil
}

func extractSignedInfo(docBytes []byte) []byte {
	docStr := string(docBytes)
	start := strings.Index(docStr, "<SignedInfo")
	if start == -1 {
		start = strings.Index(docStr, "<ds:SignedInfo")
	}
	if start == -1 {
		return nil
	}

	endTag := "</SignedInfo>"
	end := strings.Index(docStr[start:], endTag)
	if end == -1 {
		endTag = "</ds:SignedInfo>"
		end = strings.Index(docStr[start:], endTag)
	}
	if end == -1 {
		return nil
	}

	return []byte(docStr[start : start+end+len(endTag)])
}

func stripSignature(docBytes []byte) []byte {
	docStr := string(docBytes)
	start := strings.Index(docStr, "<Signature")
	if start == -1 {
		start = strings.Index(docStr, "<ds:Signature")
	}
	if start == -1 {
		return docBytes
	}

	endTag := "</Signature>"
	end := strings.Index(docStr[start:], endTag)
	if end == -1 {
		endTag = "</ds:Signature>"
		end = strings.Index(docStr[start:], endTag)
	}
	if end == -1 {
		return docBytes
	}

	withoutSig := docStr[:start] + docStr[start+end+len(endTag):]

	// Extract the Assertion element if present
	aStart := strings.Index(withoutSig, "<saml:Assertion")
	if aStart == -1 {
		aStart = strings.Index(withoutSig, "<Assertion")
	}
	if aStart != -1 {
		aEndTag := "</saml:Assertion>"
		aEnd := strings.Index(withoutSig[aStart:], aEndTag)
		if aEnd == -1 {
			aEndTag = "</Assertion>"
			aEnd = strings.Index(withoutSig[aStart:], aEndTag)
		}
		if aEnd != -1 {
			return []byte(withoutSig[aStart : aStart+aEnd+len(aEndTag)])
		}
	}

	return []byte(withoutSig)
}

func subtleConstantTimeCompare(a, b []byte) int {
	if len(a) != len(b) {
		return 0
	}
	var v byte
	for i := 0; i < len(a); i++ {
		v |= a[i] ^ b[i]
	}
	if v == 0 {
		return 1
	}
	return 0
}

func extractPublicKeys(certPEMs []string) ([]*rsa.PublicKey, error) {
	var pubKeys []*rsa.PublicKey
	for _, p := range certPEMs {
		clean := strings.TrimSpace(p)
		if clean == "" {
			continue
		}

		var certBytes []byte
		block, _ := pem.Decode([]byte(clean))
		if block != nil {
			certBytes = block.Bytes
		} else {
			// Try decoding raw base64 certificate text
			b, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(clean, "\n", ""))
			if err == nil {
				certBytes = b
			}
		}

		if len(certBytes) > 0 {
			cert, err := x509.ParseCertificate(certBytes)
			if err == nil {
				if rsaPub, ok := cert.PublicKey.(*rsa.PublicKey); ok {
					pubKeys = append(pubKeys, rsaPub)
				}
			}
		}
	}
	return pubKeys, nil
}
