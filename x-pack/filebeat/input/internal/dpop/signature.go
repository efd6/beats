package dpop

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
)

// Helpers to hash and sign DPoP proof inputs.

// sha256Base64URL returns the base64url (no padding) encoding of the SHA-256
// digest of the provided string.
func sha256Base64URL(data string) (string, error) {
	h := sha256.Sum256([]byte(data))
	enc := base64RawURLEncode(h[:])
	return enc, nil
}

// base64RawURLEncode encodes bytes using base64url without padding.
func base64RawURLEncode(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// signECDSA creates an ES256 signature over data (with SHA-256) and returns
// the raw (r || s) concatenation, as required by JOSE for ES256.
func signECDSA(priv *ecdsa.PrivateKey, data []byte) ([]byte, error) {
	h := sha256.Sum256(data)
	r, s, err := ecdsa.Sign(rand.Reader, priv, h[:])
	if err != nil {
		return nil, err
	}
	// DPoP ES256 requires the raw concatenation of r and s (not DER)
	curveBits := priv.Curve.Params().BitSize
	if priv.Curve != elliptic.P256() {
		return nil, errors.New("unsupported ECDSA curve for ES256")
	}
	octLen := (curveBits + 7) / 8
	rb := leftPadToSize(r.Bytes(), octLen)
	sb := leftPadToSize(s.Bytes(), octLen)
	return append(rb, sb...), nil
}

// signRSA creates an RS256 signature over data (with SHA-256) per PKCS#1 v1.5.
func signRSA(priv *rsa.PrivateKey, data []byte) ([]byte, error) {
	h := sha256.Sum256(data)
	return rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, h[:])
}
