package dpop

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"math/big"
)

// jwkPublic represents a minimal JSON Web Key (public part) used in DPoP headers.
// We only include the required members per RFCs for thumbprint stability.
// Use map[string]interface{} when attaching to JOSE header.

type keyAlgorithm string

const (
	algES256 keyAlgorithm = "ES256"
	algRS256 keyAlgorithm = "RS256"
)

// buildJWKAndAlg constructs a JWK (public key only) and selects the appropriate
// signing algorithm based on the provided private key. Supported keys:
//   - *ecdsa.PrivateKey with P-256 (ES256)
//   - *rsa.PrivateKey (RS256)
func buildJWKAndAlg(privateKey interface{}) (map[string]interface{}, keyAlgorithm, error) {
	switch k := privateKey.(type) {
	case *ecdsa.PrivateKey:
		return ecPublicJWK(&k.PublicKey)
	case *rsa.PrivateKey:
		return rsaPublicJWK(&k.PublicKey)
	default:
		return nil, "", errors.New("unsupported private key type for DPoP: expected *ecdsa.PrivateKey or *rsa.PrivateKey")
	}
}

func ecPublicJWK(pub *ecdsa.PublicKey) (map[string]interface{}, keyAlgorithm, error) {
	if pub == nil {
		return nil, "", errors.New("nil ECDSA public key")
	}
	// Only P-256 is supported for ES256
	if pub.Curve != elliptic.P256() {
		return nil, "", errors.New("unsupported elliptic curve: only P-256 is supported for DPoP ES256")
	}
	xBytes := pub.X.Bytes()
	yBytes := pub.Y.Bytes()
	// Pad to 32 bytes
	x := leftPadToSize(xBytes, 32)
	y := leftPadToSize(yBytes, 32)

	jwk := map[string]interface{}{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(x),
		"y":   base64.RawURLEncoding.EncodeToString(y),
	}
	return jwk, algES256, nil
}

func rsaPublicJWK(pub *rsa.PublicKey) (map[string]interface{}, keyAlgorithm, error) {
	if pub == nil {
		return nil, "", errors.New("nil RSA public key")
	}
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
	jwk := map[string]interface{}{
		"kty": "RSA",
		"n":   n,
		"e":   e,
	}
	return jwk, algRS256, nil
}

func leftPadToSize(b []byte, size int) []byte {
	if len(b) >= size {
		return b
	}
	p := make([]byte, size)
	copy(p[size-len(b):], b)
	return p
}
