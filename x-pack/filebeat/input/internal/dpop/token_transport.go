package dpop

import (
	"errors"
	"net/http"
)

// TokenTransport adds a DPoP proof to token endpoint HTTP requests.
// It retries once on DPoP-Nonce challenges (401/400/429 with DPoP-Nonce header).
// This transport should be installed on the http.Client used by oauth2 when fetching tokens.

type TokenTransport struct {
	Base     http.RoundTripper
	ProofGen *ProofGenerator
}

// RoundTrip implements http.RoundTripper, injecting a DPoP proof into token
// endpoint requests and handling one retry on a nonce challenge.
func (t *TokenTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}
	if t.ProofGen == nil {
		return nil, errors.New("token dpop transport requires ProofGenerator")
	}

	r := req.Clone(req.Context())
	proof, err := t.ProofGen.BuildProof(req.Context(), req.Method, req.URL.String(), ProofOptions{})
	if err != nil {
		return nil, err
	}
	r.Header.Set("DPoP", proof)
	resp, err := base.RoundTrip(r)
	if err != nil {
		return resp, err
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusBadRequest || resp.StatusCode == 429 {
		if nonce := resp.Header.Get("DPoP-Nonce"); nonce != "" {
			_ = resp.Body.Close()
			proof, err = t.ProofGen.BuildProof(req.Context(), req.Method, req.URL.String(), ProofOptions{Nonce: nonce})
			if err != nil {
				return nil, err
			}
			r2 := req.Clone(req.Context())
			r2.Header.Set("DPoP", proof)
			return base.RoundTrip(r2)
		}
	}
	return resp, nil
}
