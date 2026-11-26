// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package okta

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/elastic/beats/v7/pkg/logp/logptest"
)

// traceStub is an http.RoundTripper implemented by a function.
type traceStub func(*http.Request) (*http.Response, error)

func (f traceStub) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

// TestRequestTraceMasksSecrets checks that the configured secrets are masked
// in the request trace, wherever the server echoes them.
func TestRequestTraceMasksSecrets(t *testing.T) {
	const (
		token  = "00-fake-okta-token-1234" //nolint:gosec // fake credential in a test
		secret = "fake-client-secret-5678" //nolint:gosec // fake credential in a test
	)
	filename := filepath.Join(t.TempDir(), "trace.ndjson")
	cfg := conf{
		OktaToken: token,
		OAuth2:    &oAuth2Config{ClientSecret: secret},
		Tracer:    &tracerConfig{Filename: filename, MaxSize: 1},
	}
	stub := traceStub(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusBadRequest,
			Header:     http.Header{"Content-Type": {"application/json"}, "X-Echo": {token}},
			Body:       io.NopCloser(strings.NewReader(`{"errorSummary":"unknown value ` + token + ` and ` + secret + `"}`)),
		}, nil
	})
	cli := requestTrace(t.Context(), &http.Client{Transport: stub}, cfg, logptest.NewTestingLogger(t, ""))

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://example.test/api?note="+token, nil)
	if err != nil {
		t.Fatalf("failed to make request: %v", err)
	}
	resp, err := cli.Do(req)
	if err != nil {
		t.Fatalf("unexpected error from request: %v", err)
	}
	resp.Body.Close()

	trace, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("failed to read the trace file: %v", err)
	}
	for _, s := range []string{token, secret} {
		if strings.Contains(string(trace), s) {
			t.Errorf("trace must not contain %q:\n%s", s, trace)
		}
	}
	if !strings.Contains(string(trace), "REDACTED") {
		t.Errorf("trace must contain the masked form:\n%s", trace)
	}
}
