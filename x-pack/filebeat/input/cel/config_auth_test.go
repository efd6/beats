// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package cel

import (
	"slices"
	"testing"

	"github.com/elastic/beats/v7/x-pack/libbeat/common/aws"
)

func TestAuthConfigSecrets(t *testing.T) {
	secret := "client-secret-value"
	tests := []struct {
		name string
		cfg  authConfig
		want []string
	}{
		{name: "none", cfg: authConfig{}, want: nil},
		{
			name: "basic",
			cfg:  authConfig{Basic: &basicAuthConfig{User: "u", Password: "basic-password"}},
			want: []string{"basic-password"},
		},
		{
			name: "token",
			cfg:  authConfig{Token: &tokenAuthConfig{Type: "Token", Value: "token-value"}},
			want: []string{"token-value"},
		},
		{
			name: "digest",
			cfg:  authConfig{Digest: &digestAuthConfig{User: "u", Password: "digest-password"}},
			want: []string{"digest-password"},
		},
		{
			name: "oauth2",
			cfg:  authConfig{OAuth2: &oAuth2Config{ClientSecret: &secret, Password: "oauth2-password"}},
			want: []string{"client-secret-value", "oauth2-password"},
		},
		{
			name: "aws",
			cfg:  authConfig{AWS: &aws.SignerInputConfig{SecretAccessKey: "aws-secret-key", SessionToken: "aws-session-token"}},
			want: []string{"aws-secret-key", "aws-session-token"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := test.cfg.secrets()
			// The oauth2 case has an empty value for the unset fields; ignore those.
			got = slices.DeleteFunc(got, func(s string) bool { return s == "" })
			if !slices.Equal(got, test.want) {
				t.Errorf("secrets() = %q; want %q", got, test.want)
			}
		})
	}
}

func TestConfigStateSecrets(t *testing.T) {
	tests := []struct {
		name string
		cfg  config
		want []string
	}{
		{name: "none", cfg: config{}, want: nil},
		{
			name: "secret_state",
			cfg:  config{SecretState: secretState{m: map[string]any{"token": "secret-state-token", "nested": map[string]any{"k": "nested-secret-value"}}}},
			want: []string{"nested-secret-value", "secret-state-token"},
		},
		{
			name: "redact_fields_in_state",
			cfg: config{
				State:  map[string]any{"auth_token": "state-auth-token", "other": "not-secret-value", "creds": map[string]any{"password": "state-password"}}, //nolint:gosec // fake credential in a test
				Redact: &redact{Fields: []string{"auth_token", "creds.password", "missing", "creds.password.deeper"}},
			},
			want: []string{"state-auth-token", "state-password"},
		},
		{
			name: "redact_whole_map_and_list",
			cfg: config{
				State:  map[string]any{"creds": map[string]any{"a": "first-secret-value", "b": []any{"second-secret-value", 3}}},
				Redact: &redact{Fields: []string{"creds"}},
			},
			want: []string{"first-secret-value", "second-secret-value"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := test.cfg.stateSecrets()
			slices.Sort(got)
			if !slices.Equal(got, test.want) {
				t.Errorf("stateSecrets() = %q; want %q", got, test.want)
			}
		})
	}
}
