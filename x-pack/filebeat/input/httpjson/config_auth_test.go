// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package httpjson

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
