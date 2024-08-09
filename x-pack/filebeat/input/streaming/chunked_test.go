// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package streaming

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestChunkReader(t *testing.T) {
	const text = `Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor
incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis
nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.
Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore
eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident,
sunt in culpa qui officia deserunt mollit anim id est laborum.
`
	lines := strings.Split(text, "\n")
	chain := make([]*httptest.Server, len(lines))
	for i, l := range lines {
		chain[i] = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if i < len(chain)-1 {
				w.Header().Set("next", chain[i+1].URL)
			}
			w.Write([]byte(l))
			if len(l) != 0 {
				w.Write([]byte{'\n'})
			}
		}))
	}
	defer func() {
		for _, s := range chain {
			s.Close()
		}
	}()

	head, err := url.Parse(chain[0].URL)
	if err != nil {
		t.Fatalf("failed to parse test server URL: %v", err)
	}

	var cli chunkReader
	cli = chunkReader{
		client: chain[0].Client(), // This will break with TLS in testing.
		next: http.Request{
			URL: head,
		},
		refresh: func(c *http.Client, r *http.Request) (*http.Response, error) {
			if cli.last != nil {
				next := cli.last.Header.Get("next")
				if next == "" {
					return nil, io.EOF
				}
				r.URL, err = url.Parse(next)
				if err != nil {
					t.Fatalf("unexpected error parsing URL header: %v", err)
				}
			}
			return c.Do(r)
		},
	}

	var buf bytes.Buffer
	_, err = io.Copy(&buf, &cli)
	if err != nil {
		t.Errorf("unexpected error reading chunk chain: %v", err)
	}

	err = cli.Close()
	if err != nil {
		t.Errorf("unexpected error calling close: %v", err)
	}

	got := buf.String()
	if got != text {
		t.Errorf("unexpected result\n--- want\n+++ got\n%s", cmp.Diff(text, got))
	}
}
