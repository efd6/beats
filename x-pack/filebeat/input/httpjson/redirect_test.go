// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package httpjson

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	v2 "github.com/elastic/beats/v7/filebeat/input/v2"
	"github.com/elastic/beats/v7/libbeat/feature"
	"github.com/elastic/beats/v7/libbeat/statestore"
	"github.com/elastic/beats/v7/libbeat/statestore/storetest"
	"github.com/elastic/beats/v7/x-pack/filebeat/input/cel"
	conf "github.com/elastic/elastic-agent-libs/config"
	"github.com/elastic/elastic-agent-libs/logp"
)

func TestRedirect_EndToEnd(t *testing.T) {
	log := logp.NewNopLogger()
	store := newTestStore()

	httpjsonPlugin := v2.Plugin{
		Name:      "httpjson",
		Stability: feature.Stable,
		Manager:   NewInputManager(log, store),
	}
	celPlugin := cel.Plugin(log, store)

	loader, err := v2.NewLoader(log, []v2.Plugin{httpjsonPlugin, celPlugin}, "type", "")
	require.NoError(t, err)

	cfg := conf.MustNewConfigFrom(map[string]interface{}{
		"type":        "httpjson",
		"interval":    "60s",
		"run_as_cel":  true,
		"request.url": "https://api.example.com/events",
		"cel.program": `{"events":[{"message":"Hello, World!"}]}`,
		"cel.state":   map[string]interface{}{},
	})

	input, err := loader.Configure(cfg)
	require.NoError(t, err)
	require.NotNil(t, input)
}

func TestRedirect_NoRedirectWhenFlagAbsent(t *testing.T) {
	log := logp.NewNopLogger()
	store := newTestStore()

	httpjsonPlugin := v2.Plugin{
		Name:      "httpjson",
		Stability: feature.Stable,
		Manager:   NewInputManager(log, store),
	}

	loader, err := v2.NewLoader(log, []v2.Plugin{httpjsonPlugin}, "type", "")
	require.NoError(t, err)

	cfg := conf.MustNewConfigFrom(map[string]interface{}{
		"type":        "httpjson",
		"interval":    "60s",
		"request.url": "https://api.example.com/events",
	})

	input, err := loader.Configure(cfg)
	require.NoError(t, err)
	require.NotNil(t, input)
}

func TestRedirect_ErrorWithoutProgram(t *testing.T) {
	log := logp.NewNopLogger()
	store := newTestStore()

	httpjsonPlugin := v2.Plugin{
		Name:      "httpjson",
		Stability: feature.Stable,
		Manager:   NewInputManager(log, store),
	}

	loader, err := v2.NewLoader(log, []v2.Plugin{httpjsonPlugin}, "type", "")
	require.NoError(t, err)

	cfg := conf.MustNewConfigFrom(map[string]interface{}{
		"type":        "httpjson",
		"interval":    "60s",
		"request.url": "https://api.example.com/events",
		"run_as_cel":  true,
	})

	_, err = loader.Configure(cfg)
	require.Error(t, err)
}

func TestConvertHttpjsonToCel(t *testing.T) {
	cfg := conf.MustNewConfigFrom(map[string]interface{}{
		"type":        "httpjson",
		"id":          "my-input",
		"interval":    "60s",
		"request.url": "https://api.example.com/events",
		"cel.program": `{"events":[{"message":"test"}]}`,
		"cel.state":   map[string]interface{}{"cursor": map[string]interface{}{}},
	})

	out, err := convertHttpjsonToCel(cfg)
	require.NoError(t, err)

	typ, err := out.String("type", -1)
	require.NoError(t, err)
	require.Equal(t, "cel", typ)

	url, err := out.String("resource.url", -1)
	require.NoError(t, err)
	require.Equal(t, "https://api.example.com/events", url)

	program, err := out.String("program", -1)
	require.NoError(t, err)
	require.Equal(t, `{"events":[{"message":"test"}]}`, program)

	id, err := out.String("id", -1)
	require.NoError(t, err)
	require.Equal(t, "my-input", id)

	interval, err := out.String("interval", -1)
	require.NoError(t, err)
	require.Equal(t, "60s", interval)

	has, err := out.Has("state", -1)
	require.NoError(t, err)
	require.True(t, has)
}

var _ statestore.States = (*testStore)(nil)

type testStore struct {
	registry *statestore.Registry
}

func newTestStore() *testStore {
	return &testStore{
		registry: statestore.NewRegistry(storetest.NewMemoryStoreBackend()),
	}
}

func (s *testStore) Close()                                     { s.registry.Close() }
func (s *testStore) StoreFor(string) (*statestore.Store, error) { return s.registry.Get("filebeat") }
func (s *testStore) CleanupInterval() time.Duration             { return 0 }
