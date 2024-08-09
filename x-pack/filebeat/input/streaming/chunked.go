// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package streaming

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	inputcursor "github.com/elastic/beats/v7/filebeat/input/v2/input-cursor"
	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/google/cel-go/cel"
)

type chunkedStream struct {
	processor

	urlProg cel.Program
	urlAST  *cel.Ast
	client  *http.Client

	id     string
	cfg    config
	cursor map[string]any

	time func() time.Time
}

// NewChunkedFollower performs environment construction including CEL
// program and regexp compilation, and input metrics set-up for a chunked
// HTTP stream follower.
func NewChunkedFollower(ctx context.Context, id string, cfg config, cursor map[string]any, pub inputcursor.Publisher, log *logp.Logger, now func() time.Time) (StreamFollower, error) {
	s := chunkedStream{
		id:     id,
		cfg:    cfg,
		cursor: cursor,
		processor: processor{
			ns:      "chunked",
			pub:     pub,
			log:     log,
			redact:  cfg.Redact,
			metrics: newInputMetrics(id),
		},
	}
	s.metrics.url.Set(cfg.URL.String())
	s.metrics.errorsTotal.Set(0)

	patterns, err := regexpsFromConfig(cfg)
	if err != nil {
		s.metrics.errorsTotal.Inc()
		s.Close()
		return nil, err
	}

	s.prg, s.ast, err = newProgram(ctx, cfg.Program, root, nil, nil, nil, patterns, log)
	if err != nil {
		s.metrics.errorsTotal.Inc()
		s.Close()
		return nil, err
	}
	if s.cfg.URLProgram != "" {
		s.urlProg, s.urlAST, err = newProgram(ctx, s.cfg.URLProgram, root, s.client, nil, nil, patterns, log) // This will likely need a client.
		if err != nil {
			s.metrics.errorsTotal.Inc()
			s.Close()
			return nil, err
		}
	}

	return &s, nil
}

// FollowStream receives, processes and publishes events from the subscribed
// chunked stream.
func (s *chunkedStream) FollowStream(ctx context.Context) error {
	state := s.cfg.State
	if state == nil {
		state = make(map[string]any)
	}
	if s.cursor != nil {
		state["cursor"] = s.cursor
	}

	r := chunkReader{
		client:  s.client,
		refresh: s.renew(ctx, &state), // Mutates state.
	}
	defer r.Close()

	dec := json.NewDecoder(&r)
	for {
		// We may need to refresh before a staling of the conn.
		// This would happen here, but how? The dec would also
		// need to be replaced.

		var v map[string]any
		err := dec.Decode(&v)
		if err != nil {
			if err != io.EOF {
				s.metrics.errorsTotal.Inc()
				return err
			}
			return nil
		}
		s.log.Debugw("received chunked object", logp.Namespace("chunked"), v)
		state["response"] = v
		err = s.process(ctx, state, s.cursor, s.now().In(time.UTC))
		if err != nil {
			s.metrics.errorsTotal.Inc()
			s.log.Errorw("failed to process and publish data", "error", err)
			return err
		}
	}
}

func (s *chunkedStream) renew(ctx context.Context, state *map[string]any) func(c *http.Client, r *http.Request) (*http.Response, error) {
	return func(c *http.Client, r *http.Request) (*http.Response, error) {
		if s.urlProg != nil {
			var err error
			*state, r, err = getRequest(ctx, s.urlProg, s.urlAST, s.cfg.URL.String(), *state, s.cfg.Redact, s.log, s.now)
			if err != nil {
				s.metrics.errorsTotal.Inc()
				return nil, err
			}
		}

		resp, err := c.Do(r)
		if err != nil {
			s.metrics.errorsTotal.Inc()
		}
		return resp, err
	}
}

// getRequest initializes the input URL with the help of the url_program.
func getRequest(ctx context.Context, prg cel.Program, ast *cel.Ast, url string, state map[string]any, redaction *redact, log *logp.Logger, now func() time.Time) (map[string]any, *http.Request, error) {
	if prg == nil {
		return state, nil, nil
	}

	state["url"] = url
	log.Debugw("cel engine state before url_eval", logp.Namespace("chunked"), "state", redactor{state: state, cfg: redaction})
	start := now().In(time.UTC)
	state, err := evalWith(ctx, prg, ast, state, start)
	log.Debugw("url_eval result", logp.Namespace("chunked"), "modified_url", url)
	if err != nil {
		log.Errorw("failed url evaluation", "error", err)
		return state, nil, err
	}

	url, err = getTyped(state, "url", url)
	if err != nil {
		return state, nil, err
	}
	method, err := getTyped(state, "method", "GET")
	if err != nil {
		return state, nil, err
	}
	header, err := getTyped(state, "header", map[string][]string(nil))
	if err != nil {
		return state, nil, err
	}
	body, err := getTyped(state, "body", []byte(nil))
	if err != nil {
		return state, nil, err
	}

	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		return state, nil, err
	}
	req.Header = header

	return state, req, nil
}

func getTyped[T any](m map[string]any, k string, def T) (T, error) {
	v, ok := m[k]
	if !ok {
		return def, nil
	}
	vt, ok := v.(T)
	if !ok {
		return vt, fmt.Errorf("unexpected type for %s: %T, wanted: %T", k, v, def)
	}
	return vt, nil
}

// now is time.Now with a modifiable time source.
func (s *chunkedStream) now() time.Time {
	if s.time == nil {
		return time.Now()
	}
	return s.time()
}

func (s *chunkedStream) Close() error {
	s.metrics.Close()
	return nil
}

// chunkReader is an io.ReadCloser that follows a potentially
// continuous chunked http connection.
type chunkReader struct {
	client *http.Client

	// curr is the currently filled response or nil. last
	// is the previous response.
	curr, last *http.Response

	// next is the http.Request used in the refresh call
	// when curr is nil or depleted.
	next http.Request
	// refresh is called by chunkClient.Read on the
	// receiver and the receiver's next value. It should
	// make an HTTP request on the client with the,
	// potentially modified, provided request.
	refresh func(*http.Client, *http.Request) (*http.Response, error)
}

func (c *chunkReader) Read(b []byte) (int, error) {
	if c.curr == nil {
		var err error
		c.curr, err = c.refresh(c.client, &c.next)
		if err != nil {
			return 0, err
		}
		if c.curr == nil {
			return 0, io.EOF
		}
	}
	n, err := c.curr.Body.Read(b)
	if err == io.EOF {
		err = c.curr.Body.Close()
		c.last = c.curr
		c.curr = nil
	}
	return n, err
}

func (c *chunkReader) Close() error {
	if c.curr == nil {
		return nil
	}
	c.last = c.curr
	io.Copy(io.Discard, c.last.Body)
	c.curr = nil
	return c.last.Body.Close()
}
