// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/aflow/trajectory"
	"google.golang.org/genai"
)

// https://ai.google.dev/gemini-api/docs/models
const DefaultModel = "gemini-3-pro-preview"

func (flow *Flow) Execute(c context.Context, model string, inputs map[string]any,
	cache *Cache, onEvent onEvent) (map[string]any, error) {
	ctx := &Context{
		Context: c,
		Workdir: cache.Workdir,
		cache:   cache,
		state:   maps.Clone(inputs),
		onEvent: onEvent,
	}
	if s := c.Value(stubContextKey); s != nil {
		ctx.stubContext = *s.(*stubContext)
	}
	if ctx.timeNow == nil {
		ctx.timeNow = time.Now
	}
	if ctx.generateContent == nil {
		var err error
		ctx.generateContent, err = contentGenerator(c, model)
		if err != nil {
			return nil, err
		}
	}
	span := &trajectory.Span{
		Type: trajectory.SpanFlow,
		Name: flow.Name,
	}
	if err := ctx.startSpan(span); err != nil {
		return nil, err
	}
	flowErr := flow.Root.execute(ctx)
	if flowErr != nil {
		span.Results = flow.extractOutputs(ctx.state)
	}
	if err := ctx.finishSpan(span, flowErr); err != nil {
		return nil, err
	}
	if ctx.spanNesting != 0 {
		// Since we finish all spans, even on errors, we should end up at 0.
		panic(fmt.Sprintf("unbalanced spans (%v)", ctx.spanNesting))
	}
	return span.Results, nil
}

type (
	onEvent             func(*trajectory.Span) error
	generateContentFunc func(*genai.GenerateContentConfig, []*genai.Content) (
		*genai.GenerateContentResponse, error)
	contextKeyType int
)

var (
	createClientOnce sync.Once
	createClientErr  error
	client           *genai.Client
	modelList        = make(map[string]bool)
	stubContextKey   = contextKeyType(1)
)

func contentGenerator(ctx context.Context, model string) (generateContentFunc, error) {
	createClientOnce.Do(func() {
		client, createClientErr = genai.NewClient(ctx, nil)
		if createClientErr != nil {
			return
		}
		for m, err := range client.Models.All(ctx) {
			if err != nil {
				createClientErr = err
				return
			}
			modelList[m.Name] = m.Thinking
		}
	})
	if createClientErr != nil {
		return nil, createClientErr
	}
	thinking, ok := modelList[model]
	if !ok {
		models := slices.Collect(maps.Keys(modelList))
		slices.Sort(models)
		return nil, fmt.Errorf("model %q does not exist (models: %v)", model, models)
	}
	return func(cfg *genai.GenerateContentConfig, req []*genai.Content) (*genai.GenerateContentResponse, error) {
		if thinking {
			cfg.ThinkingConfig = &genai.ThinkingConfig{
				IncludeThoughts: true,
				ThinkingBudget:  genai.Ptr[int32](-1),
			}
		}
		return client.Models.GenerateContent(ctx, model, req, cfg)
	}, nil
}

type Context struct {
	Context     context.Context
	Workdir     string
	cache       *Cache
	state       map[string]any
	onEvent     onEvent
	spanSeq     int
	spanNesting int
	stubContext
}

type stubContext struct {
	timeNow         func() time.Time
	generateContent generateContentFunc
}

func (ctx *Context) Cache(typ, desc string, populate func(string) error) (string, error) {
	return ctx.cache.Cache(typ, desc, populate)
}

func (ctx *Context) startSpan(span *trajectory.Span) error {
	span.Seq = ctx.spanSeq
	ctx.spanSeq++
	span.Nesting = ctx.spanNesting
	ctx.spanNesting++
	span.Started = ctx.timeNow()
	return ctx.onEvent(span)
}

func (ctx *Context) finishSpan(span *trajectory.Span, spanErr error) error {
	ctx.spanNesting--
	if ctx.spanNesting < 0 {
		panic("unbalanced spans")
	}
	span.Finished = ctx.timeNow()
	if spanErr != nil {
		span.Error = spanErr.Error()
	}
	err := ctx.onEvent(span)
	if spanErr != nil {
		err = spanErr
	}
	return err
}
