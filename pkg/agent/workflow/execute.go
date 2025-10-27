// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package workflow

import (
	"context"

	"google.golang.org/adk/agent"
	"google.golang.org/adk/model/gemini"
	"google.golang.org/adk/runner"
	"google.golang.org/adk/session"
	"google.golang.org/genai"
)

const (
	modelName   = "gemini-2.5-pro"
	maxLLMCalls = 100
)

type Event struct {
}

func Execute(ctx context.Context, flow *Flow, inputs any,
	events []*session.Event, eventSink func(*session.Event) error) (any, error) {
	llm, err := gemini.NewModel(ctx, modelName, &genai.ClientConfig{})
	if err != nil {
		return nil, err
	}
	cctx := &createContext{
		llm: llm,
	}
	root, err := flow.Root.create(cctx)
	if err != nil {
		return nil, err
	}
	state, err := flow.convertInputs(inputs)
	if err != nil {
		return nil, err
	}
	sessions := session.InMemoryService()
	const (
		userID    = "user"
		sessionID = "session"
	)
	createReq := &session.CreateRequest{
		AppName:   flow.Name,
		UserID:    userID,
		SessionID: sessionID,
		State:     state,
	}
	createResp, err := sessions.Create(ctx, createReq)
	if err != nil {
		return nil, err
	}
	session := createResp.Session
	for _, ev := range events {
		if err := sessions.AppendEvent(ctx, session, ev); err != nil {
			return nil, err
		}
	}
	r, err := runner.New(runner.Config{
		AppName:        flow.Name,
		Agent:          root,
		SessionService: sessions,
		//ArtifactService artifact.Service
		//MemoryService   memory.Service
	})
	if err != nil {
		return nil, err
	}
	cfg := agent.RunConfig{
		MaxLLMCalls: maxLLMCalls,
	}
	for ev, err := range r.Run(ctx, userID, sessionID, nil, cfg) {
		if err != nil {
			return nil, err
		}
		if err := eventSink(ev); err != nil {
			return nil, err
		}
	}
	return flow.extractOutputs(session.State())
}
