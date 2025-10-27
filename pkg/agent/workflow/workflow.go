// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package workflow

import (
	"fmt"
	"maps"
	"regexp"
	"slices"

	"github.com/google/jsonschema-go/jsonschema"
	"google.golang.org/adk/agent"
	"google.golang.org/adk/agent/llmagent"
	"google.golang.org/adk/agent/workflowagents/sequentialagent"
	"google.golang.org/adk/model"
	"google.golang.org/adk/session"
	"google.golang.org/adk/tool"
	"google.golang.org/adk/tool/functiontool"
	"google.golang.org/genai"
)

type Flow struct {
	Name         string
	Experimental bool
	MajorVersion uint
	MinorVersion uint
	Root         Agent

	InputSchema    *jsonschema.Schema
	OutputSchema   *jsonschema.Schema
	ParseInputs    func([]byte) (any, error) `json:"-"`
	convertInputs  func(data any) (map[string]any, error)
	extractOutputs func(session.State) (any, error)
}

type createContext struct {
	llm model.LLM
}

type verifyContext struct {
	state map[string]bool
	err   error
}

type Tool interface {
	create(*createContext) (tool.Tool, error)
}

type funcTool[Args, Results any] struct {
	// For logging/debugging.
	Name        string
	Description string
	Func        func(tool.Context, Args) Results `json:"-"`

	InputSchema  *jsonschema.Schema
	OutputSchema *jsonschema.Schema
}

func NewFuncTool[Args, Results any](name, description string, fn func(tool.Context, Args) Results) Tool {
	inputSchema, err := jsonschema.For[Args](nil)
	if err != nil {
		panic(fmt.Sprintf("failed to create json schema for args type: %w", err))
	}
	outputSchema, err := jsonschema.For[Results](nil)
	if err != nil {
		panic(fmt.Sprintf("failed to create json schema for results type: %w", err))
	}
	return &funcTool[Args, Results]{
		Name:         name,
		Description:  description,
		Func:         fn,
		InputSchema:  inputSchema,
		OutputSchema: outputSchema,
	}
}

// TODO
type AgentTool struct{}

func (a *LLMAgent) create(cctx *createContext) (agent.Agent, error) {
	var tools []tool.Tool
	for _, t := range a.Tools {
		tool, err := t.create(cctx)
		if err != nil {
			return nil, err
		}
		tools = append(tools, tool)
	}
	return llmagent.New(llmagent.Config{
		Name: a.Name,
		GenerateContentConfig: &genai.GenerateContentConfig{
			Temperature: genai.Ptr[float32](0),
			ThinkingConfig: &genai.ThinkingConfig{
				IncludeThoughts: true,
				ThinkingBudget:  genai.Ptr[int32](-1),
			},
		},
		Model:                    cctx.llm,
		Instruction:              a.Instruction,
		BeforeModelCallbacks:     []llmagent.BeforeModelCallback{a.beforeModel},
		Tools:                    tools,
		OutputKey:                a.OutputKey,
		DisallowTransferToParent: true,
		DisallowTransferToPeers:  true,
	})
}

func (a *LLMAgent) beforeModel(ctx agent.CallbackContext, req *model.LLMRequest) (*model.LLMResponse, error) {
	//fmt.Printf("REQ: INSTRCUTION: %v\n", req.Config.SystemInstruction.Parts[0].Text)
	if len(req.Contents) != 0 {
		fmt.Printf("REQ: CONTENTS: %v\n", req.Contents[0].Parts[0].Text)
	}
	if len(req.Contents) == 0 {
		req.Contents = append(req.Contents, genai.NewContentFromText(a.Prompt, genai.RoleUser))
	}
	if len(req.Contents) != 0 {
		fmt.Printf("REQ: CONTENTS: %v\n", req.Contents[0].Parts[0].Text)
	}
	return nil, nil
}

var promptPlaceholderRe = regexp.MustCompile(`{+([^{}]*)}+`)

func (a *LLMAgent) verify(vctx *verifyContext) {
	for _, name := range promptPlaceholderRe.FindAllStringSubmatch(a.Prompt, -1) {
		if !vctx.state[name[1]] && vctx.err == nil {
			vctx.err = fmt.Errorf("agent %v does not have input %v, available inputs: %v",
				a.Name, name[1], slices.Collect(maps.Keys(vctx.state)))
		}
	}
	if a.OutputKey != "" {
		vctx.state[a.OutputKey] = true
	}
}

func (a *SequentialAgent) create(cctx *createContext) (agent.Agent, error) {
	var agents []agent.Agent
	for _, sub := range a.Agents {
		subAgent, err := sub.create(cctx)
		if err != nil {
			return nil, err
		}
		agents = append(agents, subAgent)
	}
	return sequentialagent.New(sequentialagent.Config{
		AgentConfig: agent.Config{
			Name:      a.Name,
			SubAgents: agents,
		},
	})
}

func (a *SequentialAgent) verify(vctx *verifyContext) {
	for _, a := range a.Agents {
		a.verify(vctx)
	}
}

func (t *funcTool[Args, Results]) create(*createContext) (tool.Tool, error) {
	cfg := functiontool.Config{
		Name:        t.Name,
		Description: t.Description,
	}
	return functiontool.New(cfg, t.Func)
}
