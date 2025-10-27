// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package agent

import (
	"encoding/json"
	"fmt"

	"github.com/google/jsonschema-go/jsonschema"
)

type Tool struct {
	// For logging/debugging.
	name         string
	description  string
	handler      func(*Context, map[string]any) (map[string]any, error)
	inputSchema  *jsonschema.Resolved
	outputSchema *jsonschema.Resolved
}

func MustFuncTool[Args, Results any](name, description string, fn func(*Context, Args) (Results, error)) *Tool {
	tool, err := NewFuncTool(name, description, fn)
	if err != nil {
		panic(err)
	}
	return tool
}

func NewFuncTool[Args, Results any](name, description string, fn func(*Context, Args) (Results, error)) (*Tool, error) {
	inputSchema, err := jsonSchema[Args]()
	if err != nil {
		return nil, err
	}
	outputSchema, err := jsonSchema[Results]()
	if err != nil {
		return nil, err
	}
	handler := func(ctx *Context, args map[string]any) (map[string]any, error) {
		typedArgs, err := convertTo[Args](inputSchema, args)
		if err != nil {
			return nil, err
		}
		results, err := fn(ctx, typedArgs)
		if err != nil {
			return nil, err
		}
		return convertTo[map[string]any](outputSchema, results)
	}
	return &Tool{
		name:         name,
		description:  description,
		handler:      handler,
		inputSchema:  inputSchema,
		outputSchema: outputSchema,
	}, nil
}

// TODO
type AgentTool struct{}

func jsonSchema[T any]() (*jsonschema.Resolved, error) {
	s, err := jsonschema.For[T](nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create json schema for type %T: %w", *new(T), err)
	}
	r, err := s.Resolve(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve json schema for type %T: %w", *new(T), err)
	}
	return r, nil
}

func convertTo[To, From any](schema *jsonschema.Resolved, from From) (To, error) {
	var to To
	raw, err := json.Marshal(from)
	if err != nil {
		return to, err
	}
	untyped := make(map[string]any)
	if err := json.Unmarshal(raw, &untyped); err != nil {
		return to, err
	}
	if err := schema.Validate(untyped); err != nil {
		return to, err
	}
	if err := json.Unmarshal(raw, &to); err != nil {
		return to, err
	}
	return to, err
}
