// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package agent

import (
	"context"
)

type Context struct {
	context.Context
	State map[string]any
}

/*
type verifyContext struct {
	state map[string]any
	err   error
}
*/

type Action interface {
	exec(*Context) error
	verify(map[string]any) error
}

type LLMAgent struct {
	// For logging/debugging only.
	Name        string
	OutputKey   string
	Instruction string
	Prompt      string
	Tools       []*Tool
}

type Pipeline struct {
	// For logging/debugging only.
	Name    string
	Actions []Action
}

func (a *LLMAgent) exec(ctx *Context) error {
	return nil
}

func (a *LLMAgent) verify(state map[string]any) error {

	for _, name := range promptPlaceholderRe.FindAllStringSubmatch(a.Prompt, -1) {
		if !vctx.state[name[1]] && vctx.err == nil {
			vctx.err = fmt.Errorf("agent %v does not have input %v, available inputs: %v",
				a.Name, name[1], slices.Collect(maps.Keys(vctx.state)))
		}
	}
	
	
	if a.OutputKey != "" {
		if _, ok := state[a.OutputKey]; ok {
			return fmt.Errorf("agent %v does not have input %v, available inputs: %v",
				a.Name, name[1], slices.Collect(maps.Keys(vctx.state)))
		}
		state[a.OutputKey] = ""
	}
	return nil
}

func (p *Pipeline) exec(ctx *Context) error {
	return nil
}

func (p *Pipeline) verify(state map[string]any) error {
	for _, a := range p.Actions {
		if err := a.verify(state); err != nil {
			return err
		}
	}
	return nil
}
