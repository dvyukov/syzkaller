// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
	"fmt"
)

type Flow struct {
	Name string // Empty for the main workflow for the workflow type.
	Root Action

	*FlowType
}

type FlowType struct {
	Type           string
	Description    string
	extractOutputs func(map[string]any) map[string]any
}

var Flows = make(map[string]*Flow)

func Register[Inputs, Outputs any](typ, description string, flows ...*Flow) {
	if err := register[Inputs, Outputs](typ, description, Flows, flows); err != nil {
		panic(err)
	}
}

func register[Inputs, Outputs any](typ, description string, all map[string]*Flow, flows []*Flow) error {
	t := &FlowType{
		Type:        typ,
		Description: description,
		extractOutputs: func(state map[string]any) map[string]any {
			// Ensure that we actually have all outputs.
			tmp, err := convertFromMap[Outputs](state, false)
			if err != nil {
				panic(err)
			}
			return convertToMap(tmp)
		},
	}
	for _, flow := range flows {
		if flow.Name == "" {
			flow.Name = typ
		} else {
			flow.Name = typ + "-" + flow.Name
		}
		flow.FlowType = t
		flow.extractOutputs = func(state map[string]any) map[string]any {
			// Ensure that we actually have all outputs.
			tmp, err := convertFromMap[Outputs](state, false)
			if err != nil {
				panic(err)
			}
			return convertToMap(tmp)
		}
		if err := registerOne[Inputs, Outputs](all, flow); err != nil {
			return err
		}
	}
	return nil
}

func registerOne[Inputs, Outputs any](all map[string]*Flow, flow *Flow) error {
	if all[flow.Name] != nil {
		return fmt.Errorf("flow %v is already registered", flow.Name)
	}
	ctx := &verifyContext{
		actions: make(map[string]bool),
		state:   make(map[string]*varState),
	}
	provideOutputs[Inputs](ctx, "flow inputs")
	flow.Root.verify(ctx)
	requireInputs[Outputs](ctx, "flow outputs")
	if err := ctx.finalize(); err != nil {
		return fmt.Errorf("flow %v: %w", flow.Name, err)
	}
	all[flow.Name] = flow
	return nil
}
