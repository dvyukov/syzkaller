// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package agent

import (
	"fmt"
	"iter"
	"reflect"
	"strings"

	"github.com/google/jsonschema-go/jsonschema"
)

type Flow struct {
	Name         string
	Experimental bool
	MajorVersion uint
	MinorVersion uint
	Root         Action

	InputSchema  *jsonschema.Resolved
	OutputSchema *jsonschema.Resolved
	//ParseInputs    func([]byte) (any, error) `json:"-"`
	//convertInputs  func(data any) (map[string]any, error)
	//extractOutputs func(session.State) (any, error)
}

var Flows = make(map[string]*Flow)

func RegisterFlows[Inputs, Outputs any](flows ...*Flow) {
	if err := registerFlows[Inputs, Outputs](flows); err != nil {
		panic(err)
	}
}

func registerFlows[Inputs, Outputs any](flows []*Flow) error {
	/*
		if typ := reflect.TypeFor[Inputs](); typ.Kind() != reflect.Struct {
			return fmt.Errorf("input type %v is not a struct", typ.Name())
		}
		if typ := reflect.TypeFor[Outputs](); typ.Kind() != reflect.Struct {
			return fmt.Errorf("output type %v is not a struct", typ.Name())
		}
	*/
	inputSchema, err := jsonSchema[Inputs]()
	if err != nil {
		return err
	}
	outputSchema, err := jsonSchema[Outputs]()
	if err != nil {
		return err
	}
	for _, flow := range flows {
		if Flows[flow.Name] != nil {
			return fmt.Errorf("flow %v is already registered", flow.Name)
		}
		flow.InputSchema = inputSchema
		flow.OutputSchema = outputSchema
		//flow.ParseInputs = parseInputs[Inputs]
		//flow.convertInputs = inputs[Inputs]
		//flow.extractOutputs = outputs[Outputs]
		if err := verify[Inputs, Outputs](flow); err != nil {
			return fmt.Errorf("flow %v: %w", flow.Name, err)
		}
		Flows[flow.Name] = flow
	}
	return nil
}

func verify[Inputs, Outputs any](flow *Flow) error {
	in := map[string]string{}
	var inputs Inputs
	for name := range foreachField(&inputs) {
		in[name] = ""
	}
	state := map[string]any{"in": in}
	if err := flow.Root.verify(state); err != nil {
		return err
	}
	var outputs Outputs
	for name := range foreachField(&outputs) {
		if _, ok := state[name]; !ok {
			return fmt.Errorf("output field %q is not created", name)
		}
	}
	return nil
}

func foreachField(data any) iter.Seq2[string, reflect.Value] {
	return func(yield func(string, reflect.Value) bool) {
		v := reflect.ValueOf(data).Elem()
		for _, field := range reflect.VisibleFields(v.Type()) {
			name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
			if name == "-" {
				continue
			}
			if name == "" {
				name = field.Name
			}
			if !yield(name, v.FieldByIndex(field.Index)) {
				break
			}
		}
	}
}
