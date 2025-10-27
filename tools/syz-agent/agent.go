// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/google/syzkaller/pkg/agent"
	_ "github.com/google/syzkaller/pkg/agent/patching"
	"github.com/google/syzkaller/pkg/tool"
)

func main() {
	var (
		flagFlow  = flag.String("workflow", "", "workflow to execute")
		flagInput = flag.String("input", "", "input json file with workflow arguments")
	)
	defer tool.Init()()
	ctx := context.Background()
	out, err := run(ctx, *flagFlow, *flagInput)
	if err != nil {
		tool.Fail(err)
	}
	os.Stdout.Write(out)
}

func run(ctx context.Context, flowName, inputFile string) ([]byte, error) {
	flow := agent.Flows[flowName]
	if flow == nil {
		return nil, fmt.Errorf("workflow %q is not found", flowName)
	}
	inputData, err := os.ReadFile(inputFile)
	if err != nil {
		return nil, fmt.Errorf("failed to open -input file: %w", err)
	}
	var inputs map[string]any
	if err := json.Unmarshal(inputData, &inputs); err != nil {
		return nil, fmt.Errorf("failed to decode -input file: %w", err)
	}

	if dump, err := json.MarshalIndent(flow, "", "\t"); err != nil {
		return nil, err
	} else {
		fmt.Printf("running workflow:\n%s\n", dump)
	}

	if dump, err := json.MarshalIndent(inputs, "", "\t"); err != nil {
		return nil, err
	} else {
		fmt.Printf("inputs:\n%s\n", dump)
	}
	//return nil, nil

	out, err := agent.Execute(ctx, flow, inputs, nil, eventLogger)
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(out, "", "\t")
}

func eventLogger(ev *agent.Event) error {
	if dump, err := json.MarshalIndent(ev, "", "\t"); err != nil {
		return err
	} else {
		fmt.Printf("event:\n%s\n", dump)
	}
	return nil
}
