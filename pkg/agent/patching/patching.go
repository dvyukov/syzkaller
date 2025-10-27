// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package patching

import (
	"github.com/google/syzkaller/pkg/agent"
	"github.com/google/syzkaller/pkg/agent/tool/codesearch"
)

type Inputs struct {
	Title      string `json:"title"`
	Reproducer string `json:"reproducer"`
	Crash      string `json:"crash"`
}

type Outputs struct {
	Subsystem   string `json:"subsystem"`
	Description string `json:"description"`
	Diff        string `json:"diff"`
}

func init() {
	agent.RegisterFlows[Inputs, Outputs](
		&agent.Flow{
			Name:         "patching",
			MajorVersion: 1,
			MinorVersion: 1,
			Root: &agent.Pipeline{
				Actions: []agent.Action{
					&agent.LLMAgent{
						Name:        "debugger",
						OutputKey:   "explanation",
						Instruction: debuggingInstruction,
						Prompt:      debuggingPrompt,
						Tools:       []*agent.Tool{codesearch.Tool},
					},
					&agent.LLMAgent{
						Name:      "subsystem-identifier",
						OutputKey: "subsystem",
						Prompt:    subsystemPrompt,
						Tools:     []*agent.Tool{codesearch.Tool},
					},
					&agent.LLMAgent{
						Name:      "diff-generator",
						OutputKey: "diff",
						Prompt:    diffPrompt,
						Tools:     []*agent.Tool{codesearch.Tool},
					},
					&agent.LLMAgent{
						Name:      "description-generator",
						OutputKey: "description",
						Prompt:    descriptionPrompt,
					},
				},
			},
		},
	)
}

const debuggingInstruction = `
You are an experienced Linux kernel developer tasked with debugging a kernel crash root cause.
You need to provide a detailed explanation of the root cause for another developer to be
able to write a fix for the bug based on your explanation.
Your final reply must contain only the explanation.
`

const debuggingPrompt = `
The crash is:

{in:crash}
`

const subsystemPrompt = `
You are an experienced Linux kernel developer tasked with identifying the kernel subsystem
for a kernel bug. The subsystem will be later used to find the relevant kernel tree to
apply a fix for this bug, and to mail the fix to relevant kernel maintainers.
Your final reply should contain only the subsystem name.
You need to choose on of the following kernel subsystem names:
 - net
 - fs
 - usb

The crash that corresponds to the bug is:

{in:crash}

The explanation of the root cause of the bug is:

{explanation}
`

const diffPrompt = `
`

const descriptionPrompt = `
`
