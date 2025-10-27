// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package codesearch

import (
	"github.com/google/syzkaller/pkg/agent"
)

var Tool = agent.MustFuncTool(
	"codesearch",
	"code searching tool",
	func(ctx *agent.Context, args args) (result, error) {
		matches, err := do(ctx, args.Action, args.Entity)
		return result{matches}, err
	})

type args struct {
	Action string `json:"action" jsonschema:"Action to perform: search or define."`
	Entity string `json:"entity" jsonschema:"Entity to search for."`
}

type result struct {
	Matches []string `json:"matches" jsonschema:"List of matches."`
}

func do(ctx *agent.Context, action, entity string) ([]string, error) {
	return []string{"foo", "bar"}, nil
}
