// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"testing"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/stretchr/testify/require"
)

func TestAIMigrations(t *testing.T) {
	// Ensure spanner DDL files are syntax-correct and idempotent.
	// NewSpannerCtx already run the "up" statements, so we start with "down".
	c := NewSpannerCtx(t)
	defer c.Close()

	up, err := loadDDLStatements("1_initialize.up.sql")
	require.NoError(t, err)
	down, err := loadDDLStatements("1_initialize.down.sql")
	require.NoError(t, err)

	require.NoError(t, executeSpannerDDL(c.ctx, down))
	require.NoError(t, executeSpannerDDL(c.ctx, up))
	require.NoError(t, executeSpannerDDL(c.ctx, down))
}

func TestAIJobs(t *testing.T) {
	c := NewSpannerCtx(t)
	defer c.Close()

	build := testBuild(1)
	c.client.UploadBuild(build)
	crash1 := testCrashWithRepro(build, 1)
	c.client.ReportCrash(crash1)
	rep := c.client.pollBug()
	_ = rep
	bug, _, _ := c.loadBug(rep.ID)

	resp, err := c.client.AIJobPoll(&dashapi.AIJobPollReq{
		Workflows: []dashapi.AIWorkflow{
			{Type: "patching", Name: "patching-baseline"},
		},
	})
	require.NoError(t, err)
	require.Equal(t, resp.ID, "")

	require.NoError(t, aiBugJobCreate(c.ctx, "patching-baseline", bug))

	resp, err = c.client.AIJobPoll(&dashapi.AIJobPollReq{
		Workflows: []dashapi.AIWorkflow{
			{Type: "patching", Name: "patching-baseline"},
		},
	})
	require.NoError(t, err)
	require.NotEqual(t, resp.ID, "")
}
