// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"runtime"
	"time"

	"github.com/google/syzkaller/pkg/image"
	"github.com/google/syzkaller/pkg/stats"
)

type Stats struct {
	statCrashes       *stats.Val
	statCrashTypes    *stats.Val
	statSuppressed    *stats.Val
	statUptime        *stats.Val
	statFuzzingTime   *stats.Val
	statAvgBootTime   *stats.Val
	statCoverFiltered *stats.Val
}

func (mgr *Manager) initStats() {
	mgr.statCrashes = stats.New("crashes", "Total number of VM crashes",
		stats.Simple, stats.Prometheus("syz_crash_total"))
	mgr.statCrashTypes = stats.New("crash types", "Number of unique crashes types",
		stats.Simple, stats.NoGraph)
	mgr.statSuppressed = stats.New("suppressed", "Total number of suppressed VM crashes",
		stats.Simple, stats.Graph("crashes"))
	mgr.statFuzzingTime = stats.New("fuzzing", "Total fuzzing time in all VMs (seconds)",
		stats.NoGraph, func(v int, period time.Duration) string { return fmt.Sprintf("%v sec", v/1e9) })
	mgr.statUptime = stats.New("uptime", "Total uptime (seconds)", stats.Simple, stats.NoGraph,
		func() int {
			firstConnect := mgr.firstConnect.Load()
			if firstConnect == 0 {
				return 0
			}
			return int(time.Now().Unix() - firstConnect)
		}, func(v int, period time.Duration) string {
			return fmt.Sprintf("%v sec", v)
		})
	mgr.statAvgBootTime = stats.New("instance restart", "Average VM restart time (sec)",
		stats.NoGraph,
		func() int {
			return int(mgr.bootTime.Value().Seconds())
		},
		func(v int, _ time.Duration) string {
			return fmt.Sprintf("%v sec", v)
		})

	stats.New("heap", "Process heap size (bytes)", stats.Graph("memory"),
		func() int {
			var ms runtime.MemStats
			runtime.ReadMemStats(&ms)
			return int(ms.Alloc)
		}, func(v int, period time.Duration) string {
			return fmt.Sprintf("%v MB", v>>20)
		})
	stats.New("VM", "Process VM size (bytes)", stats.Graph("memory"),
		func() int {
			var ms runtime.MemStats
			runtime.ReadMemStats(&ms)
			return int(ms.Sys - ms.HeapReleased)
		}, func(v int, period time.Duration) string {
			return fmt.Sprintf("%v MB", v>>20)
		})
	stats.New("images memory", "Uncompressed images memory (bytes)", stats.Graph("memory"),
		func() int {
			return int(image.StatMemory.Load())
		}, func(v int, period time.Duration) string {
			return fmt.Sprintf("%v MB", v>>20)
		})
	stats.New("uncompressed images", "Total number of uncompressed images in memory",
		func() int {
			return int(image.StatImages.Load())
		})
	mgr.statCoverFiltered = stats.New("filtered coverage", "", stats.NoGraph)
}
