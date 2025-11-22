// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"encoding/json"
	"flag"
	"sync"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/config"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/tool"
	"github.com/google/syzkaller/pkg/updater"
)

var (
	flagConfig        = flag.String("config", "", "config file")
	flagExitOnUpgrade = flag.Bool("exit-on-upgrade", false,
		"exit after a syz-ci upgrade is applied; otherwise syz-ci restarts")
)

type Config struct {
	DashboardAddr   string     `json:"dashboard_addr"`
	DashboardClient string     `json:"dashboard_client"` // Namespace-specific.
	DashboardKey    string     `json:"dashboard_key"`
	SyzkallerRepo   string     `json:"syzkaller_repo"`
	SyzkallerBranch string     `json:"syzkaller_branch"`
	VMs             []VMConfig `json:"vms"`
}

type VMConfig struct {
	// Same meaning as in the manager config.
	Target       string          `json:"target"`
	Image        string          `json:"image,omitempty"`
	KernelConfig string          `json:"kernel_config"`
	Type         string          `json:"type"`
	VM           json.RawMessage `json:"vm"`
}

func main() {
	defer tool.Init()()
	log.SetName("syz-agent")

	cfg := &Config{
		SyzkallerRepo:   "https://github.com/google/syzkaller.git",
		SyzkallerBranch: "master",
	}
	if err := config.LoadFile(*flagConfig, cfg); err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	dash, err := dashapi.New(cfg.DashboardClient, cfg.DashboardAddr, cfg.DashboardKey)
	if err != nil {
		log.Fatal(err)
	}

	updateTargets := make(map[updater.Target]bool)
	for _, vm := range cfg.VMs {
		os, vmarch, arch, _, _, err := mgrconfig.SplitTarget(vm.Target)
		if err != nil {
			log.Fatal(err)
		}
		updateTargets[updater.Target{
			OS:     os,
			VMArch: vmarch,
			Arch:   arch,
		}] = true
	}
	buildSem := osutil.NewSemaphore(1)
	updater, err := updater.New(&updater.Config{
		ExitOnUpdate:    *flagExitOnUpgrade,
		BuildSem:        buildSem,
		SyzkallerRepo:   cfg.SyzkallerRepo,
		SyzkallerBranch: cfg.SyzkallerBranch,
		Targets:         updateTargets,
	})
	if err != nil {
		log.Fatal(err)
	}

	updatePending := make(chan struct{})
	shutdownPending := make(chan struct{})
	osutil.HandleInterrupts(shutdownPending)
	updater.UpdateOnStart(true, updatePending, shutdownPending)

	ctx, stop := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		loop(ctx, dash, cfg.VMs)
	}()

	select {
	case <-shutdownPending:
	case <-updatePending:
	}
	stop()
	wg.Wait()

	select {
	case <-shutdownPending:
	default:
		updater.UpdateAndRestart()
	}
}
