// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package rpcserver

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/prog"
)

type LocalConfig struct {
	Config
	// syz-executor binary.
	Executor string
	// Temp dir where to run executor process, it's up to the caller to clean it up if necessary.
	Dir string
	// Handle ctrl+C and exit.
	HandleInterrupts bool
	// Run executor under gdb.
	GDB bool
	// RunLocal exits when this channel is closed.
	Done           chan bool
	MachineChecked func(features flatrpc.Feature, syscalls map[*prog.Syscall]bool) queue.Source
}

func RunLocal(cfg *LocalConfig) error {
	cfg.RPC = ":0"
	cfg.VMLess = true
	cfg.PrintMachineCheck = log.V(1)
	ctx := &local{
		cfg: cfg,
	}
	serv, err := newImpl(&cfg.Config, ctx)
	if err != nil {
		return err
	}
	defer serv.Close()
	ctx.serv = serv

	bin := cfg.Executor
	args := []string{"runner", "local", "localhost", fmt.Sprint(serv.Port)}
	if cfg.GDB {
		bin = "gdb"
		args = append([]string{
			"--return-child-result",
			"--ex=handle SIGPIPE nostop",
			"--args",
			cfg.Executor,
		}, args...)
	}
	cmd := exec.Command(bin, args...)
	cmd.Dir = cfg.Dir
	if cfg.Debug || cfg.GDB {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}
	if cfg.GDB {
		cmd.Stdin = os.Stdin
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start executor: %v", err)
	}
	res := make(chan error, 1)
	go func() { res <- cmd.Wait() }()
	shutdown := make(chan struct{})
	if cfg.HandleInterrupts {
		osutil.HandleInterrupts(shutdown)
	}
	var cmdErr error
	select {
	case <-shutdown:
	case <-cfg.Done:
	case err := <-res:
		cmdErr = fmt.Errorf("executor process exited: %v", err)
	}
	if cmdErr == nil {
		cmd.Process.Kill()
		<-res
	}
	if !cfg.HandleInterrupts {
		// If the executor has crashed early, reply to all remaining requests to unblock tests.
	loop:
		for {
			req := serv.execSource.Next()
			if req == nil {
				select {
				case <-cfg.Done:
					break loop
				default:
					time.Sleep(time.Millisecond)
					continue loop
				}
			}
			req.Done(&queue.Result{Status: queue.Crashed, Err: errors.New("executor crashed")})
		}
	}
	return cmdErr
}

type local struct {
	cfg  *LocalConfig
	serv *Server
}

func (ctx *local) MachineChecked(features flatrpc.Feature, syscalls map[*prog.Syscall]bool) queue.Source {
	ctx.serv.TriagedCorpus()
	return ctx.cfg.MachineChecked(features, syscalls)
}

func (ctx *local) BugFrames() ([]string, []string) {
	return nil, nil
}

func (ctx *local) MaxSignal() signal.Signal {
	return nil
}

func (ctx *local) CoverageFilter(modules []cover.KernelModule) []uint64 {
	return nil
}
