// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package probe

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/rpcserver"
	"github.com/google/syzkaller/vm"
)

type Info struct {
	Files []File
}

type File struct {
	Name  string
	Ioctl *Func
}

type Func struct {
	Name string
	File string
}

func Run(cfg *mgrconfig.Config) (*Info, error) {
	vmPool, err := vm.Create(cfg, false)
	if err != nil {
		return nil, fmt.Errorf("failed to create VM pool: %w", err)
	}
	defer vmPool.Close()
	ctx, cancel := context.WithCancelCause(context.Background())
	mgr := manager{
		info: &Info{},
		//ctx: ctx,
		cancel: cancel,
		vmPool: vmPool,
	}
	mgr.serv, err = rpcserver.New(cfg, mgr, rpcserver.NewStats(), false)
	if err != nil {
		return nil, fmt.Errorf("failed to create rpc server: %w", err)
	}
	if err := mgr.serv.Listen(); err != nil {
		return nil, fmt.Errorf("failed to start rpc server: %w", err)
	}

	mgr.pool = vm.NewDispatcher(vmPool, mgr.instance)
	go func() {
		for err := range mgr.pool.BootErrors {
			cancel(err)
		}
	}()
	mgr.pool.Loop(ctx)
	if err := context.Cause(ctx); err != errDone {
		return nil, err
	}
	return mgr.info, err
}

type manager struct {
	info *Info
	cancel context.CancelCauseFunc
	serv *rpcserver.Server
	vmPool *vm.Pool
	pool   *vm.Dispatcher
}

var errDone = errors.New("finished")

func (mgr *manager) instance(ctx context.Context, inst *vm.Instance, _ vm.UpdateInfo) {
	fwdAddr, err := inst.Forward(port)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to setup port forwarding: %w", err)
	}
	host, port, err := net.SplitHostPort(fwdAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse manager's address")
	}

	// If ExecutorBin is provided, it means that syz-executor is already in the image,
	// so no need to copy it.
	executorBin := cfg.SysTarget.ExecutorBin
	if executorBin == "" {
		executorBin, err = inst.Copy(cfg.ExecutorBin)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to copy binary: %w", err)
		}
	}

	// Run the fuzzer binary.
	start := time.Now()
	cmd := fmt.Sprintf("%v runner %v %v %v", executorBin, inst.Index(), host, port)
	_, rep, err := inst.Run(cfg.Timeouts.VMRunningTime, mgr.reporter, cmd,
		vm.ExitTimeout, vm.StopContext(ctx), vm.InjectExecuting(injectExec),
		finishCb,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to run fuzzer: %w", err)
	}
	if rep == nil {
		// This is the only "OK" outcome.
		log.Logf(0, "VM %v: running for %v, restarting", inst.Index(), time.Since(start))
		return nil, nil, nil
	}
	vmInfo, err := inst.Info()
	if err != nil {
		vmInfo = []byte(fmt.Sprintf("error getting VM info: %v\n", err))
	}
	return rep, vmInfo, nil
		
	//mgr.cancel(errDone)
}
