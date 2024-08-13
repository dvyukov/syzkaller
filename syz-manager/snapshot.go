// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"errors"
	"fmt"
	"time"

	"github.com/google/flatbuffers/go"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/vm"
)

func (mgr *Manager) snapshotLoop() {
	queue.StatNumFuzzing.Add(mgr.vmPool.Count())
	for index := 0; index < mgr.vmPool.Count(); index++ {
		index := index
		go func() {
			for {
				log.Error(mgr.snapshotVM(index))
			}
		}()
	}
	select {}
}

func (mgr *Manager) snapshotVM(index int) error {
	inst, err := mgr.vmPool.Create(index)
	if err != nil {
		return err
	}
	defer inst.Close()
	executor, err := inst.Copy(mgr.cfg.ExecutorBin)
	if err != nil {
		return err
	}
	// All network connections (including ssh) will break once we start restoring snapshots.
	// So we start a background process and log to /dev/kmsg.
	cmd := fmt.Sprintf("nohup %v exec snapshot 1>/dev/null 2>/dev/kmsg </dev/null &", executor)
	if _, _, err := inst.Run(time.Hour, mgr.reporter, cmd); err != nil {
		return err
	}

	builder := flatbuffers.NewBuilder(0)
	var envFlags flatrpc.ExecEnv
	for first := true; ; first = false {
		queue.StatExecs.Add(1)
		req := mgr.source.Next()
		if first {
			envFlags = req.ExecOpts.EnvFlags
			if err := mgr.snapshotSetup(inst, builder, envFlags); err != nil {
				req.Done(&queue.Result{Status: queue.Crashed})
				return err
			}
		}
		if envFlags != req.ExecOpts.EnvFlags {
			panic(fmt.Sprintf("request env flags has changed: 0x%x -> 0x%x",
				envFlags, req.ExecOpts.EnvFlags))
		}

		res, output, err := mgr.snapshotRun(inst, builder, req)
		if err != nil {
			req.Done(&queue.Result{Status: queue.Crashed})
			return err
		}

		if mgr.reporter.ContainsCrash(output) {
			res.Status = queue.Crashed
			rep := mgr.reporter.Parse(output)
			buf := new(bytes.Buffer)
			fmt.Fprintf(buf, "program:\n%s\n", req.Prog.Serialize())
			buf.Write(rep.Output)
			rep.Output = buf.Bytes()
			mgr.crashes <- &Crash{Report: rep}
		}

		req.Done(res)
	}
}

func (mgr *Manager) snapshotSetup(inst *vm.Instance, builder *flatbuffers.Builder, env flatrpc.ExecEnv) error {
	msg := flatrpc.SnapshotHandshakeT{
		CoverEdges:       mgr.cfg.Experimental.CoverEdges,
		Kernel64Bit:      mgr.cfg.SysTarget.PtrSize == 8,
		Slowdown:         int32(mgr.cfg.Timeouts.Slowdown),
		SyscallTimeoutMs: int32(mgr.cfg.Timeouts.Syscall / time.Millisecond),
		ProgramTimeoutMs: int32(mgr.cfg.Timeouts.Program / time.Millisecond),
		Features:         mgr.enabledFeatures,
		EnvFlags:         env,
		SandboxArg:       mgr.cfg.SandboxArg,
	}
	builder.Reset()
	builder.Finish(msg.Pack(builder))
	return inst.SetupSnapshot(builder.FinishedBytes())
}

func (mgr *Manager) snapshotRun(inst *vm.Instance, builder *flatbuffers.Builder, req *queue.Request) (
	*queue.Result, []byte, error) {
	progData, err := req.Prog.SerializeForExec()
	if err != nil {
		queue.StatExecBufferTooSmall.Add(1)
		return &queue.Result{Status: queue.ExecFailure}, nil, nil
	}
	msg := flatrpc.SnapshotRequestT{
		ExecFlags: req.ExecOpts.ExecFlags,
		NumCalls:  int32(len(req.Prog.Calls)),
		ProgData:  progData,
	}
	for _, call := range req.ReturnAllSignal {
		if call < 0 {
			msg.AllExtraSignal = true
		} else {
			msg.AllCallSignal |= 1 << call
		}
	}
	builder.Reset()
	builder.Finish(msg.Pack(builder))

	start := time.Now()
	resData, output, err := inst.RunSnapshot(builder.FinishedBytes())
	if err != nil {
		return nil, nil, err
	}
	elapsed := time.Since(start)

	res := parseExecResult(resData)
	if res.Info != nil {
		res.Info.Elapsed = uint64(elapsed)
		for len(res.Info.Calls) < len(req.Prog.Calls) {
			res.Info.Calls = append(res.Info.Calls, &flatrpc.CallInfo{
				Error: 999,
			})
		}
		res.Info.Calls = res.Info.Calls[:len(req.Prog.Calls)]
		if len(res.Info.ExtraRaw) != 0 {
			res.Info.Extra = res.Info.ExtraRaw[0]
			for _, info := range res.Info.ExtraRaw[1:] {
				res.Info.Extra.Cover = append(res.Info.Extra.Cover, info.Cover...)
				res.Info.Extra.Signal = append(res.Info.Extra.Signal, info.Signal...)
			}
			res.Info.ExtraRaw = nil
		}
	}

	ret := &queue.Result{
		Status: queue.Success,
		Info:   res.Info,
	}
	if res.Error != "" {
		ret.Status = queue.ExecFailure
		ret.Err = errors.New(res.Error)
	}
	if req.ReturnOutput {
		ret.Output = output
	}
	return ret, output, nil
}

func parseExecResult(data []byte) *flatrpc.ExecResult {
	raw, err := flatrpc.Parse[*flatrpc.ExecutorMessageRaw](data[flatbuffers.SizeUint32:])
	if err != nil {
		// Don't consider result parsing error as an infrastructure error,
		// it's just the test program corrupted memory.
		return &flatrpc.ExecResult{
			Error: err.Error(),
		}
	}
	res, ok := raw.Msg.Value.(*flatrpc.ExecResult)
	if !ok {
		return &flatrpc.ExecResult{
			Error: "result is not ExecResult",
		}
	}
	return res
}
