// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package rpcserver

import (
	"bytes"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"slices"
	"time"

	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/stats"
	"github.com/google/syzkaller/prog"
)

type Runner struct {
	source        queue.Source
	procs         int
	cover         bool
	debug         bool
	stats         *runnerStats
	stopped       bool
	finished      chan bool
	injectExec    chan<- bool
	infoc         chan chan []byte
	conn          *flatrpc.Conn
	machineInfo   []byte
	canonicalizer *cover.CanonicalizerInstance
	nextRequestID int64
	requests      map[int64]*queue.Request
	executing     map[int64]bool
	lastExec      *LastExecuting
	rnd           *rand.Rand
}

type runnerStats struct {
	statExecs              *stats.Val
	statExecRetries        *stats.Val
	statExecutorRestarts   *stats.Val
	statExecBufferTooSmall *stats.Val
	statNoExecRequests     *stats.Val
	statNoExecDuration     *stats.Val
}

func (runner *Runner) connectionLoop() error {
	var infoc chan []byte
	defer func() {
		if infoc != nil {
			infoc <- []byte("VM has crashed")
		}
	}()
	for {
		if infoc == nil {
			select {
			case infoc = <-runner.infoc:
				msg := &flatrpc.HostMessage{
					Msg: &flatrpc.HostMessages{
						Type:  flatrpc.HostMessagesRawStateRequest,
						Value: &flatrpc.StateRequest{},
					},
				}
				if err := flatrpc.Send(runner.conn, msg); err != nil {
					return err
				}
			default:
			}
		}
		for len(runner.requests)-len(runner.executing) < 2*runner.procs {
			req := runner.source.Next()
			if req == nil {
				break
			}
			if err := runner.sendRequest(req); err != nil {
				return err
			}
		}
		if len(runner.requests) == 0 {
			// The runner has not requests at all, so don't wait to receive anything from it.
			time.Sleep(10 * time.Millisecond)
			continue
		}
		raw, err := flatrpc.Recv[*flatrpc.ExecutorMessageRaw](runner.conn)
		if err != nil {
			return err
		}
		if raw.Msg == nil || raw.Msg.Value == nil {
			return errors.New("received no message")
		}
		switch msg := raw.Msg.Value.(type) {
		case *flatrpc.ExecutingMessage:
			err = runner.handleExecutingMessage(msg)
		case *flatrpc.ExecResult:
			err = runner.handleExecResult(msg)
		case *flatrpc.StateResult:
			if infoc != nil {
				buf := new(bytes.Buffer)
				fmt.Fprintf(buf, "pending requests on the VM:")
				for id := range runner.requests {
					fmt.Fprintf(buf, " %v", id)
				}
				fmt.Fprintf(buf, "\n\n")
				infoc <- append(buf.Bytes(), msg.Data...)
				infoc = nil
			}
		default:
			return fmt.Errorf("received unknown message type %T", msg)
		}
		if err != nil {
			return err
		}
	}
}

func (runner *Runner) sendRequest(req *queue.Request) error {
	if err := req.Validate(); err != nil {
		panic(err)
	}
	runner.nextRequestID++
	id := runner.nextRequestID
	var flags flatrpc.RequestFlag
	if req.ReturnOutput {
		flags |= flatrpc.RequestFlagReturnOutput
	}
	if req.ReturnError {
		flags |= flatrpc.RequestFlagReturnError
	}
	allSignal := make([]int32, len(req.ReturnAllSignal))
	for i, call := range req.ReturnAllSignal {
		allSignal[i] = int32(call)
	}
	// Do not let too much state accumulate.
	const restartIn = 600
	resetFlags := flatrpc.ExecFlagCollectSignal | flatrpc.ExecFlagCollectCover | flatrpc.ExecFlagCollectComps
	opts := req.ExecOpts
	if req.ExecOpts.ExecFlags&resetFlags != 0 && runner.rnd.Intn(restartIn) == 0 {
		opts.EnvFlags |= flatrpc.ExecEnvResetState
	}
	if runner.debug {
		opts.EnvFlags |= flatrpc.ExecEnvDebug
	}
	var data []byte
	if req.BinaryFile == "" {
		progData, err := req.Prog.SerializeForExec()
		if err != nil {
			// It's bad if we systematically fail to serialize programs,
			// but so far we don't have a better handling than counting this.
			// This error is observed a lot on the seeded syz_mount_image calls.
			runner.stats.statExecBufferTooSmall.Add(1)
			req.Done(&queue.Result{Status: queue.ExecFailure})
			return nil
		}
		data = progData
	} else {
		flags |= flatrpc.RequestFlagIsBinary
		fileData, err := os.ReadFile(req.BinaryFile)
		if err != nil {
			req.Done(&queue.Result{
				Status: queue.ExecFailure,
				Err:    err,
			})
			return nil
		}
		data = fileData
	}
	msg := &flatrpc.HostMessage{
		Msg: &flatrpc.HostMessages{
			Type: flatrpc.HostMessagesRawExecRequest,
			Value: &flatrpc.ExecRequest{
				Id:        id,
				ProgData:  data,
				Flags:     flags,
				ExecOpts:  &opts,
				AllSignal: allSignal,
			},
		},
	}
	runner.requests[id] = req
	return flatrpc.Send(runner.conn, msg)
}

func (runner *Runner) handleExecutingMessage(msg *flatrpc.ExecutingMessage) error {
	req := runner.requests[msg.Id]
	if req == nil {
		return fmt.Errorf("can't find executing request %v", msg.Id)
	}
	proc := int(msg.ProcId)
	if proc < 0 || proc >= runner.procs {
		return fmt.Errorf("got bad proc id %v", proc)
	}
	runner.stats.statExecs.Add(1)
	if msg.Try == 0 {
		if msg.WaitDuration != 0 {
			runner.stats.statNoExecRequests.Add(1)
			// Cap wait duration to 1 second to avoid extreme peaks on the graph
			// which make it impossible to see real data (the rest becomes a flat line).
			runner.stats.statNoExecDuration.Add(int(min(msg.WaitDuration, 1e9)))
		}
	} else {
		runner.stats.statExecRetries.Add(1)
	}
	runner.lastExec.Note(int(msg.Id), proc, req.Prog.Serialize(), osutil.MonotonicNano())
	select {
	case runner.injectExec <- true:
	default:
	}
	runner.executing[msg.Id] = true
	return nil
}

func (runner *Runner) handleExecResult(msg *flatrpc.ExecResult) error {
	req := runner.requests[msg.Id]
	if req == nil {
		return fmt.Errorf("can't find executed request %v", msg.Id)
	}
	delete(runner.requests, msg.Id)
	delete(runner.executing, msg.Id)
	if msg.Info != nil {
		for len(msg.Info.Calls) < len(req.Prog.Calls) {
			msg.Info.Calls = append(msg.Info.Calls, &flatrpc.CallInfo{
				Error: 999,
			})
		}
		msg.Info.Calls = msg.Info.Calls[:len(req.Prog.Calls)]
		if msg.Info.Freshness == 0 {
			runner.stats.statExecutorRestarts.Add(1)
		}
		if !runner.cover && req.ExecOpts.ExecFlags&flatrpc.ExecFlagCollectSignal != 0 {
			// Coverage collection is disabled, but signal was requested => use a substitute signal.
			addFallbackSignal(req.Prog, msg.Info)
		}
		for i := 0; i < len(msg.Info.Calls); i++ {
			call := msg.Info.Calls[i]
			call.Cover = runner.canonicalizer.Canonicalize(call.Cover)
			call.Signal = runner.canonicalizer.Canonicalize(call.Signal)
		}
		if len(msg.Info.ExtraRaw) != 0 {
			msg.Info.Extra = msg.Info.ExtraRaw[0]
			for _, info := range msg.Info.ExtraRaw[1:] {
				// All processing in the fuzzer later will convert signal/cover to maps and dedup,
				// so there is little point in deduping here.
				msg.Info.Extra.Cover = append(msg.Info.Extra.Cover, info.Cover...)
				msg.Info.Extra.Signal = append(msg.Info.Extra.Signal, info.Signal...)
			}
			msg.Info.Extra.Cover = runner.canonicalizer.Canonicalize(msg.Info.Extra.Cover)
			msg.Info.Extra.Signal = runner.canonicalizer.Canonicalize(msg.Info.Extra.Signal)
			msg.Info.ExtraRaw = nil
		}
	}
	status := queue.Success
	var resErr error
	if msg.Error != "" {
		status = queue.ExecFailure
		resErr = errors.New(msg.Error)
	}
	req.Done(&queue.Result{
		Status: status,
		Info:   msg.Info,
		Output: slices.Clone(msg.Output),
		Err:    resErr,
	})
	return nil
}

func (runner *Runner) sendSignalUpdate(plus []uint64) error {
	msg := &flatrpc.HostMessage{
		Msg: &flatrpc.HostMessages{
			Type: flatrpc.HostMessagesRawSignalUpdate,
			Value: &flatrpc.SignalUpdate{
				NewMax: runner.canonicalizer.Decanonicalize(plus),
			},
		},
	}
	return flatrpc.Send(runner.conn, msg)
}

func (runner *Runner) sendStartLeakChecks() error {
	msg := &flatrpc.HostMessage{
		Msg: &flatrpc.HostMessages{
			Type:  flatrpc.HostMessagesRawStartLeakChecks,
			Value: &flatrpc.StartLeakChecks{},
		},
	}
	return flatrpc.Send(runner.conn, msg)
}

func (runner *Runner) shutdown(crashed bool) ([]ExecRecord, []byte) {
	if runner.conn != nil {
		// Wait for the connection goroutine to finish and stop touching data.
		// If conn is nil before we removed the runner, then it won't touch anything.
		<-runner.finished
	}
	for id, req := range runner.requests {
		status := queue.Restarted
		if crashed && runner.executing[id] {
			status = queue.Crashed
		}
		req.Done(&queue.Result{Status: status})
	}
	return runner.lastExec.Collect(), runner.machineInfo
}

func (runner *Runner) queryStatus() []byte {
	resc := make(chan []byte, 1)
	timeout := time.After(time.Minute)
	select {
	case runner.infoc <- resc:
	case <-timeout:
		return []byte("VM loop is not responding")
	}
	select {
	case res := <-resc:
		return res
	case <-timeout:
		return []byte("VM is not responding")
	}
}

// addFallbackSignal computes simple fallback signal in cases we don't have real coverage signal.
// We use syscall number or-ed with returned errno value as signal.
// At least this gives us all combinations of syscall+errno.
func addFallbackSignal(p *prog.Prog, info *flatrpc.ProgInfo) {
	callInfos := make([]prog.CallInfo, len(info.Calls))
	for i, inf := range info.Calls {
		if inf.Flags&flatrpc.CallFlagExecuted != 0 {
			callInfos[i].Flags |= prog.CallExecuted
		}
		if inf.Flags&flatrpc.CallFlagFinished != 0 {
			callInfos[i].Flags |= prog.CallFinished
		}
		if inf.Flags&flatrpc.CallFlagBlocked != 0 {
			callInfos[i].Flags |= prog.CallBlocked
		}
		callInfos[i].Errno = int(inf.Error)
	}
	p.FallbackSignal(callInfos)
	for i, inf := range callInfos {
		info.Calls[i].Signal = inf.Signal
	}
}
