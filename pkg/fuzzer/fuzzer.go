// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"context"
	"fmt"
	"math/rand"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/syzkaller/pkg/corpus"
	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/pkg/rpctype"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/prog"
)

type Fuzzer struct {
	Config *Config
	Cover  *Cover

	ctx    context.Context
	mu     sync.Mutex
	stats  map[string]uint64
	rnd    *rand.Rand
	target *prog.Target

	ct           *prog.ChoiceTable
	ctProgs      int
	ctMu         sync.Mutex // TODO: use RWLock.
	ctRegenerate chan struct{}

	nextExec  *priorityQueue[*Request]
	nextJobID atomic.Int64

	nextExecFallback chan *Request

	runningJobs      atomic.Int64
	queuedCandidates atomic.Int64
}

func NewFuzzer(ctx context.Context, cfg *Config, rnd *rand.Rand,
	target *prog.Target) *Fuzzer {
	f := &Fuzzer{
		Config: cfg,
		Cover:  &Cover{},

		ctx:    ctx,
		stats:  map[string]uint64{},
		rnd:    rnd,
		target: target,

		// We're okay to lose some of the messages -- if we are already
		// regenerating the table, we don't want to repeat it right away.
		ctRegenerate: make(chan struct{}),

		nextExec:         makePriorityQueue[*Request](),
		nextExecFallback: make(chan *Request, 1000),
	}
	f.updateChoiceTable(nil)
	go f.choiceTableUpdater()
	go f.generateFallback()
	if cfg.Debug {
		go f.logCurrentStats()
	}
	return f
}

type Config struct {
	Debug          bool
	Corpus         *corpus.Corpus
	Logf           func(level int, msg string, args ...interface{})
	Coverage       bool
	FaultInjection bool
	Comparisons    bool
	Collide        bool
	EnabledCalls   map[*prog.Syscall]bool
	NoMutateCalls  map[int]bool
	FetchRawCover  bool
	NewInputFilter func(input *corpus.NewInput) bool
}

type Request struct {
	Prog         *prog.Prog
	NeedCover    bool
	NeedRawCover bool
	NeedSignal   rpctype.SignalType
	NeedHints    bool
	SignalFilter signal.Signal // If specified, the resulting signal MAY be a subset of it.
	// Fields that are only relevant within pkg/fuzzer.
	flags   ProgTypes
	stat    string
	result  *Result
	resultC chan *Result
}

type Result struct {
	Info *ipc.ProgInfo
	Stop bool
}

func (fuzzer *Fuzzer) Done(req *Request, res *Result) {
	// Triage individual calls.
	// We do it before unblocking the waiting threads because
	// it may result it concurrent modification of req.Prog.
	if req.NeedSignal != rpctype.NoSignal && res.Info != nil {
		for call, info := range res.Info.Calls {
			fuzzer.triageProgCall(req.Prog, &info, call, req.flags)
		}
		fuzzer.triageProgCall(req.Prog, &res.Info.Extra, -1, req.flags)
	}
	// Unblock threads that wait for the result.
	req.result = res
	if req.resultC != nil {
		req.resultC <- res
	}
	// Update stats.
	fuzzer.mu.Lock()
	fuzzer.stats[req.stat]++
	fuzzer.mu.Unlock()
}

func (fuzzer *Fuzzer) triageProgCall(p *prog.Prog, info *ipc.CallInfo, call int,
	flags ProgTypes) {
	prio := signalPrio(p, info, call)
	newMaxSignal := fuzzer.Cover.addRawMaxSignal(info.Signal, prio)
	if newMaxSignal.Empty() {
		return
	}
	if flags&progInTriage > 0 {
		// We are already triaging this exact prog.
		// All newly found coverage is flaky.
		fuzzer.Logf(2, "found new flaky signal in call %d in %s", call, p)
		return
	}
	fuzzer.Logf(2, "found new signal in call %d in %s", call, p)
	fuzzer.startJob(&triageJob{
		p:           p.Clone(),
		call:        call,
		info:        *info,
		newSignal:   newMaxSignal,
		flags:       flags,
		jobPriority: triageJobPrio(flags),
	})
}

func signalPrio(p *prog.Prog, info *ipc.CallInfo, call int) (prio uint8) {
	if call == -1 {
		return 0
	}
	if info.Errno == 0 {
		prio |= 1 << 1
	}
	if !p.Target.CallContainsAny(p.Calls[call]) {
		prio |= 1 << 0
	}
	return
}

type Candidate struct {
	Prog      *prog.Prog
	Smashed   bool
	Minimized bool
}

func (fuzzer *Fuzzer) NextInput() *Request {
	req := fuzzer.nextInput()
	if req.stat == statCandidate {
		if fuzzer.queuedCandidates.Add(-1) < 0 {
			panic("queuedCandidates is out of sync")
		}
	}
	return req
}

func (fuzzer *Fuzzer) nextInput() *Request {
	nextExec := fuzzer.nextExec.tryPop()

	// The fuzzer may become too interested in potentially very long hint and smash jobs.
	// Let's leave more space for new input space exploration.
	if nextExec != nil {
		if nextExec.prio.greaterThan(priority{smashPrio}) || fuzzer.nextRand()%3 != 0 {
			return nextExec.value
		} else {
			fuzzer.nextExec.push(nextExec)
		}
	}

	select {
	case r := <-fuzzer.nextExecFallback:
		return r
	default:
		return fuzzer.nextInputFallback(fuzzer.rand())
	}
}

func (fuzzer *Fuzzer) nextInputFallback(rnd *rand.Rand) *Request {
	// Either generate a new input or mutate an existing one.
	mutateRate := 0.95
	if !fuzzer.Config.Coverage {
		// If we don't have real coverage signal, generate programs
		// more frequently because fallback signal is weak.
		mutateRate = 0.5
	}
	if rnd.Float64() < mutateRate {
		req := mutateProgRequest(fuzzer, rnd)
		if req != nil {
			return req
		}
	}
	return genProgRequest(fuzzer, rnd)
}

func (fuzzer *Fuzzer) generateFallback() {
	rnd := fuzzer.rand()
	for {
		select {
		case fuzzer.nextExecFallback <- fuzzer.nextInputFallback(rnd):
		case <-fuzzer.ctx.Done():
			return
		}
	}
}

func (fuzzer *Fuzzer) startJob(newJob job) {
	fuzzer.Logf(2, "started %T", newJob)
	if impl, ok := newJob.(jobSaveID); ok {
		// E.g. for big and slow hint jobs, we would prefer not to serialize them,
		// but rather to start them all in parallel.
		impl.saveID(-fuzzer.nextJobID.Add(1))
	}
	go func() {
		fuzzer.runningJobs.Add(1)
		newJob.run(fuzzer)
		fuzzer.runningJobs.Add(-1)
	}()
}

func (fuzzer *Fuzzer) Logf(level int, msg string, args ...interface{}) {
	if fuzzer.Config.Logf == nil {
		return
	}
	fuzzer.Config.Logf(level, msg, args...)
}

func (fuzzer *Fuzzer) AddCandidates(candidates []Candidate) {
	fuzzer.queuedCandidates.Add(int64(len(candidates)))
	for _, candidate := range candidates {
		fuzzer.pushExec(candidateRequest(candidate), priority{candidatePrio})
	}
}

func (fuzzer *Fuzzer) rand() *rand.Rand {
	return rand.New(rand.NewSource(fuzzer.nextRand()))
}

func (fuzzer *Fuzzer) nextRand() int64 {
	fuzzer.mu.Lock()
	defer fuzzer.mu.Unlock()
	return fuzzer.rnd.Int63()
}

func (fuzzer *Fuzzer) pushExec(req *Request, prio priority) {
	if req.stat == "" {
		panic("Request.Stat field must be set")
	}
	if req.NeedHints && (req.NeedCover || req.NeedSignal != rpctype.NoSignal) {
		panic("Request.NeedHints is mutually exclusive with other fields")
	}
	fuzzer.nextExec.push(&priorityQueueItem[*Request]{
		value: req, prio: prio,
	})
}

func (fuzzer *Fuzzer) exec(job job, req *Request) *Result {
	req.resultC = make(chan *Result, 1)
	fuzzer.pushExec(req, job.priority())
	select {
	case <-fuzzer.ctx.Done():
		return &Result{Stop: true}
	case res := <-req.resultC:
		close(req.resultC)
		return res
	}
}

func (fuzzer *Fuzzer) updateChoiceTable(programs []*prog.Prog) {
	newCt := fuzzer.target.BuildChoiceTable(programs, fuzzer.Config.EnabledCalls)

	fuzzer.ctMu.Lock()
	defer fuzzer.ctMu.Unlock()
	if len(programs) >= fuzzer.ctProgs {
		fuzzer.ctProgs = len(programs)
		fuzzer.ct = newCt
	}
}

func (fuzzer *Fuzzer) choiceTableUpdater() {
	for {
		select {
		case <-fuzzer.ctx.Done():
			return
		case <-fuzzer.ctRegenerate:
		}
		fuzzer.updateChoiceTable(fuzzer.Config.Corpus.Programs())
	}
}

func (fuzzer *Fuzzer) ChoiceTable() *prog.ChoiceTable {
	progs := fuzzer.Config.Corpus.Programs()

	fuzzer.ctMu.Lock()
	defer fuzzer.ctMu.Unlock()

	// There were no deep ideas nor any calculations behind these numbers.
	regenerateEveryProgs := 333
	if len(progs) < 100 {
		regenerateEveryProgs = 33
	}
	if fuzzer.ctProgs+regenerateEveryProgs < len(progs) {
		select {
		case fuzzer.ctRegenerate <- struct{}{}:
		default:
			// We're okay to lose the message.
			// It means that we're already regenerating the table.
		}
	}
	return fuzzer.ct
}

func (fuzzer *Fuzzer) logCurrentStats() {
	for {
		select {
		case <-time.After(time.Minute):
		case <-fuzzer.ctx.Done():
			return
		}

		var m runtime.MemStats
		runtime.ReadMemStats(&m)

		str := fmt.Sprintf("exec queue size: %d, running jobs: %d, heap (MB): %d",
			fuzzer.nextExec.Len(), fuzzer.runningJobs.Load(), m.Alloc/1000/1000)
		fuzzer.Logf(0, "%s", str)
	}
}

func (fuzzer *Fuzzer) RotateMaxSignal(items int) {
	corpusSignal := fuzzer.Config.Corpus.Signal()
	pureMaxSignal := fuzzer.Cover.pureMaxSignal(corpusSignal)
	if pureMaxSignal.Len() < items {
		items = pureMaxSignal.Len()
	}
	fuzzer.Logf(1, "rotate %d max signal elements", items)

	delta := pureMaxSignal.RandomSubset(fuzzer.rand(), items)
	fuzzer.Cover.subtract(delta)
}
