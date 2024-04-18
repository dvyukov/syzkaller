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
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/pkg/stats"
	"github.com/google/syzkaller/prog"
)

type Fuzzer struct {
	Stats
	Config *Config
	Cover  *Cover

	ctx    context.Context
	mu     sync.Mutex
	rnd    *rand.Rand
	target *prog.Target

	choiceTable atomic.Pointer[prog.ChoiceTable]

	nextExec  *priorityQueue[*Request]
	nextJobID atomic.Int64
}

func NewFuzzer(ctx context.Context, cfg *Config, rnd *rand.Rand,
	target *prog.Target) *Fuzzer {
	if cfg.NewInputFilter == nil {
		cfg.NewInputFilter = func(call string) bool {
			return true
		}
	}
	f := &Fuzzer{
		Stats:  newStats(),
		Config: cfg,
		Cover:  newCover(),

		ctx:    ctx,
		rnd:    rnd,
		target: target,

		nextExec: makePriorityQueue[*Request](),
	}
	f.updateChoiceTable()
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
	NewInputFilter func(call string) bool
}

type Request struct {
	Prog       *prog.Prog
	ProgData   []byte
	NeedSignal SignalType
	NeedCover  bool
	NeedHints  bool
	// If specified, the resulting signal for call SignalFilterCall
	// will include subset of it even if it's not new.
	SignalFilter     signal.Signal
	SignalFilterCall int

	// Must be called to notify that the request is finished.
	Done func(res *Result)

	// Fields that are only relevant within pkg/fuzzer.
	flags   ProgTypes
	stat    *stats.Val
	resultC chan *Result
}

type SignalType int

const (
	NoSignal  SignalType = 0 // we don't need any signal
	NewSignal                // we need the newly seen signal
	AllSignal                // we need all signal
)

type Result struct {
	Info *ipc.ProgInfo
	Stop bool
}

func (fuzzer *Fuzzer) done(req *Request, res *Result) {
	// Triage individual calls.
	// We do it before unblocking the waiting threads because
	// it may result it concurrent modification of req.Prog.
	// If we are already triaging this exact prog, this is flaky coverage.
	if req.NeedSignal != NoSignal && res.Info != nil && req.flags&progInTriage == 0 {
		for call, info := range res.Info.Calls {
			fuzzer.triageProgCall(req.Prog, &info, call, req.flags)
		}
		fuzzer.triageProgCall(req.Prog, &res.Info.Extra, -1, req.flags)
	}
	// Unblock threads that wait for the result.
	if req.resultC != nil {
		req.resultC <- res
	}
	if res.Info != nil {
		fuzzer.statExecTime.Add(int(res.Info.Elapsed.Milliseconds()))
	}
	req.stat.Add(1)
}

func (fuzzer *Fuzzer) triageProgCall(p *prog.Prog, info *ipc.CallInfo, call int, flags ProgTypes) {
	prio := signalPrio(p, info, call)
	newMaxSignal := fuzzer.Cover.addRawMaxSignal(info.Signal, prio)
	if newMaxSignal.Empty() {
		return
	}
	if !fuzzer.Config.NewInputFilter(p.CallName(call)) {
		return
	}
	fuzzer.Logf(2, "found new signal in call %d in %s", call, p)
	fuzzer.startJob(fuzzer.statJobsTriage, &triageJob{
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
	for {
		req := fuzzer.nextInput()
		if req.stat == fuzzer.statExecCandidate {
			fuzzer.StatCandidates.Add(-1)
		}
		req.Done = func(res *Result) {
			fuzzer.done(req, res)
		}
		progData, err := req.Prog.SerializeForExec()
		if err != nil {
			// It's bad if we systematically fail to serialize programs,
			// but so far we don't have a better handling than counting this.
			// This error is observed a lot on the seeded syz_mount_image calls.
			fuzzer.statExecBufferTooSmall.Add(1)
			req.Done(&Result{Stop: true})
			continue
		}
		req.ProgData = progData
		return req
	}
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

	// Either generate a new input or mutate an existing one.
	mutateRate := 0.95
	if !fuzzer.Config.Coverage {
		// If we don't have real coverage signal, generate programs
		// more frequently because fallback signal is weak.
		mutateRate = 0.5
	}
	rnd := fuzzer.rand()
	if rnd.Float64() < mutateRate {
		req := mutateProgRequest(fuzzer, rnd)
		if req != nil {
			return req
		}
	}
	return genProgRequest(fuzzer, rnd)
}

func (fuzzer *Fuzzer) startJob(stat *stats.Val, newJob job) {
	fuzzer.Logf(2, "started %T", newJob)
	if impl, ok := newJob.(jobSaveID); ok {
		// E.g. for big and slow hint jobs, we would prefer not to serialize them,
		// but rather to start them all in parallel.
		impl.saveID(-fuzzer.nextJobID.Add(1))
	}
	go func() {
		stat.Add(1)
		fuzzer.statJobs.Add(1)
		newJob.run(fuzzer)
		fuzzer.statJobs.Add(-1)
		stat.Add(-1)
	}()
}

func (fuzzer *Fuzzer) Logf(level int, msg string, args ...interface{}) {
	if fuzzer.Config.Logf == nil {
		return
	}
	fuzzer.Config.Logf(level, msg, args...)
}

func (fuzzer *Fuzzer) AddCandidates(candidates []Candidate) {
	fuzzer.StatCandidates.Add(len(candidates))
	for _, candidate := range candidates {
		fuzzer.pushExec(candidateRequest(fuzzer, candidate), priority{candidatePrio})
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
	if req.NeedHints && (req.NeedCover || req.NeedSignal != NoSignal) {
		panic("Request.NeedHints is mutually exclusive with other fields")
	}
	if req.SignalFilter != nil && req.NeedSignal != NewSignal {
		panic("SignalFilter must be used with NewSignal")
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

func (fuzzer *Fuzzer) saveInput(input corpus.NewInput) {
	size, new := fuzzer.Config.Corpus.Save(input)
	// Rebuild program choice table once in a while.
	// There were no deep ideas nor any calculations behind these numbers.
	if new && (size < 100 && size%33 == 0 || size%333 == 0) {
		fuzzer.updateChoiceTable()
	}
}

func (fuzzer *Fuzzer) updateChoiceTable() {
	progs := fuzzer.Config.Corpus.Programs()
	ct := fuzzer.target.BuildChoiceTable(progs, fuzzer.Config.EnabledCalls)
	fuzzer.choiceTable.Store(ct)
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
			fuzzer.nextExec.Len(), fuzzer.statJobs.Val(), m.Alloc/1000/1000)
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
