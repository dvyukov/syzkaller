// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"fmt"
	"math/rand"

	"github.com/google/syzkaller/pkg/corpus"
	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/pkg/rpctype"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/prog"
)

const (
	smashPrio int64 = iota + 1
	genPrio
	triagePrio
	candidatePrio
	candidateTriagePrio
)

type job interface {
	run(fuzzer *Fuzzer)
	priority() priority
}

type jobSaveID interface {
	saveID(id int64)
}

type ProgTypes int

const (
	progCandidate ProgTypes = 1 << iota
	progMinimized
	progSmashed
	progInTriage
)

type jobPriority struct {
	prio priority
}

var _ jobSaveID = new(jobPriority)

func newJobPriority(base int64) jobPriority {
	prio := append(make(priority, 0, 2), base)
	return jobPriority{prio}
}

func (jp jobPriority) priority() priority {
	return jp.prio
}

// If we prioritize execution requests only by the base priorities of their origin
// jobs, we risk letting 1000s of simultaneous jobs slowly progress in parallel.
// It's better to let same-prio jobs that were started earlier finish first.
// saveID() allows Fuzzer to attach this sub-prio at the moment of job creation.
func (jp *jobPriority) saveID(id int64) {
	jp.prio = append(jp.prio, id)
}

func genProgRequest(fuzzer *Fuzzer, rnd *rand.Rand) *Request {
	p := fuzzer.target.Generate(rnd,
		prog.RecommendedCalls,
		fuzzer.ChoiceTable())
	return &Request{
		Prog:       p,
		NeedSignal: rpctype.NewSignal,
		stat:       statGenerate,
	}
}

func mutateProgRequest(fuzzer *Fuzzer, rnd *rand.Rand) *Request {
	p := fuzzer.Config.Corpus.ChooseProgram(rnd)
	if p == nil {
		return nil
	}
	newP := p.Clone()
	newP.Mutate(rnd,
		prog.RecommendedCalls,
		fuzzer.ChoiceTable(),
		fuzzer.Config.NoMutateCalls,
		fuzzer.Config.Corpus.Programs(),
	)
	return &Request{
		Prog:       newP,
		NeedSignal: rpctype.NewSignal,
		stat:       statFuzz,
	}
}

func candidateRequest(input Candidate) *Request {
	flags := progCandidate
	if input.Minimized {
		flags |= progMinimized
	}
	if input.Smashed {
		flags |= progSmashed
	}
	return &Request{
		Prog:       input.Prog,
		NeedSignal: rpctype.NewSignal,
		stat:       statCandidate,
		flags:      flags,
	}
}

// triageJob are programs for which we noticed potential new coverage during
// first execution. But we are not sure yet if the coverage is real or not.
// During triage we understand if these programs in fact give new coverage,
// and if yes, minimize them and add to corpus.
type triageJob struct {
	p         *prog.Prog
	call      int
	info      ipc.CallInfo
	newSignal signal.Signal
	flags     ProgTypes
	jobPriority
}

func triageJobPrio(flags ProgTypes) jobPriority {
	if flags&progCandidate > 0 {
		return newJobPriority(candidateTriagePrio)
	}
	return newJobPriority(triagePrio)
}

func (job *triageJob) run(fuzzer *Fuzzer) {
	callName := fmt.Sprintf("call #%v %v", job.call, job.p.CallName(job.call))
	fuzzer.Logf(3, "triaging input for %v (new signal=%v)", callName, job.newSignal.Len())
	// Compute input coverage and non-flaky signal for minimization.
	info, stop := job.deflake(fuzzer)
	if stop || info.newStableSignal.Empty() {
		return
	}
	if job.flags&progMinimized == 0 {
		stop = job.minimize(fuzzer, info.newStableSignal)
		if stop {
			return
		}
	}
	if !fuzzer.Config.NewInputFilter(job.p.CallName(job.call)) {
		return
	}
	fuzzer.Logf(2, "added new input for %v to the corpus: %s", callName, job.p)
	if job.flags&progSmashed == 0 {
		fuzzer.startJob(&smashJob{
			p:    job.p.Clone(),
			call: job.call,
		})
	}
	input := corpus.NewInput{
		Prog:     job.p,
		Call:     job.call,
		Signal:   info.stableSignal,
		Cover:    info.cover.Serialize(),
		RawCover: info.rawCover,
	}
	fuzzer.Config.Corpus.Save(input)
}

type deflakedCover struct {
	stableSignal    signal.Signal
	newStableSignal signal.Signal
	cover           cover.Cover
	rawCover        []uint32
}

func (job *triageJob) deflake(fuzzer *Fuzzer) (info deflakedCover, stop bool) {
	const signalRuns = 3
	var notExecuted int
	for i := 0; i < signalRuns; i++ {
		result := fuzzer.exec(job, &Request{
			Prog:         job.p,
			NeedSignal:   rpctype.AllSignal,
			NeedCover:    true,
			NeedRawCover: fuzzer.Config.FetchRawCover,
			stat:         statTriage,
			flags:        progInTriage,
		})
		if result.Stop {
			stop = true
			return
		}
		if !reexecutionSuccess(result.Info, &job.info, job.call) {
			// The call was not executed or failed.
			notExecuted++
			if notExecuted >= signalRuns/2+1 {
				stop = true
				return // if happens too often, give up
			}
			continue
		}
		thisSignal, thisCover := getSignalAndCover(job.p, result.Info, job.call)
		if len(info.rawCover) == 0 && fuzzer.Config.FetchRawCover {
			info.rawCover = thisCover
		}
		if i == 0 {
			info.stableSignal = thisSignal
			info.newStableSignal = job.newSignal.Intersection(thisSignal)
		} else {
			info.stableSignal = info.stableSignal.Intersection(thisSignal)
			info.newStableSignal = info.newStableSignal.Intersection(thisSignal)
		}
		if info.newStableSignal.Empty() {
			return
		}
		info.cover.Merge(thisCover)
	}
	return
}

func (job *triageJob) minimize(fuzzer *Fuzzer, newSignal signal.Signal) (stop bool) {
	const minimizeAttempts = 3
	job.p, job.call = prog.Minimize(job.p, job.call, false,
		func(p1 *prog.Prog, call1 int) bool {
			if stop {
				return false
			}
			for i := 0; i < minimizeAttempts; i++ {
				result := fuzzer.exec(job, &Request{
					Prog:         p1,
					NeedSignal:   rpctype.AllSignal,
					SignalFilter: newSignal,
					stat:         statMinimize,
				})
				if result.Stop {
					stop = true
					return false
				}
				info := result.Info
				if !reexecutionSuccess(info, &job.info, call1) {
					// The call was not executed or failed.
					continue
				}
				thisSignal, _ := getSignalAndCover(p1, info, call1)
				if newSignal.Intersection(thisSignal).Len() == newSignal.Len() {
					return true
				}
			}
			return false
		})
	return stop
}

func reexecutionSuccess(info *ipc.ProgInfo, oldInfo *ipc.CallInfo, call int) bool {
	if info == nil || len(info.Calls) == 0 {
		return false
	}
	if call != -1 {
		// Don't minimize calls from successful to unsuccessful.
		// Successful calls are much more valuable.
		if oldInfo.Errno == 0 && info.Calls[call].Errno != 0 {
			return false
		}
		return len(info.Calls[call].Signal) != 0
	}
	return len(info.Extra.Signal) != 0
}

func getSignalAndCover(p *prog.Prog, info *ipc.ProgInfo, call int) (signal.Signal, []uint32) {
	inf := &info.Extra
	if call != -1 {
		inf = &info.Calls[call]
	}
	return signal.FromRaw(inf.Signal, signalPrio(p, inf, call)), inf.Cover
}

type smashJob struct {
	p    *prog.Prog
	call int
}

func (job *smashJob) priority() priority {
	return priority{smashPrio}
}

func (job *smashJob) run(fuzzer *Fuzzer) {
	fuzzer.Logf(2, "smashing the program %s (call=%d):", job.p, job.call)
	if fuzzer.Config.Comparisons && job.call >= 0 {
		fuzzer.startJob(newHintsJob(job.p.Clone(), job.call))
	}

	const iters = 75
	rnd := fuzzer.rand()
	for i := 0; i < iters; i++ {
		p := job.p.Clone()
		p.Mutate(rnd, prog.RecommendedCalls,
			fuzzer.ChoiceTable(),
			fuzzer.Config.NoMutateCalls,
			fuzzer.Config.Corpus.Programs())
		result := fuzzer.exec(job, &Request{
			Prog:       p,
			NeedSignal: rpctype.NewSignal,
			stat:       statSmash,
		})
		if result.Stop {
			return
		}
		if fuzzer.Config.Collide {
			result := fuzzer.exec(job, &Request{
				Prog: randomCollide(p, rnd),
				stat: statCollide,
			})
			if result.Stop {
				return
			}
		}
	}
	if fuzzer.Config.FaultInjection && job.call >= 0 {
		job.faultInjection(fuzzer)
	}
}

func randomCollide(origP *prog.Prog, rnd *rand.Rand) *prog.Prog {
	if rnd.Intn(5) == 0 {
		// Old-style collide with a 20% probability.
		p, err := prog.DoubleExecCollide(origP, rnd)
		if err == nil {
			return p
		}
	}
	if rnd.Intn(4) == 0 {
		// Duplicate random calls with a 20% probability (25% * 80%).
		p, err := prog.DupCallCollide(origP, rnd)
		if err == nil {
			return p
		}
	}
	p := prog.AssignRandomAsync(origP, rnd)
	if rnd.Intn(2) != 0 {
		prog.AssignRandomRerun(p, rnd)
	}
	return p
}

func (job *smashJob) faultInjection(fuzzer *Fuzzer) {
	for nth := 1; nth <= 100; nth++ {
		fuzzer.Logf(2, "injecting fault into call %v, step %v",
			job.call, nth)
		newProg := job.p.Clone()
		newProg.Calls[job.call].Props.FailNth = nth
		result := fuzzer.exec(job, &Request{
			Prog: job.p,
			stat: statSmash,
		})
		if result.Stop {
			return
		}
		info := result.Info
		if info != nil && len(info.Calls) > job.call &&
			info.Calls[job.call].Flags&ipc.CallFaultInjected == 0 {
			break
		}
	}
}

type hintsJob struct {
	p    *prog.Prog
	call int
}

func newHintsJob(p *prog.Prog, call int) *hintsJob {
	return &hintsJob{
		p:    p,
		call: call,
	}
}

func (job *hintsJob) priority() priority {
	return priority{smashPrio}
}

func (job *hintsJob) run(fuzzer *Fuzzer) {
	// First execute the original program to dump comparisons from KCOV.
	p := job.p
	result := fuzzer.exec(job, &Request{
		Prog:      p,
		NeedHints: true,
		stat:      statSeed,
	})
	if result.Stop || result.Info == nil {
		return
	}
	// Then mutate the initial program for every match between
	// a syscall argument and a comparison operand.
	// Execute each of such mutants to check if it gives new coverage.
	p.MutateWithHints(job.call, result.Info.Calls[job.call].Comps,
		func(p *prog.Prog) bool {
			result := fuzzer.exec(job, &Request{
				Prog:       p,
				NeedSignal: rpctype.NewSignal,
				stat:       statHint,
			})
			return !result.Stop
		})
}
