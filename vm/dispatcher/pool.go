// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package dispatcher

import (
	"context"
	"io"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/log"
)

type Instance interface {
	io.Closer
}

type UpdateInfo func(cb func(info *Info))
type Runner[T Instance] func(ctx context.Context, inst T, updInfo UpdateInfo)
type CreateInstance[T Instance] func(int) (T, error)

// Pool[T] provides the functionality of a generic pool of instances.
// The instance is assumed to boot, be controlled by one Runner and then be re-created.
// The pool is assumed to have one default Runner (e.g. to be used for fuzzing), while a
// dynamically controlled sub-pool might be reserved for the arbitrary Runners.
type Pool[T Instance] struct {
	BootErrors chan error

	creator    CreateInstance[T]
	defaultJob Runner[T]
	jobs       chan Runner[T]

	// The mutex serializes ReserveForRun() calls.
	mu        sync.Mutex
	instances []*poolInstance[T]
}

func NewPool[T Instance](count int, creator CreateInstance[T], def Runner[T]) *Pool[T] {
	instances := make([]*poolInstance[T], count)
	for i := 0; i < count; i++ {
		inst := &poolInstance[T]{
			job: def,
			idx: i,
		}
		inst.reset(func() {})
		instances[i] = inst
	}
	return &Pool[T]{
		BootErrors: make(chan error, 16),
		creator:    creator,
		defaultJob: def,
		instances:  instances,
		jobs:       make(chan Runner[T]),
	}
}

func (p *Pool[T]) Loop(ctx context.Context) {
	var wg sync.WaitGroup
	wg.Add(len(p.instances))
	for _, inst := range p.instances {
		inst := inst
		go func() {
			for ctx.Err() == nil {
				p.runInstance(ctx, inst)
			}
			wg.Done()
		}()
	}
	wg.Wait()
}

func (p *Pool[T]) runInstance(ctx context.Context, inst *poolInstance[T]) {
	ctx, cancel := context.WithCancel(ctx)

	log.Logf(2, "pool: booting instance %d", inst.idx)

	p.mu.Lock()
	// Avoid races with ReserveForRun().
	inst.reset(cancel)
	p.mu.Unlock()

	inst.status(StateBooting)
	defer inst.status(StateOffline)

	obj, err := p.creator(inst.idx)
	if err != nil {
		p.BootErrors <- err
		return
	}
	defer obj.Close()

	inst.status(StateWaiting)
	// The job and jobChan fields are subject to concurrent updates.
	inst.mu.Lock()
	job, jobChan := inst.job, inst.jobChan
	inst.mu.Unlock()

	if job == nil {
		select {
		case newJob := <-jobChan:
			job = newJob
		case newJob := <-inst.switchToJob:
			job = newJob
		case <-ctx.Done():
			return
		}
	}

	inst.status(StateRunning)
	job(ctx, obj, inst.updateInfo)
}

// ReserveForRun specifies the size of the sub-pool for the execution of custom runners.
// The reserved instances will be booted, but the pool will not start the default runner.
// To unreserve all instances, execute ReserveForRun(0).
func (p *Pool[T]) ReserveForRun(count int) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if count > len(p.instances) {
		panic("trying to reserve more VMs than present")
	}

	var free, reserved []*poolInstance[T]
	for _, inst := range p.instances {
		if inst.reserved() {
			reserved = append(reserved, inst)
		} else {
			free = append(free, inst)
		}
	}

	needReserve := count - len(reserved)
	for i := 0; i < needReserve; i++ {
		log.Logf(2, "pool: reserving instance %d", free[i].idx)
		free[i].reserve(p.jobs)
	}

	needFree := len(reserved) - count
	for i := 0; i < needFree; i++ {
		log.Logf(2, "pool: releasing instance %d", reserved[i].idx)
		reserved[i].free(p.defaultJob)
	}
}

// Run blocks until it has found an instance to execute job and until job has finished.
func (p *Pool[T]) Run(job Runner[T]) {
	done := make(chan struct{})
	p.jobs <- func(ctx context.Context, inst T, upd UpdateInfo) {
		job(ctx, inst, upd)
		close(done)
	}
	<-done
}

func (p *Pool[T]) Total() int {
	return len(p.instances)
}

type Info struct {
	State      InstanceState
	Status     string
	LastUpdate time.Time
	Reserved   bool

	// The optional callbacks.
	MachineInfo    func() []byte
	DetailedStatus func() []byte
}

func (p *Pool[T]) State() []Info {
	p.mu.Lock()
	defer p.mu.Unlock()

	ret := make([]Info, len(p.instances))
	for i, inst := range p.instances {
		ret[i] = inst.getInfo()
	}
	return ret
}

// poolInstance is not thread safe.
type poolInstance[T Instance] struct {
	mu   sync.Mutex
	info Info
	idx  int

	// Either job or jobChan will be set.
	job         Runner[T]
	jobChan     chan Runner[T]
	switchToJob chan Runner[T]
	stop        func()
}

type InstanceState int

const (
	StateOffline InstanceState = iota
	StateBooting
	StateWaiting
	StateRunning
)

// reset() and status() may be called concurrently to all other methods.
// Other methods themselves are serialized.
func (pi *poolInstance[T]) reset(stop func()) {
	pi.mu.Lock()
	defer pi.mu.Unlock()

	pi.info = Info{
		State:      StateOffline,
		LastUpdate: time.Now(),
		Reserved:   pi.info.Reserved,
	}
	pi.stop = stop
	pi.switchToJob = make(chan Runner[T])
}

func (pi *poolInstance[T]) updateInfo(upd func(*Info)) {
	pi.mu.Lock()
	defer pi.mu.Unlock()
	upd(&pi.info)
	pi.info.LastUpdate = time.Now()
}

func (pi *poolInstance[T]) status(status InstanceState) {
	pi.updateInfo(func(info *Info) {
		info.State = status
	})
}

func (pi *poolInstance[T]) reserved() bool {
	return pi.jobChan != nil
}

func (pi *poolInstance[T]) getInfo() Info {
	pi.mu.Lock()
	defer pi.mu.Unlock()
	return pi.info
}

func (pi *poolInstance[T]) reserve(ch chan Runner[T]) {
	pi.stop()
	pi.jobChan = ch
	pi.job = nil
	pi.updateInfo(func(info *Info) {
		info.Reserved = true
	})
}

func (pi *poolInstance[T]) free(job Runner[T]) {
	pi.job = job
	pi.jobChan = nil

	pi.updateInfo(func(info *Info) {
		info.Reserved = false
	})

	select {
	case pi.switchToJob <- job:
		// Just in case the instance has been waiting.
		return
	default:
	}
}
