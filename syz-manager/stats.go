// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	//"sync"
	"sync/atomic"

	//"github.com/prometheus/client_golang/prometheus"
	//"github.com/prometheus/client_golang/prometheus/promauto"
)

type Stat uint64

type Stats struct {
	//crashes         Stat
	crashTypes      Stat
	crashSuppressed Stat
	//vmRestarts               Stat
	//newInputs Stat
	//execTotal                Stat
	//execTotal *stats.Val
	//rpcTraffic               Stat
	//rpcExchangeCalls         *stats.Value[int]
	//rpcExchangeProgs         *stats.Value[int]
	//rpcExchangeServerLatency *stats.Value[time.Duration]
	//rpcExchangeClientLatency *stats.Value[time.Duration]
	/*
		hubSendProgAdd   Stat
		hubSendProgDel   Stat
		hubSendRepro     Stat
		hubRecvProg      Stat
		hubRecvProgDrop  Stat
		hubRecvRepro     Stat
		hubRecvReproDrop Stat
	*/
	//corpusCover         Stat
	//corpusCoverFiltered Stat
	//corpusSignal        Stat
	//maxSignal           Stat
	//triageQueueLen      Stat
	//fuzzerJobs               Stat

}

func (s *Stat) get() uint64 {
	return atomic.LoadUint64((*uint64)(s))
}

func (s *Stat) inc() {
	s.add(1)
}

func (s *Stat) add(v int) {
	atomic.AddUint64((*uint64)(s), uint64(v))
}

func (s *Stat) set(v int) {
	atomic.StoreUint64((*uint64)(s), uint64(v))
}
