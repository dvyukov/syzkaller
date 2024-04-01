// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"sync"
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

type Stat uint64

type Stats struct {
	crashes         Stat
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
	corpusCoverFiltered Stat
	//corpusSignal        Stat
	//maxSignal           Stat
	//triageQueueLen      Stat
	//fuzzerJobs               Stat

	mu         sync.Mutex
	namedStats map[string]uint64
	//haveHub    bool
}

func (mgr *Manager) initStats() {
	//mgr.stats.execTotal = stats.Create("exec total", "Total test program executions", stats.Console, stats.Rate{}, stats.Prometheus("syz_exec_total"))

	// Prometheus Instrumentation https://prometheus.io/docs/guides/go-application .
	prometheus.Register(promauto.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "syz_crash_total",
		Help: "Count of crashes during current execution of syz-manager",
	},
		func() float64 { return float64(mgr.stats.crashes.get()) },
	))
}

func (stats *Stats) all() map[string]uint64 {
	m := map[string]uint64{
		"crashes":     stats.crashes.get(),
		"crash types": stats.crashTypes.get(),
		"suppressed":  stats.crashSuppressed.get(),
		//"vm restarts":       stats.vmRestarts.get(),
		//"new inputs": stats.newInputs.get(),
		//"exec total":        stats.execTotal.get(),
		//"coverage":          stats.corpusCover.get(),
		"filtered coverage": stats.corpusCoverFiltered.get(),
		//"signal":            stats.corpusSignal.get(),
		//"max signal":        stats.maxSignal.get(),
		//"rpc traffic (MB)":  stats.rpcTraffic.get() >> 20,
		//"fuzzer jobs":       stats.fuzzerJobs.get(),
	}
	//if exchanges := stats.rpcExchangeCalls.get(); exchanges != 0 {
	//m["exchange calls"] = exchanges
	//m["exchange progs"] = uint64(float64(stats.rpcExchangeProgs.get())/float64(exchanges) + 0.5)
	//m["exchange lat server (us)"] = uint64(stats.rpcExchangeServerLatency.get().Microseconds()) / exchanges
	//m["exchange lat client (us)"] = stats.rpcExchangeClientLatency.get() / exchanges / 1e3
	//}
	/*
		if stats.haveHub {
			m["hub: send prog add"] = stats.hubSendProgAdd.get()
			m["hub: send prog del"] = stats.hubSendProgDel.get()
			m["hub: send repro"] = stats.hubSendRepro.get()
			m["hub: recv prog"] = stats.hubRecvProg.get()
			m["hub: recv prog drop"] = stats.hubRecvProgDrop.get()
			m["hub: recv repro"] = stats.hubRecvRepro.get()
			m["hub: recv repro drop"] = stats.hubRecvReproDrop.get()
		}
	*/
	stats.mu.Lock()
	defer stats.mu.Unlock()
	for k, v := range stats.namedStats {
		m[k] = v
	}
	return m
}

func (stats *Stats) mergeNamed(named map[string]uint64) {
	stats.mu.Lock()
	defer stats.mu.Unlock()
	if stats.namedStats == nil {
		stats.namedStats = make(map[string]uint64)
	}
	for k, v := range named {
		stats.namedStats[k] += v
	}
}

/*
func (stats *Stats) setNamed(named map[string]uint64) {
	stats.mu.Lock()
	defer stats.mu.Unlock()
	if stats.namedStats == nil {
		stats.namedStats = make(map[string]uint64)
	}
	for k, v := range named {
		stats.namedStats[k] = v
	}
}
*/

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
