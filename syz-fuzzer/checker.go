// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"os"
	"syscall"
	"time"
	"unsafe"
)

func checkMemory() {
	checker := &Checker{
		start: time.Now(),
	}
	go func() {
		for range time.NewTicker(200 * time.Millisecond).C {
			checker.loop()
		}
	}()
}

const (
	NumPages  = 1024
	PageSize  = 4 << 10
	WordSize  = 8
	Phases    = 3
	Magic     = 0xABBA1972D15C0
	MemSize   = NumPages * PageSize
	MemWords  = MemSize / WordSize
	PageWords = PageSize / WordSize
)

type Checker struct {
	start time.Time
	iter  uint
	pages [Phases][]byte
}

func (ch *Checker) loop() {
	ch.pages[ch.iter%Phases] = ch.alloc()
	ch.check(ch.pages[(ch.iter-1)%Phases])
	ch.free(ch.pages[(ch.iter-2)%Phases])
	ch.pages[(ch.iter-2)%Phases] = nil
	ch.iter++
}

func (ch *Checker) alloc() []byte {
	mem, err := syscall.Mmap(-1, 0, MemSize, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_ANON|syscall.MAP_PRIVATE)
	if err != nil {
		ch.fail("mmap failed: %v", err)
	}
	for i := 0; i < NumPages; i++ {
		*word(mem, i*PageWords+PageWords/3) = 0
	}
	return mem
}

func (ch *Checker) check(mem []byte) {
	if mem == nil {
		return
	}
	fail := false
	for i := 0; i < MemWords; i++ {
		p := word(mem, i)
		w := *p
		if w != 0 {
			fmt.Printf("corruption: addr=%p expect=0x%X got=0x%X\n", p, 0, w)
			fail = true
		}
		*p = Magic
	}
	if fail {
		ch.fail("zero corruption")
	}
}

func (ch *Checker) free(mem []byte) {
	if mem == nil {
		return
	}
	fail := false
	for i := 0; i < MemWords; i++ {
		p := word(mem, i)
		w := *p
		if w != Magic {
			fmt.Printf("corruption: addr=%p expect=0x%X got=0x%X\n", p, Magic, w)
			fail = true
		}
	}
	if fail {
		ch.fail("magic corruption")
	}
	if err := syscall.Munmap(mem); err != nil {
		ch.fail("munmap failed: %v", err)
	}
}

func (ch *Checker) fail(msg string, args ...interface{}) {
	fmt.Printf("BUG: SDC: "+msg+"\n", args...)
	fmt.Printf("after %v\n", time.Since(ch.start))
	os.Exit(1)
}

func word(mem []byte, w int) *uint64 {
	return &(*[1e6]uint64)(unsafe.Pointer(&mem[0]))[w]
}
