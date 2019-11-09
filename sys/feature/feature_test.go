// Copyright 2019 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package feature

import (
	"testing"
)

func TestSimplify(t *testing.T) {
	//!!!
	/*
		opts := csource.Options{
			Threaded:     true,
			Collide:      true,
			Repeat:       true,
			Procs:        10,
			Sandbox:      "namespace",
			NetInjection: true,
			NetDevices:   true,
			NetReset:     true,
			Cgroups:      true,
			UseTmpDir:    true,
			HandleSegv:   true,
			Repro:        true,
		}
		var check func(opts csource.Options, i int)
		check = func(opts csource.Options, i int) {
			if err := opts.Check("linux"); err != nil {
				t.Fatalf("opts are invalid: %v", err)
			}
			if i == len(cSimplifies) {
				return
			}
			check(opts, i+1)
			if cSimplifies[i](&opts) {
				check(opts, i+1)
			}
		}
		check(opts, 0)
	*/
}
