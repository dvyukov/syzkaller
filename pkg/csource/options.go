// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package csource

import (
	"encoding/json"
	"fmt"

	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/sys/feature"
)

// Options control various aspects of source generation.
// Dashboard also provides serialized Options along with syzkaller reproducers.
type Options struct {
	*feature.Set

	RepeatTimes int `json:"repeat_times,omitempty"` // if non-0, repeat that many times
	Procs       int `json:"procs"`
	FaultCall   int `json:"fault_call,omitempty"`
	FaultNth    int `json:"fault_nth,omitempty"`

	// Generate code for use with repro package to print log messages,
	// which allows to detect hangs.
	Repro bool `json:"repro,omitempty"`
	Trace bool `json:"trace,omitempty"`
}

// Check checks if the opts combination is valid or not.
// For example, Collide without Threaded is not valid.
// Invalid combinations must not be passed to Write.
func (opts Options) Check(OS string) error {
	//!!! implement
	return nil
	/*
		switch opts.Sandbox {
		case "", sandboxNone, sandboxNamespace, sandboxSetuid, sandboxAndroid:
		default:
			return fmt.Errorf("unknown sandbox %v", opts.Sandbox)
		}
		if !opts.Threaded && opts.Collide {
			// Collide requires threaded.
			return errors.New("option Collide without Threaded")
		}
		if !opts.Repeat {
			if opts.Procs > 1 {
				// This does not affect generated code.
				return errors.New("option Procs>1 without Repeat")
			}
			if opts.EnableNetReset {
				return errors.New("option EnableNetReset without Repeat")
			}
			if opts.RepeatTimes > 1 {
				return errors.New("option RepeatTimes without Repeat")
			}
		}
		if opts.Sandbox == "" {
			if opts.EnableTun {
				return errors.New("option EnableTun without sandbox")
			}
			if opts.EnableNetDev {
				return errors.New("option EnableNetDev without sandbox")
			}
			if opts.EnableCgroups {
				return errors.New("option EnableCgroups without sandbox")
			}
			if opts.EnableBinfmtMisc {
				return errors.New("option EnableBinfmtMisc without sandbox")
			}
		}
		if opts.Sandbox == sandboxNamespace && !opts.UseTmpDir {
			// This is borken and never worked.
			// This tries to create syz-tmp dir in cwd,
			// which will fail if procs>1 and on second run of the program.
			return errors.New("option Sandbox=namespace without UseTmpDir")
		}
		if opts.EnableNetReset && (opts.Sandbox == "" || opts.Sandbox == sandboxSetuid) {
			return errors.New("option EnableNetReset without sandbox")
		}
		if opts.EnableCgroups && !opts.UseTmpDir {
			return errors.New("option EnableCgroups without UseTmpDir")
		}
		return opts.checkLinuxOnly(OS)
	*/
}

/*
func (opts Options) checkLinuxOnly(OS string) error {
	if OS == linux {
		return nil
	}
	if opts.NetInjection && !(OS == openbsd || OS == freebsd || OS == netbsd) {
		return fmt.Errorf("option NetInjection is not supported on %v", OS)
	}
	if opts.NetDevices {
		return fmt.Errorf("option NetDevices is not supported on %v", OS)
	}
	if opts.NetReset {
		return fmt.Errorf("option NetReset is not supported on %v", OS)
	}
	if opts.Cgroups {
		return fmt.Errorf("option Cgroups is not supported on %v", OS)
	}
	if opts.BinfmtMisc {
		return fmt.Errorf("option BinfmtMisc is not supported on %v", OS)
	}
	if opts.CloseFds {
		return fmt.Errorf("option CloseFds is not supported on %v", OS)
	}
	if opts.KCSAN {
		return fmt.Errorf("option KCSAN is not supported on %v", OS)
	}
	if opts.DevlinkPCI {
		return fmt.Errorf("option DevlinkPCI is not supported on %v", OS)
	}
	if opts.Sandbox == sandboxNamespace ||
		(opts.Sandbox == sandboxSetuid && !(OS == openbsd || OS == freebsd || OS == netbsd)) ||
		opts.Sandbox == sandboxAndroid {
		return fmt.Errorf("option Sandbox=%v is not supported on %v", opts.Sandbox, OS)
	}
	if opts.Fault {
		return fmt.Errorf("option Fault is not supported on %v", OS)
	}
	if opts.Leak {
		return fmt.Errorf("option Leak is not supported on %v", OS)
	}
	return nil
}
*/

func DefaultOpts(cfg *mgrconfig.Config) Options {
	opts := Options{
		//Threaded:         true,
		//Collide:          true,
		//Repeat:           true,
		Procs: cfg.Procs,
		//Sandbox:          cfg.Sandbox,
		//EnableTun:        true,
		//EnableNetDev:     true,
		//EnableNetReset:   true,
		//EnableCgroups:    true,
		//EnableBinfmtMisc: true,
		//EnableCloseFds:   true,
		//EnableDevlinkPCI: true,
		//UseTmpDir:        true,
		//HandleSegv:       true,
		Repro: true,
	}
	/*
		if cfg.TargetOS != linux {
			opts.EnableTun = false
			opts.EnableNetDev = false
			opts.EnableNetReset = false
			opts.EnableCgroups = false
			opts.EnableBinfmtMisc = false
			opts.EnableCloseFds = false
			opts.EnableDevlinkPCI = false
		}
		if cfg.Sandbox == "" || cfg.Sandbox == "setuid" {
			opts.EnableNetReset = false
		}
	*/
	if err := opts.Check(cfg.TargetOS); err != nil {
		panic(fmt.Sprintf("DefaultOpts created bad opts: %v", err))
	}
	return opts
}

func (opts Options) Serialize() []byte {
	data, err := json.Marshal(opts)
	if err != nil {
		panic(err)
	}
	return data
}

func DeserializeOptions(data []byte) (Options, error) {
	var opts Options
	//!!! implement
	return opts, nil
	/*
		// Before EnableCloseFds was added, close_fds() was always called,
		// so default to true.
		opts.EnableCloseFds = true
		if err := json.Unmarshal(data, &opts); err == nil {
			return opts, nil
		}
		// Support for legacy formats.
		data = bytes.Replace(data, []byte("Sandbox: "), []byte("Sandbox:empty "), -1)
		waitRepeat, debug := false, false
		n, err := fmt.Sscanf(string(data),
			"{Threaded:%t Collide:%t Repeat:%t Procs:%d Sandbox:%s"+
				" Fault:%t FaultCall:%d FaultNth:%d EnableTun:%t UseTmpDir:%t"+
				" HandleSegv:%t WaitRepeat:%t Debug:%t Repro:%t}",
			&opts.Threaded, &opts.Collide, &opts.Repeat, &opts.Procs, &opts.Sandbox,
			&opts.Fault, &opts.FaultCall, &opts.FaultNth, &opts.EnableTun, &opts.UseTmpDir,
			&opts.HandleSegv, &waitRepeat, &debug, &opts.Repro)
		if err == nil {
			if want := 14; n != want {
				return opts, fmt.Errorf("failed to parse repro options: got %v fields, want %v", n, want)
			}
			if opts.Sandbox == "empty" {
				opts.Sandbox = ""
			}
			return opts, nil
		}
		n, err = fmt.Sscanf(string(data),
			"{Threaded:%t Collide:%t Repeat:%t Procs:%d Sandbox:%s"+
				" Fault:%t FaultCall:%d FaultNth:%d EnableTun:%t UseTmpDir:%t"+
				" EnableCgroups:%t HandleSegv:%t WaitRepeat:%t Debug:%t Repro:%t}",
			&opts.Threaded, &opts.Collide, &opts.Repeat, &opts.Procs, &opts.Sandbox,
			&opts.Fault, &opts.FaultCall, &opts.FaultNth, &opts.EnableTun, &opts.UseTmpDir,
			&opts.EnableCgroups, &opts.HandleSegv, &waitRepeat, &debug, &opts.Repro)
		if err == nil {
			if want := 15; n != want {
				return opts, fmt.Errorf("failed to parse repro options: got %v fields, want %v", n, want)
			}
			if opts.Sandbox == "empty" {
				opts.Sandbox = ""
			}
			return opts, nil
		}

		return opts, err
	*/
}
