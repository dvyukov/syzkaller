// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build !generate

package feature

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

/*
var (
	flagsInited   = false
	flagFeatures  string
	flagExecutor  string
	flagProcs     int
	flagFaultCall int
	flagFaultNth  int
	flagSandbox  string
	flagCoverage bool

)
*/

func AddFlags(fs *flag.FlagSet) {
	/*
	   -       flagThreaded = flag.Bool("threaded", true, "use threaded mode in executor")
	   -       flagCollide  = flag.Bool("collide", true, "collide syscalls to provoke data races")
	   -       flagDebug    = flag.Bool("debug", false, "debug output from executor")
	*/
	fs.String("executor", "./syz-executor", "path to executor binary")
	fs.String("features", "", "comma-delimited list of features to enable/disable (see below)")
	fs.Int("procs", 1, "number of parallel test processes")
	fs.Int("fault_call", -1, "inject fault into this call (0-based)")
	fs.Int("fault_nth", 0, "inject fault on n-th operation (0-based)")
	// These are legacy flags for features, but some cross-binary interfaces depend on them.
	// We can't simply remove them because they are used during bisection/patch testing with old binaries.
	fs.String("sandbox", "none", "sandbox for fuzzing (none/setuid/namespace/android)")
	fs.Bool("cover", false, "collect feedback signals (coverage)")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage of %v:\n", filepath.Base(os.Args[0]))
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "list of features (use \"-name\" to disable):\n")
		fmt.Fprintf(os.Stderr, "%-18v enable all features\n", "all")
		for _, feat := range All {
			fmt.Fprintf(os.Stderr, "%-18v %v\n", feat.CppName, feat.Desc)
		}
	}
}

func DefaultFlags() *flag.FlagSet {
	fs := flag.NewFlagSet("default", flag.ExitOnError)
	AddFlags(fs)
	fs.Parse(nil)
	return fs
}

func (set *Set) ApplyFlags(fs *flag.FlagSet) error {
	if !fs.Parsed() {
		return fmt.Errorf("feature flags are not parsed")
	}
	/*
		set.Executor = flagExecutor
		set.Procs = flagProcs
		// By default we enable all features that are present (except few).
		for _, feat := range set.All {
			*feat.Enabled = !feat.Explicit
		}
		// And sandbox requires special handling.
		for _, id := range sandboxes {
			*set.All[id].Enabled = false
		}
		id, ok := sandboxes[flagSandbox]
		if !ok {
			return fmt.Errorf("unknown sandbox %v", flagSandbox)
		}
		*set.All[id].Enabled = true
		//!!! some features depend on sandbox, so we may need to disable some here
		// (e.g. NetReset on -setuid, lots depend on -empty).
	*/

	flags := fs.Lookup("features").Value.(flag.Getter).Get().(string)
	/*
		if flagCoverage {
			flags = "coverage," + flags
		}
	*/

	// Now apply the features flag.
	index := make(map[string]ID)
	indexFlag := make(map[string]ID)
	for _, feat := range All {
		index[feat.Name] = feat.ID
		indexFlag[feat.CppName] = feat.ID
	}
	for _, name := range strings.Split(flags, ",") {
		if name == "" {
			continue
		}
		val := true
		if name[0] == '-' {
			name = name[1:]
			val = false
		}
		if name == "all" {
			for _, feat := range set.All {
				if feat.Present {
					*feat.Enabled = val
				}
			}
			//!!! handle sandbox
			//!!! handle debug
			continue
		}
		id, ok := indexFlag[name]
		if !ok {
			return fmt.Errorf("unknown feature %v in features flag", name)
		}
		feat := set.All[id]
		//if !feat.Supported {}
		*feat.Enabled = val
		if !val {
			//!!! may need to run this multiple times if there is a transitive chain of deps.
			for _, feat1 := range set.All {
				for _, dep := range feat1.Deps {
					if dep == feat.Name {
						*feat1.Enabled = false
					}
				}
			}
		}
	}
	/*
		if flagFaultCall >= 0 {
			set.Fault = true
			set.FaultCall = flagFaultCall
			set.FaultNth = flagFaultNth
		}
	*/
	if set.Coverage && set.All[ExtraCoverage].Present {
		set.ExtraCoverage = true
	}
	return set.Check()
}

// Legacy sandbox names.
var sandboxes = map[string]ID{
	"":          SandboxEmpty,
	"none":      SandboxNone,
	"setuid":    SandboxSetuid,
	"namespace": SandboxNamespace,
	"android":   SandboxAndroid,
}

func (set *Set) Sandbox() string {
	for name, id := range sandboxes {
		if *set.All[id].Enabled {
			return name
		}
	}
	panic("no sandbox is enabled")
}

/*
func (set *Set) setSandbox(name string) error {
	for _, id := range sandboxes {
		*set.All[id].Enabled = false
	}
	if id, ok := sandboxes[name]; !ok {
		return fmt.Errorf("unknown sandbox %v", name)
	} else {
		*set.All[id].Enabled = true
	}
	return l.Check()
}
*/
