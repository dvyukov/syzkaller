// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

//go:generate rm -f enum.go
//go:generate go run -tags=generate gen.go

package feature

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/google/syzkaller/sys/targets"
)

type ID int

type Feature struct {
	ID       ID
	Name     string
	Desc     string
	Explicit bool // needs to be enabled explicitly (disabled by default)

	//!!! check names
	Deps []string

	// List of OSes that support this feature (all if empty).
	OS []string

	NeedSetup bool
	CppName   string
	MacroName string

	Supported bool
	Present   bool
	Enabled   *bool
	Reason    string
}

var All = []Feature{
	// Program execution modes.
	{
		Name:     "Debug",
		Desc:     "debug mode with verbose output",
		Explicit: true,
	},
	{
		Name: "Threaded",
		Desc: "threaded program execution: use multiple threads to mitigate blocked syscalls",
	},
	{
		Name: "Collide",
		Desc: "collide syscalls during program execution to provoke data races",
		Deps: []string{"Threaded"},
	},
	{
		Name: "Repeat",
		Desc: "repeat program multiple times",
		// We don't want to remove close_fds() call when repeat is enabled,
		// since thaExplicitt can lead to deadlocks, see executor/common_linux.h.
		Deps: []string{"CloseFDs"},
	},
	{
		Name: "MultiProc",
		Desc: "execute program in multiple processes in parallel",
		Deps: []string{"Repeat"},
	},
	{
		Name: "UseTmpDir",
		Desc: "create a new temp dir for each program",
	},
	{
		Name: "HandleSegv",
		Desc: "handle and ignore sigsegv/sigbus",
	},
	// Coverage features:
	{
		Name:     "Coverage",
		Desc:     "collect and use code coverage (feedback signal)",
		OS:       []string{"linux", "freebsd", "netbsd", "openbsd"},
		Explicit: true,
	},
	{
		Name:     "ExtraCoverage",
		Desc:     "extra coverage",
		OS:       []string{"linux"},
		Deps:     []string{"Coverage"},
		Explicit: true,
	},
	{
		Name:     "Comparisons",
		Desc:     "comparison tracing",
		OS:       []string{"linux", "freebsd", "netbsd", "openbsd"},
		Deps:     []string{"Coverage"},
		Explicit: true,
	},
	{
		Name:     "RawCoverage",
		Desc:     "collect raw covered PCs for coverage reports",
		OS:       []string{"linux", "freebsd", "netbsd", "openbsd"},
		Deps:     []string{"Coverage"},
		Explicit: true,
	},
	{
		Name:     "TraceCoverage",
		Desc:     "collect raw trace of covered PCs (don't deduplicate)",
		OS:       []string{"linux", "freebsd", "netbsd", "openbsd"},
		Deps:     []string{"RawCoverage"},
		Explicit: true,
	},
	// Sandboxes:
	{
		Name: "SandboxEmpty",
		Desc: "no sandboxing at all",
		Deps: []string{"-SandboxNone", "-SandboxSetuid", "-SandboxNamespace", "-SandboxAndroid"},
	},
	{
		Name: "SandboxNone",
		Desc: "minimal and the most permissive sandbox",
		Deps: []string{"-SandboxEmpty", "-SandboxSetuid", "-SandboxNamespace", "-SandboxAndroid"},
	},
	{
		Name: "SandboxSetuid",
		Desc: "setuid sandbox (impersonate user nobody)",
		OS:   []string{"linux", "freebsd", "netbsd", "openbsd"},
		Deps: []string{"-SandboxEmpty", "-SandboxNone", "-SandboxNamespace", "-SandboxAndroid"},
	},
	{
		Name: "SandboxNamespace",
		Desc: "namespace sandbox",
		OS:   []string{"linux"},
		// Requires UseTmpDir b/c it tries to create syz-tmp dir in cwd,
		// which will fail if procs>1 and on second run of the program.
		Deps: []string{"-SandboxEmpty", "-SandboxNone", "-SandboxSetuid", "-SandboxAndroid", "UseTmpDir"},
	},
	{
		Name: "SandboxAndroid",
		Desc: "android-specific sandboxing for the untrusted_app domain",
		OS:   []string{"linux"},
		Deps: []string{"-SandboxEmpty", "-SandboxNone", "-SandboxSetuid", "-SandboxNamespace"},
	},
	// Dynamic tools:
	{
		Name:      "Fault",
		Desc:      "fault injection",
		OS:        []string{"linux"},
		NeedSetup: true,
		Explicit:  true,
	},
	{
		Name:      "Leak",
		Desc:      "leak checking",
		OS:        []string{"linux"},
		NeedSetup: true,
	},
	{
		Name:      "KCSAN",
		Desc:      "concurrency sanitizer",
		OS:        []string{"linux"},
		NeedSetup: true,
	},
	// Fuzzing features:
	{
		Name: "NetInjection",
		Desc: "use /dev/net/tun for network packet injection",
		OS:   []string{"linux", "freebsd", "openbsd"},
		Deps: []string{"-SandboxEmpty"},
	},
	{
		Name: "NetDevices",
		Desc: "setup network devices for testing",
		OS:   []string{"linux"},
		Deps: []string{"-SandboxEmpty"},
	},
	{
		Name: "NetReset",
		Desc: "reset network namespace between programs",
		OS:   []string{"linux"},
		Deps: []string{"-SandboxEmpty", "-SandboxSetuid", "Repeat"},
	},
	{
		Name: "DevlinkPCI",
		Desc: "devlink PCI setup",
		OS:   []string{"linux"},
		//!!! it should depend on something too
	},
	{
		Name: "Cgroups",
		Desc: "setup cgroups for testing",
		OS:   []string{"linux"},
		Deps: []string{"-SandboxEmpty", "Repeat", "UseTmpDir"},
	},
	{
		Name: "CloseFDs",
		Desc: "close FDs at the end of each test",
		OS:   []string{"linux"},
		Deps: []string{"-SandboxEmpty"},
	},
	{
		Name:      "BinfmtMisc",
		Desc:      "setup binfmt_misc for testing",
		OS:        []string{"linux"},
		Deps:      []string{"-SandboxEmpty"},
		NeedSetup: true,
	},
}

func (feat *Feature) SupportedOn(os string) bool {
	for _, os1 := range feat.OS {
		if os == os1 {
			return true
		}
	}
	return len(feat.OS) == 0
}

func (feat *Feature) Status() string {
	if feat.Reason != "" {
		return feat.Reason
	}
	switch {
	case !feat.Supported:
		return "not supported on the OS"
	case !feat.Present:
		return "not present in the kernel"
	case !*feat.Enabled:
		return "disabled by user"
	default:
		return "enabled"
	}
}

/*
func (feat *Feature) Enable() {
	if !feat.Supported {
		panic(fmt.Sprintf("enabling unsupported feature %v", feat.Name))
	}
	*feat.Enabled = true
	feat.Reason = "enabled"
}
*/

func init() {
	for i := range All {
		feat := &All[i]
		feat.ID = ID(i)
		feat.CppName = cppName(feat.Name)
		feat.MacroName = strings.ToUpper(feat.CppName)
		for _, os := range feat.OS {
			if _, ok := targets.List[os]; !ok {
				panic(fmt.Sprintf("Meta[%v]: unknown OS %v", feat.Name, os))
			}
		}
	}
}

func cppName(name string) string {
	var res []byte
	for i := range name {
		c := rune(name[i])
		if unicode.IsUpper(c) && i != 0 && !unicode.IsUpper(rune(name[i-1])) {
			res = append(res, '_')
		}
		res = append(res, byte(unicode.ToLower(c)))
	}
	return string(res)
}
