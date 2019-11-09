// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"runtime"

	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
	"github.com/google/syzkaller/sys/feature"
)

var (
	flagOS     = flag.String("os", runtime.GOOS, "target os")
	flagArch   = flag.String("arch", runtime.GOARCH, "target arch")
	flagBuild  = flag.Bool("build", false, "also build the generated program")
	flagRepeat = flag.Int("repeat", 1, "repeat program that many times (<=0 - infinitely)")
	flagProcs  = flag.Int("procs", 1, "number of parallel processes")
	flagProg   = flag.String("prog", "", "file with program to convert (required)")
	flagTrace  = flag.Bool("trace", false, "trace syscall results")
	flagStrict = flag.Bool("strict", false, "parse input program in strict mode")
)

func main() {
	feature.InitFlags()
	flag.Parse()
	if *flagProg == "" {
		flag.Usage()
		os.Exit(1)
	}
	target, err := prog.GetTarget(*flagOS, *flagArch)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v", err)
		os.Exit(1)
	}
	data, err := ioutil.ReadFile(*flagProg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read prog file: %v\n", err)
		os.Exit(1)
	}
	mode := prog.NonStrict
	if *flagStrict {
		mode = prog.Strict
	}
	p, err := target.Deserialize(data, mode)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to deserialize the program: %v\n", err)
		os.Exit(1)
	}
	features := feature.Make(target.OS)
	if err := features.ParseFlags(); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	opts := csource.Options{
		Set: features,
		//Repeat:           *flagRepeat != 1,
		RepeatTimes: *flagRepeat,
		//Procs:       *flagProcs,
		//Fault:            *flagFaultCall >= 0,
		//FaultCall: *flagFaultCall,
		//FaultNth:  *flagFaultNth,
		Repro: false,
		Trace: *flagTrace,
	}
	src, err := csource.Write(p, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to generate C source: %v\n", err)
		os.Exit(1)
	}
	if formatted, err := csource.Format(src); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
	} else {
		src = formatted
	}
	os.Stdout.Write(src)
	if !*flagBuild {
		return
	}
	bin, err := csource.Build(target, src)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to build C source: %v\n", err)
		os.Exit(1)
	}
	os.Remove(bin)
	fmt.Fprintf(os.Stderr, "binary build OK\n")
}
