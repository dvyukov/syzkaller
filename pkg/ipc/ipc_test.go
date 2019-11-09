// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package ipc

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/host"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
	"github.com/google/syzkaller/sys/feature"
)

const timeout = 10 * time.Second

func buildExecutor(t *testing.T, target *prog.Target) string {
	src := filepath.FromSlash("../../executor/executor.cc")
	bin, err := csource.BuildFile(target, src)
	if err != nil {
		t.Fatal(err)
	}
	return bin
}

func initTest(t *testing.T) (*prog.Target, *feature.Set, func()) {
	t.Parallel()
	target, err := prog.GetTarget(runtime.GOOS, runtime.GOARCH)
	if err != nil {
		t.Fatal(err)
	}
	features, err := host.Check(target, feature.DefaultFlags())
	if err != nil {
		t.Fatal(err)
	}
	features.Executor = buildExecutor(t, target)
	cleanup := func() {
		os.Remove(features.Executor)
	}
	return target, features, cleanup
}

// TestExecutor runs all internal executor unit tests.
// We do it here because we already build executor binary here.
func TestExecutor(t *testing.T) {
	target, err := prog.GetTarget(runtime.GOOS, runtime.GOARCH)
	if err != nil {
		t.Fatal(err)
	}
	bin := buildExecutor(t, target)
	defer os.Remove(bin)
	output, err := osutil.RunCmd(time.Minute, "", bin, "test")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("executor output:\n%s", output)
}

func TestExecute(t *testing.T) {
	target, features0, cleanup := initTest(t)
	defer cleanup()

	for mode := 0; mode < 3; mode++ {
		t.Logf("testing mode %v\n", mode)
		features := features0.Copy()
		switch mode {
		case 0:
		case 1:
			features.Collide = false
		case 2:
			features.Threaded = false
			features.Collide = false
		default:
			panic("bad")
		}
		env, err := MakeEnv(target, 0)
		if err != nil {
			t.Fatalf("failed to create env: %v", err)
		}
		defer env.Close()

		for i := 0; i < 10; i++ {
			p := target.GenerateSimpleProg()
			output, info, hanged, err := env.Exec(features, p)
			if err != nil {
				t.Fatalf("failed to run executor: %v", err)
			}
			if hanged {
				t.Fatalf("program hanged:\n%s", output)
			}
			if len(info.Calls) == 0 {
				t.Fatalf("no calls executed:\n%s", output)
			}
			if info.Calls[0].Errno != 0 {
				t.Fatalf("simple call failed: %v\n%s", info.Calls[0].Errno, output)
			}
			if len(output) != 0 {
				t.Fatalf("output on empty program")
			}
		}
	}
}

func TestParallel(t *testing.T) {
	target, features, cleanup := initTest(t)
	defer cleanup()

	const P = 10
	errs := make(chan error, P)
	for p := 0; p < P; p++ {
		p := p
		go func() {
			env, err := MakeEnv(target, p)
			if err != nil {
				errs <- fmt.Errorf("failed to create env: %v", err)
				return
			}
			defer func() {
				env.Close()
				errs <- err
			}()
			p := target.GenerateSimpleProg()
			output, info, hanged, err := env.Exec(features, p)
			if err != nil {
				err = fmt.Errorf("failed to run executor: %v", err)
				return
			}
			if hanged {
				err = fmt.Errorf("program hanged:\n%s", output)
				return
			}
			if len(info.Calls) == 0 {
				err = fmt.Errorf("no calls executed:\n%s", output)
				return
			}
			if info.Calls[0].Errno != 0 {
				err = fmt.Errorf("simple call failed: %v\n%s", info.Calls[0].Errno, output)
				return
			}
			if len(output) != 0 {
				err = fmt.Errorf("output on empty program")
				return
			}
		}()
	}
	for p := 0; p < P; p++ {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
}
