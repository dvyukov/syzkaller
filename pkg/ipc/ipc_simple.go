// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build freebsd fuchsia windows

package ipc

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/prog"
)

type Env struct {
	bin    []string
	pid    int
	config Config

	StatExecs    uint64
	StatRestarts uint64
}

func MakeEnv(bin string, pid int, config Config) (*Env, error) {
	if config.Timeout < 7*time.Second {
		config.Timeout = 7 * time.Second
	}
	env := &Env{
		bin:    strings.Split(bin, " "),
		pid:    pid,
		config: config,
	}
	if len(env.bin) == 0 {
		return nil, fmt.Errorf("binary is empty string")
	}
	if runtime.GOOS != "fuchsia" {
		env.bin[0] = osutil.Abs(env.bin[0])
		base := filepath.Base(env.bin[0])
		pidStr := fmt.Sprint(pid)
		if len(base)+len(pidStr) >= 16 {
			// TASK_COMM_LEN is currently set to 16
			base = base[:15-len(pidStr)]
		}
		binCopy := filepath.Join(filepath.Dir(env.bin[0]), base+pidStr)
		if err := os.Link(env.bin[0], binCopy); err == nil {
			env.bin[0] = binCopy
		}
	}
	return env, nil
}

func (env *Env) Close() error {
	return nil
}

func (env *Env) Exec(opts *ExecOpts, p *prog.Prog) (output []byte, info []CallInfo, failed, hanged bool, err0 error) {
	atomic.AddUint64(&env.StatExecs, 1)
	dir, err := ioutil.TempDir("./", "syzkaller-testdir")
	if err != nil {
		err0 = fmt.Errorf("failed to create temp dir: %v", err)
		return
	}
	defer os.RemoveAll(dir)

	rout, wout, err := os.Pipe()
	if err != nil {
		err0 = fmt.Errorf("failed to create pipe: %v", err)
		return
	}
	defer rout.Close()
	defer wout.Close()

	data := make([]byte, prog.ExecBufferSize)
	n, err := p.SerializeForExec1(data, env.pid)
	if err != nil {
		err0 = err
		return
	}
	inbuf := new(bytes.Buffer)
	binary.Write(inbuf, binary.LittleEndian, uint64(env.config.Flags))
	binary.Write(inbuf, binary.LittleEndian, uint64(opts.Flags))
	binary.Write(inbuf, binary.LittleEndian, uint64(env.pid))
	inbuf.Write(data[:n])

	cmd := exec.Command(env.bin[0], env.bin[1:]...)
	cmd.Env = []string{}
	cmd.Dir = dir
	cmd.Stdin = inbuf
	cmd.ExtraFiles = []*os.File{wout}
	if env.config.Flags&FlagDebug != 0 {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stdout
	}
	if err := cmd.Start(); err != nil {
		err0 = err
		return
	}
	wout.Close()
	done := make(chan error)
	go func() {
		done <- cmd.Wait()
	}()
	t := time.NewTimer(env.config.Timeout)
	select {
	case <-done:
		t.Stop()
	case <-t.C:
		cmd.Process.Kill()
		<-done
	}
	{
		output, err := ioutil.ReadAll(rout)
		if err != nil {
			fmt.Printf("read out data: %v\n", err)
		} else {
			//fmt.Printf("read %v out data\n", len(output))
			info = make([]CallInfo, len(p.Calls))
			for len(output) >= 8 {
				r := *(*[2]uint32)(unsafe.Pointer(&output[0]))
				output = output[8:]
				//fmt.Printf("  result: idx=%v res=%v\n", r[0], r[1])
				if int(r[0]) < len(info) {
					sig := uint32(p.Calls[r[0]].Meta.ID<<16) | r[1]
					info[r[0]].Signal = []uint32{sig}
					info[r[0]].Errno = int(r[1])
				}
			}
		}
	}
	return
}
