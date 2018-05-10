// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build !appengine

package osutil

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// UmountAll recurusively unmounts all mounts in dir.
func UmountAll(dir string) {
	files, _ := ioutil.ReadDir(dir)
	for _, f := range files {
		name := filepath.Join(dir, f.Name())
		if f.IsDir() {
			UmountAll(name)
		}
		fn := []byte(name + "\x00")
		syscall.Syscall(syscall.SYS_UMOUNT2, uintptr(unsafe.Pointer(&fn[0])), syscall.MNT_FORCE, 0)
	}
}

func Sandbox(cmd *exec.Cmd, user, net bool) error {
	enabled, uid, gid, err := initSandbox()
	if err != nil {
		return err
	}
	if !enabled {
		return nil
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = new(syscall.SysProcAttr)
	}
	if user {
		cmd.SysProcAttr.Credential = &syscall.Credential{
			Uid: uid,
			Gid: gid,
		}
	}
	if net {
		cmd.SysProcAttr.Cloneflags = syscall.CLONE_NEWNET | syscall.CLONE_NEWIPC |
			syscall.CLONE_NEWNS | syscall.CLONE_NEWUTS | syscall.CLONE_NEWPID
	}
	return nil
}

func SandboxChown(file string) error {
	enabled, uid, gid, err := initSandbox()
	if err != nil {
		return err
	}
	if !enabled {
		return nil
	}
	return os.Chown(file, int(uid), int(gid))
}

var (
	sandboxOnce     sync.Once
	sandboxEnabled  = true
	sandboxUsername = "syzkaller"
	sandboxUID      = ^uint32(0)
	sandboxGID      = ^uint32(0)
)

func initSandbox() (bool, uint32, uint32, error) {
	sandboxOnce.Do(func() {
		sandboxEnabled = false
		return

		if syscall.Getuid() != 0 {
			sandboxEnabled = false
			return
		}
		uid, err := usernameToID("-u")
		if err != nil {
			return
		}
		gid, err := usernameToID("-g")
		if err != nil {
			return
		}
		sandboxUID = uid
		sandboxGID = gid
	})
	if sandboxEnabled && sandboxUID == ^uint32(0) {
		return false, 0, 0, fmt.Errorf("user %q is not found, can't sandbox command", sandboxUsername)
	}
	return sandboxEnabled, sandboxUID, sandboxGID, nil
}

func usernameToID(what string) (uint32, error) {
	out, err := RunCmd(time.Minute, "", "id", what, sandboxUsername)
	if err != nil {
		return 0, err
	}
	str := strings.Trim(string(out), " \t\n")
	id, err := strconv.ParseUint(str, 10, 32)
	if err != nil {
		return 0, err
	}
	return uint32(id), nil
}

func setPdeathsig(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = new(syscall.SysProcAttr)
	}
	cmd.SysProcAttr.Pdeathsig = syscall.SIGKILL
}

func prolongPipe(r, w *os.File) {
	for sz := 128 << 10; sz <= 2<<20; sz *= 2 {
		syscall.Syscall(syscall.SYS_FCNTL, w.Fd(), syscall.F_SETPIPE_SZ, uintptr(sz))
	}
}
