// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vminfo

import (
	//"fmt"
	"slices"
	"strings"
	//"regexp"

	"github.com/google/syzkaller/pkg/flatrpc"
	"golang.org/x/sync/errgroup"
)

func (linux) extractGlobs() []string {
	var globs []string
	for _, path := range []string{"/dev", "/sys", "/proc"} {
		// Our globs currently do not support recursion (#4906),
		// so we append N "/*" parts manully. Some of the paths can be very deep,
		// e.g. /sys can have up to 30 levels, see:
		// sudo find /sys -ls 2>/dev/null | sed "s#[^/]##g" | sort | uniq -c
		for i := 1; i < 30; i++ {
			globs = append(globs, path+strings.Repeat("/*", i))
		}
	}
	return globs
}

func (linux linux) extract(ctx *checkContext, info *flatrpc.InfoRequestRawT) (*IfaceInfo, error) {
	symb := symbolizer.NewSymbolizer(target *targets.Target) *Symbolizer {

	files := linux.fileList(info)
	res := &IfaceInfo{
		Files: make([]FileInfo, len(files)),
	}
	var eg errgroup.Group
	eg.SetLimit(1000)
	for i, file := range files {
		i, file := i, file
		eg.Go(func() error {
			fi, err := linux.extractFileInfo(ctx, file)
			res.Files[i] = fi
			return err
		})
	}
	
	if err := eg.Wait(); err != nil {
		return nil, err
	}
	return res, nil
/*	
	fmt.Printf("FILES %v:\n", len(files))
	for _, file := range files {
		fmt.Printf("%v\n", file)
	}
	return nil, nil
*/////////
}

type fopDesc struct {
	mode string
	call string
	caller string
}

var fops = []fopDesc{
	{
		mode: "O_RDONLY"
		call: "read(r0, &AUTO=' ', AUTO)",
		caller: "vfs_read",
	},
	{
		mode: "O_WRONLY"
		call: "write(r0, &AUTO=' ', AUTO)",
		caller: "vfs_write",
	},
}

func (linux linux) extractFileInfo(ctx *checkContext, file string) (FileInfo, error) {
	fi := FileInfo{
		Name: file,
	}
	for _, fop := range fops {
		text := fmt.Sprintf("r0 = openat(0x%x, &AUTO='%s', 0x%x, 0x0)\n%v",
			ctx.val("AT_FDCWD"), file, ctx.val(fop.mode), fop.call)
		pi := ctx.execCover(text).Calls[1]
		if (pi.Calls[0].Flags & flatrpc.CallFlagFinished) == 0 || pi.Calls[0].Errno != 0 {
			continue
		}
		for _, pc := range pi.Calls[1].Cover {
		}
		
		
		
	}
	return fi, nil
}

func (linux linux) fileList(info *flatrpc.InfoRequestRawT) []string {
	var files []string
	dedup := make(map[string]bool)
	for _, glob := range info.Globs {
		for _, file := range glob.Files {
			if dedup[file] || !linux.fileFilter(file) {
				continue
			}
			dedup[file] = true
			files = append(files, file)
		}
	}
	slices.Sort(files)
	return files
}

func (linux) fileFilter(file string) bool {
	if strings.HasPrefix(file, "/dev/") {
		return true
	}
	if proc := "/proc/"; strings.HasPrefix(file, proc) {
		// These won't be present in the test process.
		if strings.HasPrefix(file, "/proc/self/fdinfo/") ||
			strings.HasPrefix(file, "/proc/thread-self/fdinfo/") {
			return false
		}
		// It contains actual pid number that will be different in the test.
		if strings.HasPrefix(file, "/proc/self/task/") {
			return false
		}
		// Ignore all actual processes.
		c := file[len(proc)]
		return c < '0' || c > '9'
	}
	if strings.HasPrefix(file, "/sys/") {
		// There are too many tracing events, so leave just one of them.
		if strings.HasPrefix(file, "/sys/kernel/tracing/events/") &&
			!strings.HasPrefix(file, "/sys/kernel/tracing/events/vmalloc/") ||
			strings.HasPrefix(file, "/sys/kernel/debug/tracing/events/") &&
				!strings.HasPrefix(file, "/sys/kernel/debug/tracing/events/vmalloc/") {
			return false
		}
		// There are too many slabs, so leave just one of them.
		if strings.HasPrefix(file, "/sys/kernel/slab/") &&
			!strings.HasPrefix(file, "/sys/kernel/slab/kmalloc-64") {
			return false
		}
		return true
	}
	return false
}
