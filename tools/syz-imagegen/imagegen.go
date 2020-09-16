// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// syz-imagegen generates sys/linux/test/syz_mount_image_* test files.
// It requires f2fs-tools package to be installed.
package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/google/syzkaller/pkg/osutil"
)

type FileSystem struct {
	Name      string
	MinSize   int
	MkfsFlags [][]string
}

var fileSystems = []FileSystem{
	{
		Name:    "f2fs",
		MinSize: 64 << 20,
		MkfsFlags: [][]string{
			{"-a 0", "-a 1"},
			{"-s 1", "-s 2"},
			{"", "-m"},
			{"", "-O encrypt"},
		},
	},
	{
		Name:    "btrfs",
		MinSize: 16 << 20,
		MkfsFlags: [][]string{
			{"", "-M"},
			{"", "-K"},
			{"--csum crc32c", "--csum xxhash", "--csum sha256", "--csum blake2"},
			{"--nodesize 4096 -O mixed-bg", "-O extref", "-O raid56", "-O no-holes", "-O raid1c34"},
		},
	},
}

func main() {
	var images []*Image
	for _, fs := range fileSystems {
		index := 0
		enumerateFlags(&images, &index, fs, "", 0)
	}
	procs := runtime.NumCPU()
	requests := make(chan *Image, procs)
	go func() {
		for _, image := range images {
			requests <- image
		}
		close(requests)
	}()
	for p := 0; p < procs; p++ {
		go func() {
			for image := range requests {
				image.done <- generateImage(image)
			}
		}()
	}
	failed := false
	for _, image := range images {
		err := <-image.done
		if err != nil {
			fmt.Printf("mkfs.%v %v: %v\n", image.fs.Name, image.flags, err)
			failed = true
			continue
		}
		fmt.Printf("mkfs.%v[%vMB] %v\n", image.fs.Name, image.size>>20, image.flags)
	}
	if failed {
		os.Exit(1)
	}
}

type Image struct {
	fs    FileSystem
	flags string
	index int
	size  int
	done  chan error
}

func enumerateFlags(images *[]*Image, index *int, fs FileSystem, flags string, flagsIndex int) {
	if flagsIndex == len(fs.MkfsFlags) {
		*images = append(*images, &Image{fs: fs, flags: flags, index: *index, done: make(chan error, 1)})
		*index++
		return
	}
	for _, flag := range fs.MkfsFlags[flagsIndex] {
		if flags != "" && flag != "" {
			flag = " " + flag
		}
		enumerateFlags(images, index, fs, flags+flag, flagsIndex+1)
	}
}

func generateImage(image *Image) error {
	var err error
	for image.size = image.fs.MinSize; image.size <= 128<<20; image.size *= 2 {
		if err = generateImageSize(image); err == nil {
			return nil
		}
	}
	return err
}

func generateImageSize(image *Image) error {
	disk, err := osutil.TempFile("syz-imagegen")
	if err != nil {
		return err
	}
	defer os.Remove(disk)
	if err := os.Truncate(disk, int64(image.size)); err != nil {
		return err
	}
	args := append(strings.Split(image.flags, " "), disk)
	output, err := exec.Command("mkfs."+image.fs.Name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v\n%s", err, output)
	}
	data, err := ioutil.ReadFile(disk)
	if err != nil {
		return err
	}
	out, err := writeImage(image.fs, data)
	if err != nil {
		return err
	}
	outFile := filepath.Join("sys", "linux", "test", fmt.Sprintf("syz_mount_image_%v_%v", image.fs.Name, image.index))
	return osutil.WriteFile(outFile, out)
}

func writeImage(fs FileSystem, data []byte) ([]byte, error) {
	buf := new(bytes.Buffer)
	fmt.Fprintf(buf, "# Code generated by tools/syz-imagegen. DO NOT EDIT.\n")
	fmt.Fprintf(buf, "# requires: manual\n\n")
	syscallSuffix := fs.Name
	if syscallSuffix == "ext2" || syscallSuffix == "ext3" {
		syscallSuffix = "ext4"
	}
	segs := calculateSegments(data)
	fmt.Fprintf(buf, `syz_mount_image$%v(&(0x7f0000000000)='%v\x00', &(0x7f0000000100)='./file0\x00',`+
		` 0x%x, 0x%x, &(0x7f0000000200)=[`,
		syscallSuffix, fs.Name, len(data), len(segs))
	addr := 0x7f0000010000
	for i, seg := range segs {
		if i != 0 {
			fmt.Fprintf(buf, ", ")
		}
		fmt.Fprintf(buf, `{&(0x%x)="%v", 0x%x, 0x%x}`,
			addr, hex.EncodeToString(seg.data), len(seg.data), seg.offset)
		addr = (addr + len(seg.data) + 0xff) & ^0xff
	}
	fmt.Fprintf(buf, "], 0x0, &(0x%x))\n", addr)
	return buf.Bytes(), nil
}

type Segment struct {
	offset int
	data   []byte
}

func calculateSegments(data []byte) []Segment {
	const (
		skip  = 32 // min zero bytes to skip
		align = 32 // non-zero block alignment
	)
	data0 := data
	zeros := make([]byte, skip+align)
	var segs []Segment
	offset := 0
	for len(data) != 0 {
		pos := bytes.Index(data, zeros)
		if pos == -1 {
			segs = append(segs, Segment{offset, data})
			break
		}
		pos = (pos + align - 1) & ^(align - 1)
		if pos != 0 {
			segs = append(segs, Segment{offset, data[:pos]})
		}
		for pos < len(data) && data[pos] == 0 {
			pos++
		}
		pos = pos & ^(align - 1)
		offset += pos
		data = data[pos:]
	}
	if false {
		// self-test.
		restored := make([]byte, len(data0))
		for _, seg := range segs {
			copy(restored[seg.offset:], seg.data)
		}
		if !bytes.Equal(data0, restored) {
			panic("restored data differs!")
		}
	}
	return segs
}

// TODO: also generate syz_read_part_table tests:
//	fmt.Printf(`syz_read_part_table(0x%x, 0x%x, &(0x7f0000000200)=[`,
//		len(data0), len(segs))
//	addr := 0x7f0000010000
//	for i, seg := range segs {
//		if i != 0 {
//			fmt.Printf(", ")
//		}
//		fmt.Printf(`{&(0x%x)="%v", 0x%x, 0x%x}`,
//			addr, hex.EncodeToString(seg.data), len(seg.data), seg.offset)
//		addr = (addr + len(seg.data) + 0xff) & ^0xff
//	}
//	fmt.Printf("])\n")
