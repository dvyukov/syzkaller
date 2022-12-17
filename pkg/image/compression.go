// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package image

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"sync"
	"syscall"
	"unsafe"
)

func Compress(rawData []byte) []byte {
	var buffer bytes.Buffer
	zlibWriter := zlib.NewWriter(&buffer)

	_, err := zlibWriter.Write(rawData)
	if err != nil {
		panic(fmt.Sprintf("could not compress with zlib: %v", err))
	}

	err = zlibWriter.Close()
	if err != nil {
		panic(fmt.Sprintf("could not finalize compression with zlib: %v", err))
	}

	return buffer.Bytes()
}

// Temporary scratch data used by the decompression procedure.
type decompressScratch struct {
	r   bytes.Reader
	zr  io.Reader
	buf []byte
}

var (
	decompressMu   sync.Mutex
	decompressPool = sync.Pool{New: func() interface{} {
		return &decompressScratch{
			buf: make([]byte, 8<<10),
		}
	}}
)

func MustDecompress(compressed []byte) (data []byte, dtor func()) {
	if len(compressed) == 0 {
		return nil, func() {}
	}
	// Optimized decompression procedure that is ~2x faster than a naive version
	// and consumes significantly less memory and generates less garbage.
	// Images tend to contain lots of 0s, especially the larger images.
	// The main idea is that we mmap a buffer and then don't write 0s into it
	// (since it already contains all 0s). As the result if a page is all 0s
	// then we don't page it in and don't consume memory for it.
	// Executor uses the same optimization during decompression.
	//
	// However, we consume lots of virtual memory even when the actual non-zero
	// data in the image is small. In 32-bit processes we may run out of virtual
	// address space, so we hold a global mutex while the data is used.
	// This restricts memory consumption to at most one uncompressed image.
	const useMutex = unsafe.Sizeof(uintptr(0)) == 4
	if useMutex {
		decompressMu.Lock()
	}
	scratch := decompressPool.Get().(*decompressScratch)
	defer decompressPool.Put(scratch)
	scratch.r.Reset(compressed)
	if scratch.zr == nil {
		zr, err := zlib.NewReader(&scratch.r)
		if err != nil {
			panic(err)
		}
		scratch.zr = zr
	} else {
		if err := scratch.zr.(zlib.Resetter).Reset(&scratch.r, nil); err != nil {
			panic(err)
		}
	}
	// Note: executor/common_zlib.h also knows this const.
	const maxImageSize = 132 << 20
	var err error
	data, err = syscall.Mmap(-1, 0, maxImageSize, syscall.PROT_READ|syscall.PROT_WRITE,
		syscall.MAP_ANON|syscall.MAP_PRIVATE)
	if err != nil {
		panic(err)
	}
	dtor = func() {
		if err := syscall.Munmap(data[:maxImageSize]); err != nil {
			panic(err)
		}
		if useMutex {
			decompressMu.Unlock()
		}
	}
	offset := 0
	for {
		n, err := scratch.zr.Read(scratch.buf)
		if err != nil && err != io.EOF {
			panic(err)
		}
		if n == 0 {
			break
		}
		if offset+n > len(data) {
			panic(fmt.Sprintf("bad image size: offset=%v n=%v data=%v", offset, n, len(data)))
		}
		// Copy word-at-a-time and avoid bounds checks in the loop,
		// this is considerably faster than a naive byte loop.
		// We already checked bounds above.
		type word uint64
		const wordSize = unsafe.Sizeof(word(0))
		words := uintptr(n) / wordSize
		src := (*word)(unsafe.Pointer(&scratch.buf[0]))
		dst := (*word)(unsafe.Pointer(&data[offset]))
		for i := uintptr(0); i < words; i++ {
			if *src != 0 {
				*dst = *src
			}
			src = (*word)(unsafe.Pointer(uintptr(unsafe.Pointer(src)) + wordSize))
			dst = (*word)(unsafe.Pointer(uintptr(unsafe.Pointer(dst)) + wordSize))
		}
		// Copy any remaining trailing bytes.
		for i := words * wordSize; i < uintptr(n); i++ {
			v := scratch.buf[i]
			if v != 0 {
				data[uintptr(offset)+i] = v
			}
		}
		offset += n
	}
	data = data[:offset]
	return
}

func DecompressCheck(compressed []byte) error {
	if len(compressed) == 0 {
		return nil
	}
	zlibReader, err := zlib.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return fmt.Errorf("could not initialise zlib: %v", err)
	}
	if _, err := io.Copy(ioutil.Discard, zlibReader); err != nil {
		return fmt.Errorf("could not read data with zlib: %v", err)
	}
	return zlibReader.Close()
}

func DecodeB64(b64Data []byte) ([]byte, error) {
	decoder := base64.NewDecoder(base64.StdEncoding, bytes.NewReader(b64Data))
	rawData, err := io.ReadAll(decoder)
	if err != nil {
		return nil, fmt.Errorf("could not decode Base64: %v", err)
	}
	return rawData, nil
}

func EncodeB64(rawData []byte) []byte {
	var buf bytes.Buffer
	encoder := base64.NewEncoder(base64.StdEncoding, &buf)
	_, err := encoder.Write(rawData)
	if err != nil {
		panic(fmt.Sprintf("could not encode Base64: %v", err))
	}
	err = encoder.Close()
	if err != nil {
		panic(fmt.Sprintf("could not finalize encoding to Base64: %v", err))
	}
	return buf.Bytes()
}
