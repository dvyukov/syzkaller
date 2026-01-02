// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/osutil"
)

type Cache struct {
	Workdir string
	timeNow func() time.Time
	mu      sync.Mutex
}

func NewCache(dir string) (*Cache, error) {
	return newTestCache(dir, time.Now)
}

func newTestCache(dir string, timeNow func() time.Time) (*Cache, error) {
	if dir == "" {
		return nil, fmt.Errorf("cache workdir is empty")
	}
	return &Cache{
		Workdir: osutil.Abs(dir),
		timeNow: timeNow,
	}, nil
}

// Cache creates/returns a cached directory with contents created by the populate callback.
// The populate callback receives a dir it needs to populate with cached files.
// The typ must be a short descriptive name of the contents (e.g. "build", "source", etc).
// The desc is used to identify cached entries and must fully describe the cached contents
// (the second invocation with the same typ+desc will return dir created by the first
// invocation with the same typ+desc).
func (c *Cache) Cache(typ, desc string, populate func(string) error) (string, error) {
	// Note: we don't populate a temp dir and then atomically rename it to the final destination,
	// because at least kernel builds encode the current path in debug info/compile commands,
	// so moving the dir later would break all that. Instead we rely on the presence of the meta file
	// to denote valid cache entries. Modification time of the file says when it was last used.
	id := hash.String(desc)
	dir := filepath.Join(c.Workdir, typ, id)
	metaFile := filepath.Join(dir, "aflow-meta")
	if !osutil.IsExist(metaFile) {
		c.mu.Lock()
		defer c.mu.Unlock()

		os.RemoveAll(dir)
		if err := osutil.MkdirAll(dir); err != nil {
			return "", err
		}
		if err := populate(dir); err != nil {
			os.RemoveAll(dir)
			return "", err
		}
		if err := osutil.WriteFile(metaFile, []byte(desc)); err != nil {
			os.RemoveAll(dir)
			return "", err
		}
	}
	// Note the entry was used now.
	now := c.timeNow()
	if err := os.Chtimes(metaFile, now, now); err != nil {
		return "", err
	}
	return dir, nil
}
