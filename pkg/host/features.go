// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package host

import (
	"flag"
	"fmt"
	"time"

	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/feature"
	"github.com/google/syzkaller/sys/targets"
)

// Target-OS-specific source file must define:
//	var checkFeature checkMap
// with actual feature check functions specific for the OS.
type checkMap map[feature.ID]func() string

// Check detects features supported on the host.
func Check(target *prog.Target, fs *flag.FlagSet) (*feature.Set, error) {
	features := feature.Make(target.OS)
	hostFuzzer := targets.Get(target.OS, target.Arch).HostFuzzer
	for i := range features.All {
		feat := &features.All[i]
		checker := checkFeature[feat.ID]
		if hostFuzzer {
			// On these OSes we run Go binaries on host,
			// so we have checkFeature map for the host and it is
			// irrelevant for the target OS.
			checker = nil
		}
		if feat.Supported {
			if checker != nil {
				if reason := checker(); reason != "" {
					feat.Present = false
					feat.Reason = reason
				}
			}
		} else if checker != nil {
			return nil, fmt.Errorf("feature %v is not supported on %v but has a checker",
				feat.Name, target.OS)
		}
	}
	if err := features.ApplyFlags(fs); err != nil {
		return nil, err
	}
	return features, nil
}

// Setup enables and does any one-time setup for the requested features on the host.
// Note: this can be called multiple times and must be idempotent.
func Setup(target *prog.Target, features *feature.Set) error {
	if targets.Get(target.OS, target.Arch).HostFuzzer {
		// See the comment in Check.
		return nil
	}
	args := []string{"setup"}
	for _, feat := range features.All {
		if feat.Present && feat.NeedSetup {
			args = append(args, feat.Name)
		}
	}
	_, err := osutil.RunCmd(time.Minute, "", features.Executor, args...)
	return err
}
