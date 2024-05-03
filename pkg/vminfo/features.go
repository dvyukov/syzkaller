// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vminfo

import (
	"github.com/google/syzkaller/pkg/flatrpc"
)

type Feature struct {
	Enabled   bool
	NeedSetup bool
	Reason    string
}

type Features map[flatrpc.Feature]Feature

func (features Features) Enabled() flatrpc.Feature {
	var mask flatrpc.Feature
	for feat, info := range features {
		if info.Enabled {
			mask |= feat
		}
	}
	return mask
}

func (features Features) NeedSetup() flatrpc.Feature {
	var mask flatrpc.Feature
	for feat, info := range features {
		if info.Enabled && info.NeedSetup {
			mask |= feat
		}
	}
	return mask
}

const featureNotImplemented = "support is not implemented"
