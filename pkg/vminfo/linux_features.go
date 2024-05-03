// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vminfo

import (
	"github.com/google/syzkaller/pkg/flatrpc"
)

func (linux) featureCheck(feat flatrpc.Feature) string {
	return ""
}
