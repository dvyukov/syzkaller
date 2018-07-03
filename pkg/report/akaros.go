// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package report

import (
	"regexp"
)

type akaros struct {
	ignores []*regexp.Regexp
}

func ctorAkaros(kernelSrc, kernelObj string, ignores []*regexp.Regexp) (Reporter, []string, error) {
	ctx := &akaros{
		ignores: ignores,
	}
	return ctx, nil, nil
}

func (ctx *akaros) ContainsCrash(output []byte) bool {
	return false
}

func (ctx *akaros) Parse(output []byte) *Report {
	return nil
}

func (ctx *akaros) Symbolize(rep *Report) error {
	return nil
}
