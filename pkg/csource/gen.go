// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

//go:build ignore

package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"regexp"

	"github.com/google/syzkaller/pkg/tool"
)

func main() {
	out, err := os.Create("generated.go")
	if err != nil {
		tool.Fail(err)
	}
	defer out.Close()
	data, err := ioutil.ReadFile("../../executor/common.h")
	if err != nil {
		tool.Fail(err)
	}
	executorFilenames := []string{
		"common_linux.h",
		"common_bsd.h",
		"common_openbsd.h",
		"common_fuchsia.h",
		"common_windows.h",
		"common_test.h",
		"common_kvm_amd64.h",
		"common_kvm_arm64.h",
		"common_kvm_ppc64.h",
		"common_usb_linux.h",
		"common_usb_netbsd.h",
		"common_usb.h",
		"common_ext.h",
		"android/android_seccomp.h",
		"kvm.h",
		"kvm_amd64.S.h",
		"kvm_ppc64le.S.h",
		"common_zlib.h",
	}
	data = replaceIncludes(executorFilenames, "../../executor/", data)
	androidFilenames := []string{
		"arm64_app_policy.h",
		"arm_app_policy.h",
		"x86_64_app_policy.h",
		"x86_app_policy.h",
		"arm64_system_policy.h",
		"arm_system_policy.h",
		"x86_64_system_policy.h",
		"x86_system_policy.h",
	}
	data = replaceIncludes(androidFilenames, "../../executor/android/", data)
	// Remove `//` comments, but keep lines which start with `//%`.
	for _, remove := range []string{
		"(\n|^)\\s*//$",
		"(\n|^)\\s*//[^%].*",
		"\\s*//$",
		"\\s*//[^%].*",
	} {
		data = regexp.MustCompile(remove).ReplaceAll(data, nil)
	}
	fmt.Fprintf(out, "// Code generated by gen.go from executor/*.h. DO NOT EDIT.\n\n")
	fmt.Fprintf(out, "package csource\n\nvar commonHeader = `\n")
	out.Write(data)
	fmt.Fprintf(out, "`\n")
}

func replaceIncludes(filenames []string, location string, data []byte) []byte {
	for _, include := range filenames {
		contents, err := ioutil.ReadFile(location + include)
		if err != nil {
			tool.Fail(err)
		}
		replace := []byte("#include \"" + include + "\"")
		if bytes.Index(data, replace) == -1 {
			tool.Failf("can't find %v include", include)
		}
		data = bytes.Replace(data, replace, contents, -1)
	}
	return data
}
