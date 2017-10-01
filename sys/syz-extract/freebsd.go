// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/google/syzkaller/pkg/compiler"
)

type freebsd struct{}

func (*freebsd) prepare(sourcedir string, build bool, arches []string) error {
	if sourcedir == "" {
		return fmt.Errorf("provide path to kernel checkout via -sourcedir flag (or make extract SOURCEDIR)")
	}
	return nil
}

func (*freebsd) prepareArch(arch *Arch) error {
	return nil
}

func (*freebsd) processFile(arch *Arch, info *compiler.ConstInfo) (map[string]uint64, map[string]bool, error) {
	vals := info.Consts
	bin, out, err := freebsdCompile(arch.sourceDir, nil,
		info.Includes, info.Incdirs, nil, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to run gcc: %v\n%v", err, string(out))
	}
	os.Remove(bin)

	var other []string
	addVals := make(map[string][]string)
	valMap := make(map[string]bool)
	for _, val := range vals {
		valMap[val] = true
		if strings.HasPrefix(val, "SYS_") {
			for _, compat := range []string{"__", "freebsd11_", "freebsd10_", "freebsd7_"} {
				subst := "SYS_" + compat + val[4:]
				addVals[val] = append(addVals[val], subst)
				valMap[subst] = true
				other = append(other, subst)
			}
		}
	}
	vals = append(vals, other...)

	undeclared := make(map[string]bool)
	bin, out, err = freebsdCompile(arch.sourceDir, vals,
		info.Includes, info.Incdirs, info.Defines, undeclared)
	if err != nil {
		for _, errMsg := range []string{
			"error: ‘([a-zA-Z0-9_]+)’ undeclared",
			"note: in expansion of macro ‘([a-zA-Z0-9_]+)’",
		} {
			re := regexp.MustCompile(errMsg)
			matches := re.FindAllSubmatch(out, -1)
			for _, match := range matches {
				val := string(match[1])
				if !undeclared[val] && valMap[val] {
					undeclared[val] = true
				}
			}
		}
		bin, out, err = freebsdCompile(arch.sourceDir, vals,
			info.Includes, info.Incdirs, info.Defines, undeclared)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to run gcc: %v\n%v\nundeclared: %+v",
				err, string(out), undeclared)
		}
	}
	defer os.Remove(bin)

	res, err := runBinaryAndParse(bin, vals, undeclared)
	if err != nil {
		return nil, nil, err
	}
	for orig, substs := range addVals {
		for _, subst := range substs {
			if undeclared[orig] && !undeclared[subst] {
				res[orig] = res[subst]
				delete(res, subst)
				delete(undeclared, orig)
			}
			delete(undeclared, subst)
		}
	}
	return res, undeclared, nil

	/*
		bin, out, err := freebsdCompile(arch.sourceDir, info.Consts, info.Includes, info.Incdirs, info.Defines)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to run compiler: %v\n%v", err, string(out))
		}
		defer os.Remove(bin)
		res, err := runBinaryAndParse(bin, info.Consts, nil)
		if err != nil {
			return nil, nil, err
		}
		return res, nil, nil
	*/
}

func freebsdCompile(sourceDir string, vals, includes, incdirs []string, defines map[string]string, undeclared map[string]bool) (bin string, out []byte, err error) {
	includeText := "#include <sys/syscall.h>\n"
	for _, inc := range includes {
		includeText += fmt.Sprintf("#include <%v>\n", inc)
	}
	definesText := ""
	for k, v := range defines {
		definesText += fmt.Sprintf("#ifndef %v\n#define %v %v\n#endif\n", k, k, v)
	}
	valsText := ""
	for _, v := range vals {
		if undeclared[v] {
			continue
		}
		if valsText != "" {
			valsText += ","
		}
		valsText += v
	}
	//valsText := strings.Join(vals, ",")
	src := freebsdSrc
	src = strings.Replace(src, "[[INCLUDES]]", includeText, 1)
	src = strings.Replace(src, "[[DEFAULTS]]", definesText, 1)
	src = strings.Replace(src, "[[VALS]]", valsText, 1)
	binFile, err := ioutil.TempFile("", "")
	if err != nil {
		return "", nil, fmt.Errorf("failed to create temp file: %v", err)
	}
	binFile.Close()
	includeDir := filepath.Join(sourceDir, "sys")
	args := []string{"-x", "c", "-", "-o", binFile.Name(), "-fmessage-length=0", "-w", "-I", includeDir,
		"-nostdinc", "-I", "/tmp/freebsd", "-I", filepath.Join(sourceDir, "sys", "sys")}
	for _, incdir := range incdirs {
		args = append(args, "-I"+sourceDir+"/"+incdir)
	}
	cmd := exec.Command("gcc", args...)
	cmd.Stdin = strings.NewReader(src)
	out, err = cmd.CombinedOutput()
	if err != nil {
		os.Remove(binFile.Name())
		return "", out, err
	}
	return binFile.Name(), nil, nil
}

var freebsdSrc = `
[[INCLUDES]]
[[DEFAULTS]]
int printf(const char *format, ...);
int main() {
	int i;
	unsigned long long vals[] = {[[VALS]]};
	for (i = 0; i < sizeof(vals)/sizeof(vals[0]); i++) {
		if (i != 0)
			printf(" ");
		printf("%llu", vals[i]);
	}
	return 0;
}
`
