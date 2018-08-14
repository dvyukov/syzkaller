// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package report

import (
	"bufio"
	"bytes"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/google/syzkaller/pkg/symbolizer"
	"github.com/ianlancetaylor/demangle"
)

type fuchsia struct {
	obj     string
	ignores []*regexp.Regexp
}

var (
	zirconPanic      = []byte("ZIRCON KERNEL PANIC")
	zirconPanicShort = []byte("KERNEL PANIC")
	zirconKernelHang = []byte("stopping other cpus")
	zirconServiceCrash = []byte("<== fatal exception: process ")
	zirconSyzPrefix = []byte("syz")
	zirconRIP        = regexp.MustCompile(` RIP: (0x[0-9a-f]+) `)
	zirconBT         = regexp.MustCompile(`^bt#[0-9]+: (0x[0-9a-f]+)`)
	zirconReportEnd  = []byte("Halted")
	zirconUnrelated  = []*regexp.Regexp{
		regexp.MustCompile(`^\[\d+\.\d+\] \d+\.\d+`),
		regexp.MustCompile(`stopping other cpus`),
		regexp.MustCompile(`^halting cpu`),
		regexp.MustCompile(`^dso: `),
		regexp.MustCompile(`^UPTIME: `),
		regexp.MustCompile(`^BUILDID `),
		regexp.MustCompile(`^Halting\.\.\.`),
	}
	zirconSkip = []*regexp.Regexp{
		regexp.MustCompile("^platform_halt$"),
		regexp.MustCompile("^exception_die$"),
		regexp.MustCompile("^_panic$"),
	}
)

func ctorFuchsia(kernelSrc, kernelObj string, ignores []*regexp.Regexp) (Reporter, []string, error) {
	ctx := &fuchsia{
		ignores: ignores,
	}
	if kernelObj != "" {
		ctx.obj = filepath.Join(kernelObj, "zircon.elf")
	}
	suppressions := []string{
		"fatal exception: process /tmp/syz-fuzzer", // OOM presumably
	}
	return ctx, suppressions, nil
}

func (ctx *fuchsia) ContainsCrash(output []byte) bool {
	if bytes.Contains(output, zirconPanic) ||
		bytes.Contains(output, zirconKernelHang) {
		return true
	}
	if pos := bytes.Index(output, zirconServiceCrash); pos != -1 {
		end := pos + len(zirconServiceCrash) + 32
		if end > len(output) {
			end = len(output)
		}
		if !bytes.Contains(output[pos:end], zirconSyzPrefix) {
			return true
		}
	}
	return false
}

func (ctx *fuchsia) Parse(output []byte) *Report {
	output = ctx.symbolize(output)

	rep := simpleLineParser(output, zirconOopses, zirconStackParams, ctx.ignores, ctx.symbolizeLine)
	if rep == nil {
		return nil
	}
	return rep
}

	/*
	rep := &Report{
		Output: output,
		EndPos: len(output),
	}
	wantLocation := true
	if pos := bytes.Index(output, zirconPanic); pos != -1 {
		rep.Title = string(zirconPanicShort)
		rep.StartPos = pos
	} else if pos := bytes.Index(output, zirconKernelHang); pos != -1 {
		rep.Title = string(zirconKernelHang)
		rep.StartPos = pos
		wantLocation = false // these tend to produce random locations
	} else if pos := bytes.Index(output, zirconServiceCrash); pos != -1 {
		lineEnd := pos + len(zirconServiceCrash) + 32
		if lineEnd > len(output) {
			lineEnd = len(output)
		}
		if !bytes.Contains(output[pos:lineEnd], zirconSyzPrefix) {
			return nil
		}
		rep.StartPos = pos
		endPos := bytes.Index(output[pos:], []byte(": end\n"))
		if endPos != -1 {
			rep.EndPos = pos + endPos
		}
		pos += len(zirconServiceCrash)
		end := pos
		for end < len(output) {
			ch := output[end]
			if ch >= 'a' && ch <= 'z' ||
				ch >= 'A' && ch <= 'Z' ||
				ch >= '0' && ch <= '9' ||
				ch == '/' || ch == '-' || ch == '_' {
				end++
				continue
			}
			break
		}
		rep.Title = fmt.Sprintf("fatal exception in %s", output[pos:end])
		return rep
	} else {
		return nil
	}
	symb := symbolizer.NewSymbolizer()
	defer symb.Close()
	where := ""
	for s := bufio.NewScanner(bytes.NewReader(output[rep.StartPos:])); s.Scan(); {
		line := s.Bytes()
		if len(line) == 0 || matchesAny(line, zirconUnrelated) {
			continue
		}
		if bytes.Equal(line, zirconReportEnd) {
			break
		}
		if bytes.Contains(line, []byte("DEBUG ASSERT FAILED")) {
			rep.Title = "ASSERT FAILED"
		}
		if bytes.Contains(line, []byte("Supervisor Page Fault exception")) {
			rep.Title = "Supervisor fault"
		}
		if bytes.Contains(line, []byte("recursion in interrupt handler")) {
			rep.Title = "recursion in interrupt handler"
		}
		if bytes.Contains(line, []byte("double fault")) {
			rep.Title = "double fault"
		}
		if match := zirconRIP.FindSubmatchIndex(line); match != nil {
			ctx.processPC(rep, symb, line, match, false, &where)
		} else if match := zirconBT.FindSubmatchIndex(line); match != nil {
			if ctx.processPC(rep, symb, line, match, true, &where) {
				continue
			}
		}
		rep.Report = append(rep.Report, line...)
		rep.Report = append(rep.Report, '\n')
	}
	if wantLocation && where != "" {
		rep.Title = fmt.Sprintf("%v in %v", rep.Title, where)
	}
	return rep
	*/

func (ctx *fuchsia) symbolize(output []byte) []byte {
	if ctx.obj == "" {
		return output
	}
	symb := symbolizer.NewSymbolizer()
	defer symb.Close()
	output = zirconRIP.ReplaceAllFunc(output, func(line []byte) []byte { return ctx.symbolizeLine(symb, line, false) }
	output = zirconBT.ReplaceAllFunc(output, func(line []byte) []byte { return ctx.symbolizeLine(symb, line, true) }
	return output
}

func (ctx *fuchsia) symbolizeLine(symb *symbolizer.Symbolizer, line []byte, call bool) []byte {

	**********************************************
	this will not work because we need to copy while RIP line, which we don't have here
	**********************************************

	pcStart := bytes.Index(line, []byte{'0', 'x'})
	
	//prefix := line[match[0]:match[1]]
	//pcStart := match[2] - match[0]
	//pcEnd := match[3] - match[0]
	//pcStr := prefix[pcStart:pcEnd]
	pc, err := strconv.ParseUint(string(line[pcStart:]), 0, 64)
	if err != nil {
		return line
	}
	shortPC := pc & 0xfffffff
	pc = 0xffffffff80000000 | shortPC
	if call {
		pc--
	}
	frames, err := symb.Symbolize(ctx.obj, pc)
	if err != nil || len(frames) == 0 {
		return line
	}
	out := new(bytes.Buffer)
	for _, frame := range frames {
		file := ctx.trimFile(frame.File)
		name := demangle.Filter(frame.Func, demangle.NoParams, demangle.NoTemplateParams)
		if strings.Contains(name, "<lambda(") {
			// demangle produces super long (full) names for lambdas.
			name = "lambda"
		}
		id := "[ inline ]"
		if !frame.Inline {
			id = fmt.Sprintf("0x%08x", shortPC)
		}
		
		start := replace(append([]byte{}, prefix...), pcStart, pcEnd, []byte(id))
		frameLine := fmt.Sprintf("%s %v %v:%v\n", start, name, file, frame.Line)
		rep.Report = append(rep.Report, frameLine...)
	}
	return true
}

func (ctx *fuchsia) trimFile(file string) string {
	const (
		prefix1 = "zircon/kernel/"
		prefix2 = "zircon/"
	)
	if pos := strings.LastIndex(file, prefix1); pos != -1 {
		return file[pos+len(prefix1):]
	}
	if pos := strings.LastIndex(file, prefix2); pos != -1 {
		return file[pos+len(prefix2):]
	}
	return file
}

func (ctx *fuchsia) Symbolize(rep *Report) error {
	// We symbolize in Parse because zircon stacktraces don't contain even function names.
	return nil
}

var fuchsiaStackParams = &stackParams{
	//stackStartRes: linuxStackKeywords,
	frameRes: []*regexp.Regexp{
		compile("^ +(?:{{PC}} )?{{FUNC}}"),
	},
	//skipPatterns: []string{}
}

var zirconOopses = []*oops{
	{
		[]byte("ZIRCON KERNEL PANIC"),
		[]oopsFormat{
			{
				title:        compile("ZIRCON KERNEL PANIC"),
				fmt:          "KERNEL PANIC in %[1]",
				noStackTrace: true,
			},
		},
		[]*regexp.Regexp{},
	},
}
