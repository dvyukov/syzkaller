// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

// A hint is basically a tuple consisting of a pointer to an argument
// in one of the syscalls of a program and a value, which should be
// assigned to that argument (we call it a replacer).

// A simplified version of hints workflow looks like this:
//		1. Fuzzer launches a program (we call it a hint seed) and collects all
// the comparisons' data for every syscall in the program.
//		2. Next it tries to match the obtained comparison operands' values
// vs. the input arguments' values.
//		3. For every such match the fuzzer mutates the program by
// replacing the pointed argument with the saved value.
//		4. If a valid program is obtained, then fuzzer launches it and
// checks if new coverage is obtained.
// For more insights on particular mutations please see prog/hints_test.go.

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"maps"
	"io"
	"sort"
	"sync"

	"github.com/google/syzkaller/pkg/image"
)

var (
	statsMu       sync.Mutex
	syscallHints  = make(map[string]*perSyscall)
	compTypes     = make(map[string]int)
	compArgs      = make(map[string]int)
	compReplacers = make(map[string]int)
)

type compType int

const (
	compTypeConst compType = iota
	compTypeInt
	compTypeFlags
	compTypeLen
	compTypeData
	compTypeCompressed
	compTypeTotal
	compTypeCount
)

func (t compType) String() string {
	switch t {
	case compTypeConst:
		return "const"
	case compTypeInt:
		return "int"
	case compTypeFlags:
		return "flags"
	case compTypeLen:
		return "len"
	case compTypeData:
		return "data"
	case compTypeCompressed:
		return "compressed"
	case compTypeTotal:
		return "total"
	}
	panic("unknown type")
}

type perSyscall struct {
	name  string
	count int
	comps int
	types [compTypeCount]int
}

func DumpCompStats(w io.Writer) {
	statsMu.Lock()
	defer statsMu.Unlock()
	type syscallStat struct {
		name  string
		count int
		comps int
		types [compTypeCount]int
	}
	total := 0
	var syscalls []syscallStat
	for name, syscall := range syscallHints {
		total += syscall.count
		syscalls = append(syscalls, syscallStat{
			name:  name,
			count: syscall.count,
			comps: syscall.comps / syscall.count,
			types: [compTypeCount]int{
				syscall.types[compTypeConst] / syscall.count,
				syscall.types[compTypeInt] / syscall.count,
				syscall.types[compTypeFlags] / syscall.count,
				syscall.types[compTypeLen] / syscall.count,
				syscall.types[compTypeData] / syscall.count,
				syscall.types[compTypeCompressed] / syscall.count,
				syscall.types[compTypeTotal] / syscall.count,
			},
		})
	}
	sort.Slice(syscalls, func(i, j int) bool {
		if syscalls[i].types[compTypeTotal] != syscalls[j].types[compTypeTotal] {
			return syscalls[i].types[compTypeTotal] > syscalls[j].types[compTypeTotal]
		}
		return syscalls[i].name < syscalls[j].name
	})
	fmt.Fprintf(w, "Per syscall info\n")
	for _, s := range syscalls {
		fmt.Fprintf(w, "%-50v: hints %5v comps %5v replacers %5v const %4v int %4v flags %4v len %4v data %4v compressed %4v\n",
			s.name, s.count, s.comps, s.types[compTypeTotal],
			s.types[compTypeConst], s.types[compTypeInt], s.types[compTypeFlags],
			s.types[compTypeLen], s.types[compTypeData], s.types[compTypeCompressed])
	}
	fmt.Fprintf(w, "\n")
	types := maps.Clone(compTypes)
	for k, v := range types {
		types[k] = v / total
	}	
	dumpCompStat(w, types, "Replacer types")
	dumpCompStat(w, compReplacers, "Replacers per type")
	dumpCompStat(w, compArgs, "Comparison arguments")
}

func dumpCompStat(w io.Writer, m map[string]int, name string) {
	type stat struct {
		what string
		val  int
	}
	total := 0
	stats := make([]stat, 0, len(m))
	for k, v := range m {
		total += v
		stats = append(stats, stat{k, v})
	}
	sort.Slice(stats, func(i, j int) bool {
		if stats[i].val != stats[j].val {
			return stats[i].val > stats[j].val
		}
		return stats[i].what < stats[j].what
	})
	fmt.Fprintf(w, "%v (total %v records with %v sum)\n", name, len(stats), total)
	for _, s := range stats[:min(len(stats), 1000)] {
		fmt.Fprintf(w, "%-50v: %v\n", s.what, s.val)
	}
	if len(stats) > 1000 {
		fmt.Fprintf(w, "\n...\n")
		for _, s := range stats[len(stats)-100:] {
			fmt.Fprintf(w, "%-50v: %v\n", s.what, s.val)
		}
	}
	fmt.Fprintf(w, "\n")
}

// Example: for comparisons {(op1, op2), (op1, op3), (op1, op4), (op2, op1)}
// this map will store the following:
//
//	m = {
//			op1: {map[op2]: true, map[op3]: true, map[op4]: true},
//			op2: {map[op1]: true}
//	}.
type CompMap map[uint64]map[uint64]bool

const (
	maxDataLength = 100
)

var specialIntsSet map[uint64]bool

func (m CompMap) AddComp(arg1, arg2 uint64) {
	if _, ok := m[arg1]; !ok {
		m[arg1] = make(map[uint64]bool)
	}
	m[arg1][arg2] = true
}

func (m CompMap) String() string {
	buf := new(bytes.Buffer)
	for v, comps := range m {
		if len(buf.Bytes()) != 0 {
			fmt.Fprintf(buf, ", ")
		}
		fmt.Fprintf(buf, "0x%x:", v)
		for c := range comps {
			fmt.Fprintf(buf, " 0x%x", c)
		}
	}
	return buf.String()
}

// InplaceIntersect() only leaves the value pairs that are also present in other.
func (m CompMap) InplaceIntersect(other CompMap) {
	for val1, nested := range m {
		for val2 := range nested {
			if !other[val1][val2] {
				delete(nested, val2)
			}
		}
		if len(nested) == 0 {
			delete(m, val1)
		}
	}
}

// Mutates the program using the comparison operands stored in compMaps.
// For each of the mutants executes the exec callback.
// The callback must return whether we should continue substitution (true)
// or abort the process (false).
func (p *Prog) MutateWithHints(callIndex int, comps CompMap, exec func(p *Prog) bool) {
	statsMu.Lock()
	total := 0
	for arg1, args2 := range comps {
		for arg2 := range args2 {
			compArgs[fmt.Sprintf("0x%x - 0x%x", arg1, arg2)]++
			total++
		}
	}
	callName := p.Calls[callIndex].Meta.Name
	syscall := syscallHints[callName]
	if syscall == nil {
		syscall = &perSyscall{
			name: callName,
		}
		syscallHints[callName] = syscall
	}
	syscall.count++
	syscall.comps += total
	statsMu.Unlock()

	p = p.Clone()
	c := p.Calls[callIndex]
	doMore := true
	execValidate := func(compType compType, replacer uint64) bool {
		// Don't try to fix the candidate program.
		// Assuming the original call was sanitized, we've got a bad call
		// as the result of hint substitution, so just throw it away.
		if p.Target.sanitize(c, false) != nil {
			return true
		}
		if p.checkConditions() != nil {
			// Patching unions that no longer satisfy conditions would
			// require much deeped changes to prog arguments than
			// generateHints() expects.
			// Let's just ignore such mutations.
			return true
		}
		statsMu.Lock()
		syscall.types[compType]++
		syscall.types[compTypeTotal]++
		compTypes[compType.String()]++
		compTypes[compTypeTotal.String()]++
		compReplacers[fmt.Sprintf("%s 0x%x", compType, replacer)]++
		statsMu.Unlock()

		p.debugValidate()
		doMore = exec(p)
		return doMore
	}
	ForeachArg(c, func(arg Arg, ctx *ArgCtx) {
		if !doMore {
			ctx.Stop = true
			return
		}
		generateHints(comps, arg, execValidate)
	})
}

func generateHints(compMap CompMap, arg Arg, exec func(compType, uint64) bool) {
	typ := arg.Type()
	if typ == nil || arg.Dir() == DirOut {
		return
	}
	switch t := typ.(type) {
	case *ProcType:
		// Random proc will not pass validation.
		// We can mutate it, but only if the resulting value is within the legal range.
		return
	case *ConstType:
		if IsPad(typ) {
			return
		}
	case *CsumType:
		// Csum will not pass validation and is always computed.
		return
	case *BufferType:
		switch t.Kind {
		case BufferFilename:
			// This can generate escaping paths and is probably not too useful anyway.
			return
		case BufferString, BufferGlob:
			if len(t.Values) != 0 {
				// These are frequently file names or complete enumerations.
				// Mutating these may be useful iff we intercept strcmp
				// (and filter out file names).
				return
			}
		}
	}

	switch a := arg.(type) {
	case *ConstArg:
		checkConstArg(a, compMap, exec)
	case *DataArg:
		if typ.(*BufferType).Kind == BufferCompressed {
			checkCompressedArg(a, compMap, exec)
		} else {
			checkDataArg(a, compMap, exec)
		}
	}
}

func checkConstArg(arg *ConstArg, compMap CompMap, exec func(compType, uint64) bool) {
	original := arg.Val
	// Note: because shrinkExpand returns a map, order of programs is non-deterministic.
	// This can affect test coverage reports.
	for _, replacer := range shrinkExpand(original, compMap, arg.Type().TypeBitSize(), false) {
		typ := compTypeConst
		switch arg.Type().(type) {
		case *IntType:
			typ = compTypeInt
		case *FlagsType:
			typ = compTypeFlags
		case *LenType:
			typ = compTypeLen
		}
		arg.Val = replacer
		if !exec(typ, replacer) {
			break
		}
	}
	arg.Val = original
}

func checkDataArg(arg *DataArg, compMap CompMap, exec func(compType, uint64) bool) {
	bytes := make([]byte, 8)
	data := arg.Data()
	size := len(data)
	if size > maxDataLength {
		size = maxDataLength
	}
	for i := 0; i < size; i++ {
		original := make([]byte, 8)
		copy(original, data[i:])
		val := binary.LittleEndian.Uint64(original)
		for _, replacer := range shrinkExpand(val, compMap, 64, false) {
			binary.LittleEndian.PutUint64(bytes, replacer)
			copy(data[i:], bytes)
			if !exec(compTypeData, replacer) {
				break
			}
		}
		copy(data[i:], original)
	}
}

func checkCompressedArg(arg *DataArg, compMap CompMap, exec func(compType, uint64) bool) {
	data0 := arg.Data()
	data, dtor := image.MustDecompress(data0)
	defer dtor()
	// Images are very large so the generic algorithm for data arguments
	// can produce too many mutants. For images we consider only
	// 4/8-byte aligned ints. This is enough to handle all magic
	// numbers and checksums. We also ignore 0 and ^uint64(0) source bytes,
	// because there are too many of these in lots of images.
	bytes := make([]byte, 8)
	for i := 0; i < len(data); i += 4 {
		original := make([]byte, 8)
		copy(original, data[i:])
		val := binary.LittleEndian.Uint64(original)
		for _, replacer := range shrinkExpand(val, compMap, 64, true) {
			binary.LittleEndian.PutUint64(bytes, replacer)
			copy(data[i:], bytes)
			arg.SetData(image.Compress(data))
			if !exec(compTypeCompressed, replacer) {
				break
			}
		}
		copy(data[i:], original)
	}
	arg.SetData(data0)
}

// Shrink and expand mutations model the cases when the syscall arguments
// are casted to narrower (and wider) integer types.
//
// Motivation for shrink:
//
//	void f(u16 x) {
//			u8 y = (u8)x;
//			if (y == 0xab) {...}
//	}
//
// If we call f(0x1234), then we'll see a comparison 0x34 vs 0xab and we'll
// be unable to match the argument 0x1234 with any of the comparison operands.
// Thus we shrink 0x1234 to 0x34 and try to match 0x34.
// If there's a match for the shrank value, then we replace the corresponding
// bytes of the input (in the given example we'll get 0x12ab).
// Sometimes the other comparison operand will be wider than the shrank value
// (in the example above consider comparison if (y == 0xdeadbeef) {...}).
// In this case we ignore such comparison because we couldn't come up with
// any valid code example that does similar things. To avoid such comparisons
// we check the sizes with leastSize().
//
// Motivation for expand:
//
//	void f(i8 x) {
//			i16 y = (i16)x;
//			if (y == -2) {...}
//	}
//
// Suppose we call f(-1), then we'll see a comparison 0xffff vs 0xfffe and be
// unable to match input vs any operands. Thus we sign extend the input and
// check the extension.
// As with shrink we ignore cases when the other operand is wider.
// Note that executor sign extends all the comparison operands to int64.
func shrinkExpand(v uint64, compMap CompMap, bitsize uint64, image bool) []uint64 {
	v = truncateToBitSize(v, bitsize)
	limit := uint64(1<<bitsize - 1)
	var replacers map[uint64]bool
	for _, iwidth := range []int{8, 4, 2, 1, -4, -2, -1} {
		var width int
		var size, mutant uint64
		if iwidth > 0 {
			width = iwidth
			size = uint64(width) * 8
			mutant = v & ((1 << size) - 1)
		} else {
			width = -iwidth
			size = uint64(width) * 8
			if size > bitsize {
				size = bitsize
			}
			if v&(1<<(size-1)) == 0 {
				continue
			}
			mutant = v | ^((1 << size) - 1)
		}
		if image {
			// For images we can produce too many mutants for small integers.
			if width < 4 {
				continue
			}
			if mutant == 0 || (mutant|^((1<<size)-1)) == ^uint64(0) {
				continue
			}
		}
		// Use big-endian match/replace for both blobs and ints.
		// Sometimes we have unmarked blobs (no little/big-endian info);
		// for ANYBLOBs we intentionally lose all marking;
		// but even for marked ints we may need this too.
		// Consider that kernel code does not convert the data
		// (i.e. not ntohs(pkt->proto) == ETH_P_BATMAN),
		// but instead converts the constant (i.e. pkt->proto == htons(ETH_P_BATMAN)).
		// In such case we will see dynamic operand that does not match what we have in the program.
		for _, bigendian := range []bool{false, true} {
			if bigendian {
				if width == 1 {
					continue
				}
				mutant = swapInt(mutant, width)
			}
			for newV := range compMap[mutant] {
				// Check the limit for negative numbers.
				if newV > limit && ((^(limit >> 1) & newV) != ^(limit >> 1)) {
					continue
				}
				mask := uint64(1<<size - 1)
				newHi := newV & ^mask
				newV = newV & mask
				if newHi != 0 && newHi^^mask != 0 {
					continue
				}
				if bigendian {
					newV = swapInt(newV, width)
				}
				// We insert special ints (like 0) with high probability,
				// so we don't try to replace to special ints them here.
				// Images are large so it's hard to guess even special
				// ints with random mutations.
				if !image && specialIntsSet[newV] {
					continue
				}
				// Replace size least significant bits of v with
				// corresponding bits of newV. Leave the rest of v as it was.
				replacer := (v &^ mask) | newV
				if replacer == v {
					continue
				}
				replacer = truncateToBitSize(replacer, bitsize)
				// TODO(dvyukov): should we try replacing with arg+/-1?
				// This could trigger some off-by-ones.
				if replacers == nil {
					replacers = make(map[uint64]bool)
				}
				replacers[replacer] = true
			}
		}
	}
	if replacers == nil {
		return nil
	}
	res := make([]uint64, 0, len(replacers))
	for v := range replacers {
		res = append(res, v)
	}
	sort.Slice(res, func(i, j int) bool {
		return res[i] < res[j]
	})
	return res
}

func init() {
	specialIntsSet = make(map[uint64]bool)
	for _, v := range specialInts {
		specialIntsSet[v] = true
	}
}
