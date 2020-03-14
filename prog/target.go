// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"fmt"
	"math/rand"
	"sort"
	"sync"
	"sync/atomic"
)

// Target describes target OS/arch pair.
type Target struct {
	OS         string
	Arch       string
	Revision   string // unique hash representing revision of the descriptions
	PtrSize    uint64
	PageSize   uint64
	NumPages   uint64
	DataOffset uint64

	Syscalls  []*Syscall
	Resources []*ResourceDesc
	Consts    []ConstValue

	// MakeDataMmap creates calls that mmaps target data memory range.
	MakeDataMmap func() []*Call

	// Neutralize neutralizes harmful calls by transforming them into non-harmful ones
	// (e.g. an ioctl that turns off console output is turned into ioctl that turns on output).
	Neutralize func(c *Call)

	// AnnotateCall annotates a syscall invocation in C reproducers.
	// The returned string will be placed inside a comment except for the
	// empty string which will omit the comment.
	AnnotateCall func(c ExecCall) string

	// SpecialTypes allows target to do custom generation/mutation for some struct's and union's.
	// Map key is struct/union name for which custom generation/mutation is required.
	// Map value is custom generation/mutation function that will be called
	// for the corresponding type. g is helper object that allows generate random numbers,
	// allocate memory, etc. typ is the struct/union type. old is the old value of the struct/union
	// for mutation, or nil for generation. The function returns a new value of the struct/union,
	// and optionally any calls that need to be inserted before the arg reference.
	SpecialTypes map[string]func(g *Gen, typ Type, dir Dir, old Arg) (Arg, []*Call)

	// Special strings that can matter for the target.
	// Used as fallback when string type does not have own dictionary.
	StringDictionary []string

	// Resources that play auxiliary role, but widely used throughout all syscalls (e.g. pid/uid).
	AuxResources map[string]bool

	// Additional special invalid pointer values besides NULL to use.
	SpecialPointers []uint64

	// Filled by prog package:
	SyscallMap map[string]*Syscall
	ConstMap   map[string]uint64

	init        sync.Once
	initArch    func(target *Target)
	types       []Type
	resourceMap map[string]*ResourceDesc
	// Maps resource name to a list of calls that can create the resource.
	resourceCtors map[string][]*Syscall
	any           anyTypes

	// The default ChoiceTable is used only by tests and utilities, so we initialize it lazily.
	defaultOnce             sync.Once
	defaultChoiceTable      *ChoiceTable
	initDiscriminationsOnce sync.Once
}

const maxSpecialPointers = 16

var targets = make(map[string]*Target)

func RegisterTarget(target *Target, types []Type, initArch func(target *Target)) {
	key := target.OS + "/" + target.Arch
	if targets[key] != nil {
		panic(fmt.Sprintf("duplicate target %v", key))
	}
	target.initArch = initArch
	target.types = types
	targets[key] = target
}

func GetTarget(OS, arch string) (*Target, error) {
	if OS == "android" {
		OS = "linux"
	}
	key := OS + "/" + arch
	target := targets[key]
	if target == nil {
		var supported []string
		for _, t := range targets {
			supported = append(supported, fmt.Sprintf("%v/%v", t.OS, t.Arch))
		}
		sort.Strings(supported)
		return nil, fmt.Errorf("unknown target: %v (supported: %v)", key, supported)
	}
	target.init.Do(target.lazyInit)
	return target, nil
}

func AllTargets() []*Target {
	var res []*Target
	for _, target := range targets {
		target.init.Do(target.lazyInit)
		res = append(res, target)
	}
	sort.Slice(res, func(i, j int) bool {
		if res[i].OS != res[j].OS {
			return res[i].OS < res[j].OS
		}
		return res[i].Arch < res[j].Arch
	})
	return res
}

func (target *Target) lazyInit() {
	target.Neutralize = func(c *Call) {}
	target.AnnotateCall = func(c ExecCall) string { return "" }
	target.initTarget()
	target.initArch(target)
	// Give these 2 known addresses fixed positions and prepend target-specific ones at the end.
	target.SpecialPointers = append([]uint64{
		0x0000000000000000, // NULL pointer (keep this first because code uses special index=0 as NULL)
		0xffffffffffffffff, // unmapped kernel address (keep second because serialized value will match actual pointer value)
		0x9999999999999999, // non-canonical address
	}, target.SpecialPointers...)
	if len(target.SpecialPointers) > maxSpecialPointers {
		panic("too many special pointers")
	}
	// These are used only during lazyInit.
	target.ConstMap = nil
	target.types = nil
}

func (target *Target) initTarget() {
	target.ConstMap = make(map[string]uint64)
	for _, c := range target.Consts {
		target.ConstMap[c.Name] = c.Value
	}

	target.resourceMap = restoreLinks(target.Syscalls, target.Resources, target.types)
	target.initAnyTypes()

	target.SyscallMap = make(map[string]*Syscall)
	for i, c := range target.Syscalls {
		c.ID = i
		target.SyscallMap[c.Name] = c
		c.inputResources = target.getInputResources(c)
		c.outputResources = target.getOutputResources(c)
	}

	target.populateResourceCtors()
	target.resourceCtors = make(map[string][]*Syscall)
	for _, res := range target.Resources {
		target.resourceCtors[res.Name] = target.calcResourceCtors(res, false)
	}
}

func (target *Target) GetConst(name string) uint64 {
	if target.ConstMap == nil {
		panic("GetConst can only be used during target initialization")
	}
	v, ok := target.ConstMap[name]
	if !ok {
		panic(fmt.Sprintf("const %v is not defined for %v/%v", name, target.OS, target.Arch))
	}
	return v
}

func (target *Target) sanitize(c *Call, fix bool) error {
	if err := target.sanitizeDiscriminations(c, fix); err != nil {
		return err
	}
	target.Neutralize(c)
	return nil
}

const maxConstraints = 4

type (
	discriminationConstraint struct {
		argIdx [maxConstraints]uint8
		argVal [maxConstraints]uint64
	}
	discriminationGroup struct {
		id          string
		constraints map[discriminationConstraint]map[int]bool
	}
)

func (target *Target) sanitizeDiscriminations(c *Call, fix bool) error {
	//return nil

	target.initDiscriminationsOnce.Do(target.initDiscriminations)
	fixLimit := -1
	if fix {
		fixLimit = 1000
	}
	return target.sanitizeDiscriminationArg(c, 0, 0, fixLimit, &discriminationConstraint{})
}

func (target *Target) sanitizeDiscriminationArg(c *Call, argIdx, constraintPos, fixLimit int, constraint *discriminationConstraint) error {
	if argIdx >= len(c.Args) {
		return nil
	}
	//if c.Meta.Name == "mutate_integer" {
	//	fmt.Printf("sanitizeDiscriminationArg: argIdx=%v constraintPos=%v constraint=%+v\n", argIdx, constraintPos, *constraint)
	//}
	arg, ok := c.Args[argIdx].(*ConstArg)
	if ok {

		//return fmt.Sprintf("%v=0x%x,", a.Type().FieldName(), v), optional
		argVal, _ := arg.Value()
		argVal = truncateToBitSize(argVal, arg.Type().TypeBitSize())

		constraint.argIdx[constraintPos] = uint8(argIdx)
		constraint.argVal[constraintPos] = argVal
		calls := c.Meta.group.constraints[*constraint]
		//fmt.Printf("ARG %v, constraint=%v part=%v optional=%v calls=%v\n", argIdx, constraint, part, optional, calls)

		//fmt.Printf("%v: CHECKING: %+v CALLS: %v\n", c.Meta.Name, *constraint, calls)

		if len(calls) != 0 && !calls[c.Meta.ID] {
			if fixLimit < 0 {
				return target.discriminationError(c, constraint, calls)
			}
			if fixLimit == 0 {
				panic(fmt.Sprintf("infinite discrimination fix: call %v [%v], arg %v [%T], constraint %+v",
					c.Meta.Name, c.Meta.group.id, argIdx, arg.Type(), *constraint))
			}
			//fmt.Printf("%v: FIXING arg %v: 0x%x", c.Meta.Name, argIdx, arg.Val)
			switch typ := arg.Type().(type) {
			case *ConstType:
				arg.Val = typ.Val
			case *FlagsType:
				arg.Val = typ.Vals[0]
			case *IntType:
				arg.Val++
			default:
				panic(fmt.Sprintf("call %v, arg %v, unhandled type %T, constraint %+v", c.Meta.Name, argIdx, typ, *constraint))
			}
			//fmt.Printf(" -> 0x%x\n", arg.Val)
			return target.sanitizeDiscriminationArg(c, argIdx, constraintPos, fixLimit-1, constraint)
		}

		switch arg.Type().(type) {
		case *ConstType, *FlagsType, *ProcType:
		default:
			return target.sanitizeDiscriminationArg(c, argIdx+1, constraintPos, fixLimit, constraint)
			//if err := target.sanitizeDiscriminationArg(c, argIdx+1, constraintPos, fixLimit, constraint); err != nil {
			//		return err
			//		}
			//!!! constraint.argIdx[constraintPos] = uint8(argIdx)
			//!!! constraint.argVal[constraintPos] = argVal
		}

		constraintPos++
	}
	return target.sanitizeDiscriminationArg(c, argIdx+1, constraintPos, fixLimit, constraint)
}

func (target *Target) discriminationError(c *Call, constraint *discriminationConstraint, calls map[int]bool) error {
	args := ""
	for i, arg := range constraint.argIdx {
		if i != 0 && arg == 0 {
			break
		}
		args += fmt.Sprintf("%v=0x%x,", c.Meta.Args[arg].Name, constraint.argVal[i])
	}
	var names []string
	for id := range calls {
		names = append(names, target.Syscalls[id].Name)
	}
	sort.Strings(names)
	return fmt.Errorf("call %v has args %v allowed calls with such args: %v",
		c.Meta.Name, args, names)
}

func (target *Target) initDiscriminations() {
	//!!!prune empty groups and short-circuit
	groups := make(map[string]*discriminationGroup)
	groupCalls := make(map[string][]string)
	for _, call := range target.Syscalls {
		id := call.CallName
		for i, field := range call.Args {
			switch arg := field.Type.(type) {
			case *ResourceType:
				id += fmt.Sprintf("-%v:%v", i, arg.Name())
			case *PtrType:
				if typ, ok := arg.Elem.(*BufferType); ok && typ.Kind == BufferString && len(typ.Values) == 1 {
					id += fmt.Sprintf("-%v:%v", i, typ.Values[0])
				}
			}
		}
		groupCalls[id] = append(groupCalls[id], call.Name)

		call.group = groups[id]
		if call.group == nil {
			call.group = &discriminationGroup{
				id:          id,
				constraints: make(map[discriminationConstraint]map[int]bool),
			}
			groups[id] = call.group
		}
		collectConstraints(call, 0, 0, -1, 0, &discriminationConstraint{})
	}
	if false {
		for id, group := range groups {
			if len(groupCalls[id]) == 1 || len(group.constraints) == 0 {
				//continue
			}
			if id != "syz_open_dev-0:/dev/video#" {
				//continue
			}
			fmt.Printf("\nGROUP: %v calls %v, constraints %v\n", id, len(groupCalls[id]), len(group.constraints))
			fmt.Printf("CALLS: %v\n", groupCalls[id])
			for constraint, calls := range group.constraints {
				for i, arg := range constraint.argIdx {
					if i != 0 && arg == 0 {
						break
					}
					fmt.Printf(" %v:0x%x", arg, constraint.argVal[i])
				}
				fmt.Printf(":")
				for call := range calls {
					fmt.Printf(" %v", target.Syscalls[call].Name)
				}
				fmt.Printf("\n")
			}
		}
	}
}

func collectConstraints(call *Syscall, argIdx, constraintPos, prevArgIdx int, prevArgVal uint64, constraint *discriminationConstraint) {
	if prevArgIdx != -1 {
		if constraintPos >= len(constraint.argIdx) {
			panic(fmt.Sprintf("%v: too many discrimination args: %+v", call.Name, *constraint))
		}

		constraint.argIdx[constraintPos] = uint8(prevArgIdx)
		constraint.argVal[constraintPos] = prevArgVal
		/*
		   if call.Name == "socket" {
		   fmt.Printf("COLLECT %v argIdx=%v, constraintPos=%v, prevArgIdx=%v, prevArgVal=0x%x, constraint=%v\n", call.Name, argIdx, constraintPos, prevArgIdx, prevArgVal, *constraint)
		   }
		*/
		constraintPos++
		defer func() {
			constraintPos--
			constraint.argIdx[constraintPos] = 0
			constraint.argVal[constraintPos] = 0
		}()

		calls := call.group.constraints[*constraint]
		if calls == nil {
			calls = make(map[int]bool)
			call.group.constraints[*constraint] = calls
		}
		calls[call.ID] = true
	}
	if argIdx == len(call.Args) {
		return
	}
	switch arg := call.Args[argIdx].Type.(type) {
	case *ConstType:
		//part := fmt.Sprintf("%v=0x%x,", arg.FieldName(), arg.Val)
		collectConstraints(call, argIdx+1, constraintPos, argIdx, arg.Val, constraint)
	case *ProcType:
		// This is required to allow at least the default value for ProcType.
		collectConstraints(call, argIdx+1, constraintPos, argIdx, 0, constraint)
	case *FlagsType:
		for _, v := range arg.Vals {
			v = truncateToBitSize(v, arg.TypeBitSize())
			collectConstraints(call, argIdx+1, constraintPos, argIdx, v, constraint)
		}
	default:
		collectConstraints(call, argIdx+1, constraintPos, -1, 0, constraint)
	}
}

func RestoreLinks(syscalls []*Syscall, resources []*ResourceDesc, types []Type) {
	restoreLinks(syscalls, resources, types)
}

var (
	typeRefMu sync.Mutex
	typeRefs  atomic.Value // []Type
)

func restoreLinks(syscalls []*Syscall, resources []*ResourceDesc, types []Type) map[string]*ResourceDesc {
	typeRefMu.Lock()
	defer typeRefMu.Unlock()
	refs := []Type{nil}
	if old := typeRefs.Load(); old != nil {
		refs = old.([]Type)
	}
	for _, typ := range types {
		typ.setRef(Ref(len(refs)))
		refs = append(refs, typ)
	}
	typeRefs.Store(refs)

	resourceMap := make(map[string]*ResourceDesc)
	for _, res := range resources {
		resourceMap[res.Name] = res
	}

	ForeachType(syscalls, func(typ Type, ctx TypeCtx) {
		if ref, ok := typ.(Ref); ok {
			typ = types[ref]
			*ctx.Ptr = typ
		}
		switch t := typ.(type) {
		case *ResourceType:
			t.Desc = resourceMap[t.TypeName]
			if t.Desc == nil {
				panic("no resource desc")
			}
		}
	})
	return resourceMap
}

func (target *Target) DefaultChoiceTable() *ChoiceTable {
	target.defaultOnce.Do(func() {
		target.defaultChoiceTable = target.BuildChoiceTable(nil, nil)
	})
	return target.defaultChoiceTable
}

type Gen struct {
	r *randGen
	s *state
}

func (g *Gen) Target() *Target {
	return g.r.target
}

func (g *Gen) Rand() *rand.Rand {
	return g.r.Rand
}

func (g *Gen) NOutOf(n, outOf int) bool {
	return g.r.nOutOf(n, outOf)
}

func (g *Gen) Alloc(ptrType Type, dir Dir, data Arg) (Arg, []*Call) {
	return g.r.allocAddr(g.s, ptrType, dir, data.Size(), data), nil
}

func (g *Gen) GenerateArg(typ Type, dir Dir, pcalls *[]*Call) Arg {
	return g.generateArg(typ, dir, pcalls, false)
}

func (g *Gen) GenerateSpecialArg(typ Type, dir Dir, pcalls *[]*Call) Arg {
	return g.generateArg(typ, dir, pcalls, true)
}

func (g *Gen) generateArg(typ Type, dir Dir, pcalls *[]*Call, ignoreSpecial bool) Arg {
	arg, calls := g.r.generateArgImpl(g.s, typ, dir, ignoreSpecial)
	*pcalls = append(*pcalls, calls...)
	g.r.target.assignSizesArray([]Arg{arg}, []Field{{Name: "", Type: arg.Type()}}, nil)
	return arg
}

func (g *Gen) MutateArg(arg0 Arg) (calls []*Call) {
	updateSizes := true
	for stop := false; !stop; stop = g.r.oneOf(3) {
		ma := &mutationArgs{target: g.r.target, ignoreSpecial: true}
		ForeachSubArg(arg0, ma.collectArg)
		if len(ma.args) == 0 {
			// TODO(dvyukov): probably need to return this condition
			// and updateSizes to caller so that Mutate can act accordingly.
			return
		}
		arg, ctx := ma.chooseArg(g.r.Rand)
		newCalls, ok := g.r.target.mutateArg(g.r, g.s, arg, ctx, &updateSizes)
		if !ok {
			continue
		}
		calls = append(calls, newCalls...)
	}
	return calls
}

type Builder struct {
	target *Target
	ma     *memAlloc
	p      *Prog
}

func MakeProgGen(target *Target) *Builder {
	return &Builder{
		target: target,
		ma:     newMemAlloc(target.NumPages * target.PageSize),
		p: &Prog{
			Target: target,
		},
	}
}

func (pg *Builder) Append(c *Call) error {
	pg.target.assignSizesCall(c)
	pg.target.sanitize(c, true)
	pg.p.Calls = append(pg.p.Calls, c)
	return nil
}

func (pg *Builder) Allocate(size uint64) uint64 {
	return pg.ma.alloc(nil, size)
}

func (pg *Builder) AllocateVMA(npages uint64) uint64 {
	psize := pg.target.PageSize
	addr := pg.ma.alloc(nil, (npages+1)*psize)
	return (addr + psize - 1) & ^(psize - 1)
}

func (pg *Builder) Finalize() (*Prog, error) {
	if err := pg.p.validate(); err != nil {
		return nil, err
	}
	if _, err := pg.p.SerializeForExec(make([]byte, ExecBufferSize)); err != nil {
		return nil, err
	}
	p := pg.p
	pg.p = nil
	return p, nil
}
