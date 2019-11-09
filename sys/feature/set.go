// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build !generate

package feature

import (
	"fmt"
)

type Set struct {
	flags
	custom
	All []Feature
}

type custom struct {
	Executor  string
	Procs     int
	FaultCall int
	FaultNth  int
}

func Make(OS string) *Set {
	set := new(Set)
	for i, feat := range All {
		feat.Enabled = field(&set.flags, i)
		if feat.SupportedOn(OS) {
			feat.Supported = true
			feat.Present = true
		}
		set.All = append(set.All, feat)
	}
	return set
}

// Serial is feature representation suitable for passing in RPCs
// (can't pass List since it contains pointers to itself).
type Serial struct {
	Name      string
	Supported bool
	Present   bool
	Enabled   bool
	Reason    string
}

type Serialized struct {
	custom
	All []Serial
}

func (set *Set) Serialize() *Serialized {
	ss := &Serialized{
		custom: set.custom,
	}
	for _, feat := range set.All {
		ss.All = append(ss.All, Serial{
			Name:      feat.Name,
			Supported: feat.Supported,
			Present:   feat.Present,
			Enabled:   *feat.Enabled,
			Reason:    feat.Reason,
		})
	}
	return ss
}

func (ss *Serialized) Deserialize() (*Set, error) {
	if len(ss.All) != len(All) {
		return nil, fmt.Errorf("serialized features contain %v entries, want %v",
			len(ss.All), len(All))
	}
	set := new(Set)
	set.custom = ss.custom
	for i, feat := range All {
		s := ss.All[i]
		if s.Name != feat.Name {
			return nil, fmt.Errorf("bad serialized feature name %v, want %v",
				s.Name, feat.Name)
		}
		feat.Enabled = field(&set.flags, i)
		feat.Supported = s.Supported
		feat.Present = s.Present
		*feat.Enabled = s.Enabled
		feat.Reason = s.Reason
		set.All = append(set.All, feat)
	}
	return set, nil
}

func (set *Set) Copy() *Set {
	new := *set
	for i := range new.All {
		feat := &new.All[i]
		feat.Enabled = field(&new.flags, i)
	}
	return &new
}

func (set *Set) Enabled() []Feature {
	var res []Feature
	for _, feat := range set.All {
		if *feat.Enabled {
			res = append(res, feat)
		}
	}
	return res
}

func (set *Set) Supported() []Feature {
	var res []Feature
	for _, feat := range set.All {
		if feat.Supported && len(feat.OS) != 0 {
			res = append(res, feat)
		}
	}
	return res
}

func (set *Set) Check() error {
	fmt.Printf("checking features:\n")
	for _, feat := range set.All {
		fmt.Printf("  %v: supp=%v present='%v' enabled=%v\n",
			feat.CppName, feat.Supported, feat.Reason, *feat.Enabled)
	}

	index := make(map[string]ID)
	for _, feat := range All {
		index[feat.Name] = feat.ID
	}
	for _, feat := range set.All {
		if !feat.Supported && feat.Present {
			return fmt.Errorf("feature %v is not supported but present", feat.Name)
		}
		if !feat.Supported && *feat.Enabled {
			return fmt.Errorf("feature %v can't be enabled (not supported on OS)", feat.Name)
		}
		if !feat.Present && *feat.Enabled {
			return fmt.Errorf("feature %v can't be enabled (not present in kernel)", feat.Name)
		}
		if !*feat.Enabled {
			continue
		}
		for _, dep := range feat.Deps {
			expected := true
			if dep != "" && dep[0] == '-' {
				dep = dep[1:]
				expected = false
			}
			i, ok := index[dep]
			if !ok {
				return fmt.Errorf("feature %v depends on unknown feature %v",
					feat.Name, dep)
			}
			if *set.All[i].Enabled != expected {
				msg := "feature %v depends on disabled feature %v"
				if !expected {
					msg = "feature %v conflicts with enabled feature %v"
				}
				return fmt.Errorf(msg, feat.Name, dep)
			}
		}
	}
	nsandbox := 0
	for _, id := range sandboxes {
		if *set.All[id].Enabled {
			nsandbox++
		}
	}
	if nsandbox != 1 {
		return fmt.Errorf("%v sandboxes enabled", nsandbox)
	}
	return nil
}

func (set *Set) Simplify(i int) *Set {
	return nil
}
