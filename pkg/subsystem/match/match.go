// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package match

import (
	"regexp"
	"strings"

	"github.com/google/syzkaller/pkg/subsystem/entity"
)

type PathMatcher struct {
	matches []*match
}

type match struct {
	include *regexp.Regexp
	exclude *regexp.Regexp
	object  *entity.Subsystem
}

func MakePathMatcher(list []*entity.Subsystem) (*PathMatcher, error) {
	m := &PathMatcher{}
	for _, item := range list {
		err := m.register(item)
		if err != nil {
			return nil, err
		}
	}
	return m, nil
}

func (p *PathMatcher) register(item *entity.Subsystem) error {
	onlyInclude := []string{}
	list := []entity.PathRule{}
	for _, r := range item.PathRules {
		if r.ExcludeRegexp == "" {
			// It's expected that almost everything will go to this branch.
			onlyInclude = append(onlyInclude, r.IncludeRegexp)
		} else {
			list = append(list, r)
		}
	}
	if len(onlyInclude) > 0 {
		list = append(list, entity.PathRule{
			IncludeRegexp: strings.Join(onlyInclude, "|"),
		})
	}
	for _, rule := range list {
		m, err := buildMatch(rule, item)
		if err != nil {
			return err
		}
		p.matches = append(p.matches, m)
	}
	return nil
}

func (p *PathMatcher) Match(path string) []*entity.Subsystem {
	ret := []*entity.Subsystem{}
	for _, m := range p.matches {
		if m.exclude != nil && m.exclude.MatchString(path) {
			continue
		}
		if m.include != nil && !m.include.MatchString(path) {
			continue
		}
		ret = append(ret, m.object)
	}
	return ret
}

func buildMatch(rule entity.PathRule, item *entity.Subsystem) (*match, error) {
	var err error
	m := &match{object: item}
	if rule.IncludeRegexp != "" {
		m.include, err = regexp.Compile(rule.IncludeRegexp)
		if err != nil {
			return nil, err
		}
	}
	if rule.ExcludeRegexp != "" {
		m.exclude, err = regexp.Compile(rule.ExcludeRegexp)
		if err != nil {
			return nil, err
		}
	}
	return m, nil
}
