// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package linux

import (
	"testing"

	"github.com/google/syzkaller/pkg/subsystem/entity"
)

func TestEmailToName(t *testing.T) {
	tests := map[string]string{
		// These are following the general rules.
		"linux-nilfs@vger.kernel.org":           "nilfs",
		"tomoyo-dev-en@lists.osdn.me":           "tomoyo",
		"tipc-discussion@lists.sourceforge.net": "tipc",
		"v9fs-developer@lists.sourceforge.net":  "v9fs",
		"zd1211-devs@lists.sourceforge.net":     "zd1211",
		// Test that we can handle exceptions.
		"virtualization@lists.linux-foundation.org": "virt",
	}
	for email, name := range tests {
		result := emailToName(email)
		if result != name {
			t.Fatalf("%#v: expected %#v, got %#v", email, name, result)
		}
	}
}

func TestSetSubsystemNames(t *testing.T) {
	test := []struct {
		inName  string
		email   string
		outName string
	}{
		{
			inName:  "ext4",
			email:   "",
			outName: "ext4",
		},
		{
			inName:  "ntfs",
			email:   "",
			outName: "ntfs",
		},
		{
			inName:  "",
			email:   "linux-ntfs-dev@lists.sourceforge.net",
			outName: "linux-ntfs-dev@lists.sourceforge.net", // duplicate name
		},
		{
			inName:  "",
			email:   "llvm@lists.linux.dev",
			outName: "llvm",
		},
		{
			inName:  "",
			email:   "llvm@abcd.com",
			outName: "llvm@abcd.com", // duplicate
		},
	}
	input := []*entity.Subsystem{}
	for _, item := range test {
		s := &entity.Subsystem{Name: item.inName}
		if item.email != "" {
			s.Lists = append(s.Lists, item.email)
		}
		input = append(input, s)
	}
	err := setSubsystemNames(input)
	if err != nil {
		t.Fatal(err)
	}
	for i, item := range test {
		if item.outName != input[i].Name {
			t.Fatalf("invalid name for #%d: expected %#v, got %#v",
				i+1, item.outName, input[i].Name,
			)
		}
	}
}
