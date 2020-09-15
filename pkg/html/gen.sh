#!/bin/bash
# Copyright 2020 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

set -eu

echo '// Code generated by pkg/html/html.go. DO NOT EDIT.' > generated.go
echo 'package html' >> generated.go
echo 'const style = `' >> generated.go
cat ../../dashboard/app/static/style.css >> generated.go
echo '`' >> generated.go
echo 'const js = `' >> generated.go
cat ../../dashboard/app/static/common.js >> generated.go
echo '`' >> generated.go
