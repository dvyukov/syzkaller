#!/usr/bin/env python
# Copyright 2017 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

from __future__ import print_function
import os
import re
import sys

link_re = re.compile('\[' + '[^\[\]]+' + '\]' + '\(' + '([^\(\)]+)' + '\)')

if len(sys.argv) < 3:
	print('Usage: <root_dir> <doc_files>...')
	sys.exit(1)

root = sys.argv[1]
docs = sys.argv[2:]

links = []

for doc in docs:
	with open(doc) as f:
		for i, line in enumerate(f.readlines()):
			for match in link_re.finditer(line):
				links += [(doc, match.group(1), i + 1, match.start(1))]

def filter_link(args):
	(doc, link, line, col) = args
	if link.startswith('http'):
		return False
	if link.startswith('#'):
		return False
	if link.startswith('mailto'):
		return False
	return True

links = list(filter(filter_link, links))

def fix_link(args):
	(doc, link, line, col) = args
	link = link.split('#')[0]
	link = link.split('?')[0]
	return (doc, link, line, col)

links = list(map(fix_link, links))

errors = []

def check_link(args):
	(doc, link, line, col) = args
	path = os.path.dirname(doc)
	full_link = None
	if link[0] == '/':
		link = link[1:]
		full_link = os.path.join(root, link)
	else:
		full_link = os.path.join(root, path, link)
	if not os.path.exists(full_link):
		return False
	return True

for link in links:
	if not check_link(link):
		errors += [link]

if len(errors) == 0:
	print('%d links checked: OK' % (len(links),))
	sys.exit(0)

for (doc, link, line, col) in errors:
	print('%s:%d:%d: Broken link %s.' % (doc, line, col, link))

sys.exit(2)
