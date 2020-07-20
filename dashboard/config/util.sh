#!/bin/bash
# Copyright 2019 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

# This script provides utility functions, don't use it directly.

set -eux

[ -z "${CC}" ] && echo 'Please set $CC to point to the compiler!' && exit

THIS_DIR=`cd "${BASH_SOURCE[0]}"; pwd`
MAKE_VARS="CC=${CC}"

function util_add_syzbot_bits {
  scripts/kconfig/merge_config.sh -m .config ${THIS_DIR}/bits-syzbot.config
  if [ "$#" == "1" ]; then
    if [ "$1" == "aux-debug" ]; then
      scripts/kconfig/merge_config.sh -m .config ${THIS_DIR}/bits-syzbot-aux-debug.config
    fi
  fi
  # Fix up config.
  make ${MAKE_VARS} olddefconfig
  # syzbot does not support modules.
  sed -i "s#=m\$#=y#g" .config
  # Fix up configs that can only be modules.
  make ${MAKE_VARS} olddefconfig
}

function util_add_syzbot_extra_bits {
  TMP_FILE=$(mktemp /tmp/syzkaller.XXXXXX)
  echo "# The following configs are added manually, preserve them.
# CONFIG_DEBUG_MEMORY was once added to mm tree and cause disabling of KASAN,
# which in turn caused storm of assorted crashes after silent memory
# corruptions. The config was reverted, but we keep it here for the case
# it is reintroduced to kernel again.
CONFIG_DEBUG_MEMORY=y
# This config can be used to enable any additional temporal debugging
# features in linux-next tree.
CONFIG_DEBUG_AID_FOR_SYZBOT=y
# These configs can be used to prevent fuzzers from trying stupid things.
# See https://github.com/google/syzkaller/issues/1622 for details.
CONFIG_TWIST_KERNEL_BEHAVIOR=y
CONFIG_TWIST_FOR_SYZKALLER_TESTING=y
" > ${TMP_FILE}
  cat .config >> ${TMP_FILE}
  mv ${TMP_FILE} .config
  rm -rf ${TMP_FILE}
}
