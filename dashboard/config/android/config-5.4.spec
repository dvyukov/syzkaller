### This is a commit from android-5.4 branch, are there any better tags to use?
kernel https://android.googlesource.com/kernel/common cdedb91e2984
compiler clang
### compiler ${KERNEL}/prebuilts-master/clang/host/linux-x86/clang-r370808/bin/clang

make gki_defconfig

include ../linux/bits/x86_64
include ../linux/bits/kasan

### TODO:
### util_add_usb_bits "android"

include config-bits
