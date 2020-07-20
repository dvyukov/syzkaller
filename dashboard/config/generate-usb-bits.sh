CC="${CC:-gcc}"
THIS_DIR=`cd $(dirname $0); pwd`
MERGE_USB_SCRIPT=${THIS_DIR}/kconfiglib-merge-usb-configs.py

# OUTPUT_CONFIG=${THIS_DIR}/upstream-usb.config

cd ${SOURCEDIR}

rm .config
make defconfig
make kvmconfig
make olddefconfig
cp .config .defconfig

rm -rf ./Kconfiglib
git clone --depth=1 https://github.com/ulfalizer/Kconfiglib.git
wget -qO- https://raw.githubusercontent.com/ulfalizer/Kconfiglib/master/makefile.patch | patch -p1

configs=""
for config in ${THIS_DIR}/distros/${prefix}*; do
	configs+="${config},"
done

make ${MAKE_VARS} scriptconfig SCRIPT=${MERGE_USB_SCRIPT} SCRIPT_ARG=${configs}
git checkout ./scripts/kconfig/Makefile
rm -rf ./Kconfiglib

make olddefconfig
