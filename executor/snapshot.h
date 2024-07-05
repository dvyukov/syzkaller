// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#include <dirent.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include <atomic>
#include <string>
#include <utility>

struct Ivshmem {
	// Ivshmem interrupt doorbell register.
	volatile uint32* doorbell;
	std::atomic<rpc::SnapshotState>* state;
	char* input;
	char* output;
};

// Finds qemu ivshmem device, see:
// https://www.qemu.org/docs/master/specs/ivshmem-spec.html
static std::string FindIvshmem()
{
	std::string result;
	DIR* devices = opendir("/sys/bus/pci/devices");
	while (auto* dev = readdir(devices)) {
		if (dev->d_name[0] == '.')
			continue;
		const std::string& vendor = ReadTextFile("/sys/bus/pci/devices/%s/vendor", dev->d_name);
		const std::string& device = ReadTextFile("/sys/bus/pci/devices/%s/device", dev->d_name);
		debug("PCI device %s: vendor=%s device=%s\n", dev->d_name, vendor.c_str(), device.c_str());
		if (vendor != "0x1af4" || device != "0x1110")
			continue;
		closedir(devices);
		return dev->d_name;
	}
	fail("cannot find ivshmem PCI device");
}

static Ivshmem IvshmemMmap()
{
	const std::string& dev = FindIvshmem();
	char filename[1024];
	snprintf(filename, sizeof(filename), "/sys/bus/pci/devices/%s/resource0", dev.c_str());
	int res0 = open(filename, O_RDWR);
	if (res0 == -1)
		fail("failed to open ivshmem resource0");
	void* regs = mmap(nullptr, getpagesize(), PROT_READ | PROT_WRITE, MAP_SHARED, res0, 0);
	close(res0);
	if (regs == MAP_FAILED)
		fail("failed to mmap ivshmem resource0");
	snprintf(filename, sizeof(filename), "/sys/bus/pci/devices/%s/resource2", dev.c_str());
	int res2 = open(filename, O_RDWR);
	if (res2 == -1)
		fail("failed to open ivshmem resource2");
	constexpr size_t kIvshmemSize = 64 << 20;
	void* shmem = mmap(nullptr, kIvshmemSize, PROT_READ | PROT_WRITE, MAP_SHARED, res0, 0);
	close(res2);
	if (shmem == MAP_FAILED)
		fail("failed to mmap ivshmem resource2");
	Ivshmem ivs = {};
	ivs.doorbell = static_cast<uint32*>(regs) + 3;
	ivs.state = static_cast<std::atomic<rpc::SnapshotState>*>(shmem);
	ivs.input = static_cast<char*>(shmem) + 1;
	ivs.output = static_cast<char*>(shmem) + (4 << 20);
	return ivs;
}

static void Snapshot(char** argv, int argc)
{
	flag_debug = true;
	Ivshmem ivs = IvshmemMmap();
	if (*ivs.state != rpc::SnapshotState::Initial)
		failmsg("bad initial ivs state", "state=0x%x", (int)ivs.state->load());
	//!!! comment
	int kmsg = open("/dev/kmsg", O_WRONLY);
	if (kmsg == -1)
		fail("failed to open /dev/kmsg");
	dup2(STDERR_FILENO, kmsg);
	debug("read init ivs state\n");
	*ivs.state = rpc::SnapshotState::Ready;
	while (*ivs.state == rpc::SnapshotState::Ready)
		;
	if (*ivs.state == rpc::SnapshotState::InputReady) {
		debug("got cmd state: 0x%x\n", *(uint32*)ivs.input);
		ivs.output[0] = ivs.input[0] + 1;
		ivs.output[1] = ivs.input[1] + 1;
	}
	*ivs.state = rpc::SnapshotState::Executed;
	for (;;)
		sleep(1000);
}
