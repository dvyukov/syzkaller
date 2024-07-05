// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#include <dirent.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <atomic>
#include <string>
#include <utility>

//!!! special kernel for 1 proc (fewer devices, etc)
//!!! use executor as init
//!!! pre-create threads/pre-fault memory before the snapshot

struct Ivshmem {
	// Ivshmem interrupt doorbell register.
	volatile uint32* doorbell;
	std::atomic<rpc::SnapshotState>* state;
	char* input;
	char* output;
};

// Finds qemu ivshmem device, see:
// https://www.qemu.org/docs/master/specs/ivshmem-spec.html
static Ivshmem FindIvshmem()
{
	std::string result;
	DIR* devices = opendir("/sys/bus/pci/devices");
	if (!devices)
		fail("opendir(/sys/bus/pci/devices) failed");
	void* regs = nullptr;
	void* shmem = nullptr;
	while (auto* dev = readdir(devices)) {
		if (dev->d_name[0] == '.')
			continue;
		const std::string& vendor = ReadTextFile("/sys/bus/pci/devices/%s/vendor", dev->d_name);
		const std::string& device = ReadTextFile("/sys/bus/pci/devices/%s/device", dev->d_name);
		debug("PCI device %s: vendor=%s device=%s\n", dev->d_name, vendor.c_str(), device.c_str());
		if (vendor != "0x1af4" || device != "0x1110")
			continue;
		char filename[1024];
		snprintf(filename, sizeof(filename), "/sys/bus/pci/devices/%s/resource2", dev->d_name);
		int res2 = open(filename, O_RDWR);
		if (res2 == -1)
			fail("failed to open ivshmem resource2");
		struct stat statbuf;
		if (fstat(res2, &statbuf))
			fail("failed to fstat ivshmem resource2");
		debug("ivshmem resource2 size %zu\n", statbuf.st_size);
		constexpr size_t kIvshmemSize = 64 << 20;
		if (statbuf.st_size == (4 << 10)) {
			snprintf(filename, sizeof(filename), "/sys/bus/pci/devices/%s/resource0", dev->d_name);
			int res0 = open(filename, O_RDWR);
			if (res0 == -1)
				fail("failed to open ivshmem resource0");
			regs = mmap(nullptr, getpagesize(), PROT_READ | PROT_WRITE, MAP_SHARED, res0, 0);
			close(res0);
			if (regs == MAP_FAILED)
				fail("failed to mmap ivshmem resource0");
		} else if (statbuf.st_size == kIvshmemSize) {
			//!!! mmap part as read-only and part as write-only
			shmem = mmap(nullptr, kIvshmemSize, PROT_READ | PROT_WRITE, MAP_SHARED, res2, 0);
			if (shmem == MAP_FAILED)
				fail("failed to mmap ivshmem resource2");
		}
		close(res2);
	}
	closedir(devices);
	if (regs == nullptr || shmem == nullptr)
		fail("cannot find ivshmem PCI devices");
	Ivshmem ivs = {};
	ivs.doorbell = static_cast<uint32*>(regs) + 3;
	ivs.state = static_cast<std::atomic<rpc::SnapshotState>*>(shmem);
	ivs.input = static_cast<char*>(shmem) + 1;
	ivs.output = static_cast<char*>(shmem) + (4 << 20);
	return ivs;
}

/*
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

	struct stat statbuf;
	if (fstat(res2, &statbuf))
		fail("failed to fstat ivshmem resource2");
	debug("ivshmem resource2 size %zu\n", statbuf.st_size);
	constexpr size_t kIvshmemSize = 64 << 20;
	if (statbuf.st_size != kIvshmemSize)
		return;

	//!!! mmap part as read-only and part as write-only
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
*/

static Ivshmem ivs;

static void SnapshotSetup(char** argv, int argc)
{
	//!!! run setup functions

	flag_debug = true; //!!!
	// auto level = ReadTextFile("/proc/sys/kernel/printk_devkmsg");
	// debug("printk_devkmsg: %s\n", level.c_str());

	write_file("/proc/sys/kernel/printk_devkmsg", "on\n");
	// level = ReadTextFile("/proc/sys/kernel/printk_devkmsg");
	// debug("printk_devkmsg: %s\n", level.c_str());

	ivs = FindIvshmem();
	input_data = reinterpret_cast<uint8*>(ivs.input + sizeof(execute_req));
	output_data = reinterpret_cast<OutputData*>(ivs.output);
	output_size = kMaxOutput;
	while (*ivs.state != rpc::SnapshotState::Handshake)
		sleep_ms(10);
	//!!!	failmsg("bad initial ivs state", "state=0x%x", (int)ivs.state->load());
	debug("HANDSHAKE: magix=0x%llx flags=0x%llx\n", ((handshake_req*)ivs.input)->magic, (uint64)((handshake_req*)ivs.input)->flags);
	parse_handshake(*(handshake_req*)ivs.input);

	//!!! place max_signal/cover_filter in ivshmem

	/*
	volatile int xxx = 42;
	//!!! comment
	int kmsg = open("/dev/kmsg", O_WRONLY);
	if (kmsg == -1)
		fail("failed to open /dev/kmsg");
	dup2(STDERR_FILENO, kmsg);
	debug("read init ivs state\n");
	*ivs.state = rpc::SnapshotState::Ready;
	while (*ivs.state == rpc::SnapshotState::Ready) {
		debug("waiting for state change\n");
		sleep(1);
		;
	}
	kmsg = open("/dev/kmsg", O_WRONLY);
	if (kmsg == -1)
		fail("failed to open /dev/kmsg");
	dup2(STDERR_FILENO, kmsg);
	write(kmsg, "HERE!!!!!!\n", sizeof("HERE!!!!!!\n"));
	debug("got state %d xxx=%d\n", (int)ivs.state->load(), ++xxx);
	if (*ivs.state == rpc::SnapshotState::InputReady) {
		debug("got cmd state: 0x%x\n", *(uint32*)ivs.input);
		ivs.output[0] = ivs.input[0] + 1;
		ivs.output[1] = ivs.input[1] + 1;
		ivs.output[2] = ++xxx;
	}
	*ivs.state = rpc::SnapshotState::Executed;
	//debug("writing to doorbell\n");
	*ivs.doorbell = (1<<16);
	//debug("wrote to doorbell\n");
	for (;;) {
		//debug("sleeping\n");
		sleep(1000);
	}
	*/
}

static void SnapshotSetState(rpc::SnapshotState state)
{
	debug("changing stapshot state %s -> %s\n",
	      rpc::EnumNameSnapshotState(*ivs.state), rpc::EnumNameSnapshotState(state));
	*ivs.state = state;
	*ivs.doorbell = 1 << 16;
}

static void SnapshotStart()
{
	debug("SnapshotStart\n");
	// flag_debug = false;
	SnapshotSetState(rpc::SnapshotState::Ready);
	while (*ivs.state == rpc::SnapshotState::Ready)
		;
	if (*ivs.state == rpc::SnapshotState::Snapshotted) {
		SnapshotSetState(rpc::SnapshotState::Executed);
		for (;;)
			sleep(1000);
	}
	parse_execute(*(execute_req*)ivs.input);
	// input_data = reinterpret_cast<uint8*>(ivs.input + sizeof(execute_req));
}

NORETURN static void SnapshotDone(bool failed)
{
	debug("SnapshotDone\n");
	auto data = finish_output(output_data, 0, 0, 0, 0, failed ? kFailStatus : 0, nullptr);
	//(void)data;
	output_data->data_offset.store(data.data() - (uint8_t*)output_data, std::memory_order_relaxed);
	output_data->data_size.store(data.size(), std::memory_order_relaxed);
	SnapshotSetState(failed ? rpc::SnapshotState::Failed : rpc::SnapshotState::Executed);
	for (;;)
		sleep(1000);
}
