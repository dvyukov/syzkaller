// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build

#define SYZ_EXECUTOR
#include "common_fuchsia.h"

#include "executor_posix.h"

#include "executor.h"

#include "syscalls_fuchsia.h"

#include <zircon/syscalls/debug.h>
#include <zircon/syscalls/exception.h>
#include <zircon/syscalls/object.h>
#include <zircon/syscalls/port.h>

char input_data[kMaxInput];
uint32_t output;
__thread thread_t* current;

static void* ex_handler(void* arg);

int main(int argc, char** argv)
{
	if (argc == 2 && strcmp(argv[1], "version") == 0) {
		puts("linux " GOARCH " " SYZ_REVISION " " GIT_REVISION);
		return 0;
	}

	if (false) {
	zx_status_t status;
	zx_handle_t port;
	if ((status = zx_port_create(0, &port)) != ZX_OK)
		fail("zx_port_create failed: %d", status);
	if ((status = zx_task_bind_exception_port(zx_process_self(), port, 0, 0)) != ZX_OK)
		fail("zx_task_bind_exception_port failed: %d", status);
	pthread_t th;
	if (pthread_create(&th, 0, ex_handler, (void*)(long)port))
		fail("pthread_create failed");
	}
	install_segv_handler();
	int pos = 0;
	for (;;) {
		int rv = read(0, input_data + pos, sizeof(input_data) - pos);
		if (rv < 0)
			fail("read failed");
		if (rv == 0)
			break;
		pos += rv;
	}
	if (pos < 24)
		fail("truncated input");

	uint64_t flags = *(uint64_t*)input_data;
	flag_debug = flags & (1 << 0);
	flag_threaded = flags & (1 << 2);
	flag_collide = flags & (1 << 3);
	if (!flag_threaded)
		flag_collide = false;
	uint64_t executor_pid = *((uint64_t*)input_data + 2);
	debug("input %d, threaded=%d collide=%d pid=%llu\n",
	      pos, flag_threaded, flag_collide, executor_pid);

	execute_one(((uint64_t*)input_data) + 3);
	return 0;
}

long execute_syscall(call_t* c, long a0, long a1, long a2, long a3, long a4, long a5, long a6, long a7, long a8)
{
	debug("%s = %p\n", c->name, c->call);
	long res = c->call(a0, a1, a2, a3, a4, a5, a6, a7, a8);
	debug("%s = %ld\n", c->name, res);
	errno = res;
	return res;
}

void* ex_handler(void* arg)
{
	zx_handle_t port = (zx_handle_t)(long)arg;
	for (int i = 0; i < 10000; i++) {
		zx_status_t status;
		zx_port_packet_t packet = {};
		if ((status = zx_port_wait(port, ZX_TIME_INFINITE, &packet, 0)) != ZX_OK) {
			debug("zx_port_wait failed: %d\n", status);
			continue;
		}
		debug("got exception packet: type=%d status=%d tid=%llu\n", packet.type, packet.status, packet.exception.tid);
		zx_handle_t thread;
		if ((status = zx_object_get_child(zx_process_self(), packet.exception.tid, ZX_RIGHT_SAME_RIGHTS, &thread)) != ZX_OK) {
			debug("zx_object_get_child failed: %d\n", status);
			continue;
		}
		zx_x86_64_general_regs_t regs;
		uint32_t bytes_read;
		if ((status = zx_thread_read_state(thread, ZX_THREAD_STATE_REGSET0, &regs, sizeof(regs), &bytes_read)) != ZX_OK ||
		    bytes_read != sizeof(regs)) {
			debug("zx_thread_read_state failed: %d/%d (%d)\n", bytes_read, (int)sizeof(regs), status);
		} else {
			regs.rip = (uint64_t)&recover;
			if ((status = zx_thread_write_state(thread, ZX_THREAD_STATE_REGSET0, &regs, sizeof(regs))) != ZX_OK)
				debug("zx_thread_write_state failed: %d\n", status);
		}
		if ((status = zx_task_resume(thread, ZX_RESUME_EXCEPTION)) != ZX_OK)
			debug("zx_task_resume failed: %d\n", status);
		zx_handle_close(thread);
	}
	doexit(1);
	return 0;
}

void thread_init(thread_t* th)
{
	zx_status_t status;
	zx_info_handle_basic_t info;
	if ((status = zx_object_get_info(zx_thread_self(), ZX_INFO_HANDLE_BASIC, &info, sizeof(info), 0, 0)) != ZX_OK)
		fail("zx_object_get_info failed: %d", status);
	th->osid = info.koid;
	current = th;
}

void cover_open()
{
}

void cover_enable(thread_t* th)
{
}

void cover_reset(thread_t* th)
{
}

uint64_t read_cover_size(thread_t* th)
{
	return 0;
}

uint32_t* write_output(uint32_t v)
{
	return &output;
}

void write_completed(uint32_t completed)
{
}

void call_completed(uint32_t call_idx, uint64_t result, uint32_t reserrno)
{
	uint32_t data[2];
	data[0] = call_idx;
	data[1] = -reserrno;
	int res = write(3, data, sizeof(data));
	debug("call_completed(%d, %d) = %d\n", data[0], data[1], res);
}
