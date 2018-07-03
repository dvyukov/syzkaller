// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build

#define SYZ_EXECUTOR
#include "common_akaros.h"

#include "executor_posix.h"

#include "syscalls_akaros.h"

#include "executor.h"

#include <sys/mman.h>

uint32 output;

static void child();

int main(int argc, char** argv)
{
fprintf(stderr, "main argc=%d\n", argc);

	if (argc == 2 && strcmp(argv[1], "version") == 0) {
		puts(GOOS " " GOARCH " " SYZ_REVISION " " GIT_REVISION);
		return 0;
	}
	if (argc == 2 && strcmp(argv[1], "child") == 0) {
		child();
		doexit(0);
	}

	if (mmap((void*)SYZ_DATA_OFFSET, SYZ_NUM_PAGES * SYZ_PAGE_SIZE, PROT_READ | PROT_WRITE,
		 MAP_ANON | MAP_PRIVATE | MAP_FIXED, -1, 0) != (void*)SYZ_DATA_OFFSET)
		fail("mmap of data segment failed");

	use_temporary_dir();
	install_segv_handler();
	main_init();
debug("main_init\n");
	reply_handshake();

	for (;;) {
		char cwdbuf[128] = "/syz-tmpXXXXXX";
		mkdtemp(cwdbuf);
debug("forking...\n");
		int pid = fork();
		if (pid < 0)
			fail("fork failed");
		if (pid == 0) {
fprintf(stderr, "child fork\n");
			if (chdir(cwdbuf))
				fail("chdir failed");
			execl(argv[0], argv[0], "loop", NULL);
			fail("execl failed");
		}
fprintf(stderr, "forked\n");
		int status = 0;
		uint64 start = current_time_ms();
		for (;;) {
			int res = waitpid(pid, &status, WNOHANG);
			if (res == pid)
				break;
			sleep_ms(10);
			uint64 now = current_time_ms();
			if (now - start < 5 * 1000)
				continue;
			kill(pid, SIGKILL);
			while (waitpid(pid, &status, 0) != pid) {
			}
			break;
		}
		status = WEXITSTATUS(status);
		if (status == kFailStatus)
			fail("child failed");
		if (status == kErrorStatus)
			error("child errored");
		remove_dir(cwdbuf);
		reply_execute(0);
	}
	return 0;
}

static void child()
{
	flag_debug = true;
	debug("child process started\n");
	receive_execute();
	debug("child received execute\n");
	close(kInPipeFd);
	execute_one();
}

long execute_syscall(const call_t* c, long a0, long a1, long a2, long a3, long a4, long a5, long a6, long a7, long a8)
{
	return syscall(c->sys_nr, a0, a1, a2, a3, a4, a5, a6, a7, a8);
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

uint32 cover_read_size(thread_t* th)
{
	return 0;
}

bool cover_check(uint32 pc)
{
	return true;
}

bool cover_check(uint64 pc)
{
	return true;
}

uint32* write_output(uint32 v)
{
	return &output;
}

void write_completed(uint32 completed)
{
}

bool kcov_comparison_t::ignore() const
{
	return false;
}
