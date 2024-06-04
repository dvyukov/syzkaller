// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <deque>
#include <iomanip>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

std::ostream& operator<<(std::ostream& ss, const rpc::ExecRequestRawT& req)
{
	return ss << "id=" << req.id
		  << " flags=0x" << std::hex << static_cast<uint64>(req.flags)
		  << " env_flags=0x" << std::hex << static_cast<uint64>(req.exec_opts->env_flags())
		  << " exec_flags=0x" << std::hex << static_cast<uint64>(req.exec_opts->exec_flags())
		  << " prod_data=" << std::dec << req.prog_data.size()
		  << "\n";
}

class Proc
{
public:
	Proc(Connection& conn, const char* bin, int id, int max_signal_fd, int cover_fitler_fd,
	     uint32 slowdown, uint32 syscall_timeout_ms, uint32 program_timeout_ms)
	    : conn_(conn), bin_(bin), id_(id), max_signal_fd_(max_signal_fd), cover_fitler_fd_(cover_fitler_fd), slowdown_(slowdown), syscall_timeout_ms_(syscall_timeout_ms), program_timeout_ms_(program_timeout_ms)
	{
		char tmp[128];
		snprintf(tmp, sizeof(tmp), "syz-proc-%d-req-mem", id_);
		req_mem_fd_ = open(tmp, O_RDWR | O_CREAT | O_TRUNC, 0600);
		if (req_mem_fd_ == -1)
			failmsg("open failed", "file=%s", tmp);
		if (fallocate(req_mem_fd_, 0, 0, kMaxInput))
			fail("fallocate failed");
		req_mem_ = mmap(nullptr, kMaxInput, PROT_READ | PROT_WRITE, MAP_SHARED, req_mem_fd_, 0);
		if (req_mem_ == MAP_FAILED)
			fail("mmap failed");

		snprintf(tmp, sizeof(tmp), "syz-proc-%d-resp-mem", id_);
		resp_mem_fd_ = open(tmp, O_RDWR | O_CREAT | O_TRUNC, 0600);
		if (resp_mem_fd_ == -1)
			failmsg("open failed", "file=%s", tmp);
		if (fallocate(resp_mem_fd_, 0, 0, kMaxOutput))
			fail("fallocate failed");
		void* resp_mem = mmap(nullptr, kMaxOutput, PROT_READ | PROT_WRITE, MAP_SHARED, resp_mem_fd_, 0);
		if (resp_mem == MAP_FAILED)
			fail("mmap failed");
		resp_mem_ = static_cast<OutputData*>(resp_mem);

		Start();
	}

	bool Execute(rpc::ExecRequestRawT& msg)
	{
		if (state_ != State::Started && state_ != State::Idle)
			return false;
		if (msg_)
			fail("already have pending msg");
		if (wait_start_)
			wait_end_ = current_time_ms();
		if (state_ == State::Idle &&
		    (exec_env_ != msg.exec_opts->env_flags() || sandbox_arg_ != msg.exec_opts->sandbox_arg()))
			Restart();
		attempts_ = 0;
		msg_ = std::move(msg);
		if (state_ == State::Started)
			Handshake();
		else
			Execute();
		return true;
	}

	void Arm(Select& select)
	{
		select.Arm(resp_pipe_);
		select.Arm(stdout_pipe_);
	}

	void Ready(Select& select, uint64 now, bool empty)
	{
		if ((state_ == State::Handshaking || state_ == State::Executing) &&
		    now > exec_start_ + 10 * 1000) {  //!!! use proper timeout
			Restart();
			return;
		}

		if (select.Ready(stdout_pipe_) && !ReadOutput()) {
			//!!! not needed in fork mode
			// Restart();
			// return;
		}
		if (select.Ready(resp_pipe_) && !ReadResponse(empty)) {
			Restart();
			return;
		}
		return;
	}

private:
	enum State : uint8 {
		Started,
		Handshaking,
		Idle,
		Executing,
	};

	Connection& conn_;
	const char* const bin_;
	const int id_;
	const int max_signal_fd_;
	const int cover_fitler_fd_;
	const uint32 slowdown_;
	const uint32 syscall_timeout_ms_;
	const uint32 program_timeout_ms_;
	State state_ = State::Started;
	pid_t pid_ = 0;
	void* req_mem_ = nullptr;
	OutputData* resp_mem_ = nullptr;
	int req_mem_fd_ = -1;
	int resp_mem_fd_ = -1;
	int req_pipe_ = -1;
	int resp_pipe_ = -1;
	int stdout_pipe_ = -1;
	rpc::ExecEnv exec_env_ = rpc::ExecEnv::NONE;
	int64_t sandbox_arg_ = 0;
	std::optional<rpc::ExecRequestRawT> msg_;
	std::vector<uint8_t> output_;
	size_t debug_output_pos_ = 0;
	uint64 attempts_ = 0;
	uint64 freshness_ = 0;
	uint64 exec_start_ = 0;
	uint64 wait_start_ = 0;
	uint64 wait_end_ = 0;

	friend std::ostream& operator<<(std::ostream& ss, const Proc& proc)
	{
		ss << "id=" << proc.id_
		   << " state=" << static_cast<int>(proc.state_)
		   << " freshness=" << proc.freshness_
		   << " attempts=" << proc.attempts_
		   << " exec_start=" << current_time_ms() - proc.exec_start_
		   << "\n";
		if (proc.msg_)
			ss << "\tcurrent request: " << *proc.msg_;
		return ss;
	}

	void Restart()
	{
		debug("proc %d: restarting subprocess, current state %u attempts %llu\n", id_, state_, attempts_);
		kill(-pid_, SIGKILL);
		kill(pid_, SIGKILL);
		int pid = 0;
		int wstatus = 0;
		do
			pid = waitpid(pid_, &wstatus, 0);
		while (pid == -1 && errno == EINTR);
		if (pid != pid_)
			failmsg("child wait failed", "pid_=%d pid=%d", pid_, pid);
		if (WIFSTOPPED(wstatus))
			failmsg("child stopped", "status=%d", wstatus);
		pid_ = 0;
		int status = WEXITSTATUS(wstatus);
		debug("proc %d: subprocess exit status %d\n", id_, status);
		if (++attempts_ > 20) {
			while (ReadOutput()) {
			}
			output_.push_back(0);
			failmsg("repeatedly failed to execute the program", "proc=%d status=%d output:\n%s",
				id_, status, output_.data());
		}
		// Ignore all other errors.
		// Without fork server executor can legitimately exit (program contains exit_group),
		// with fork server the top process can exit with kFailStatus if it wants special handling.
		if (status != kFailStatus)
			status = 0;
		if (FailCurrentRequest(status == kFailStatus)) {
			// Read out all pening output until EOF.
			if (IsSet(msg_->flags, rpc::RequestFlag::ReturnOutput)) {
				while (ReadOutput()) {
				}
			}
			HandleCompletion(status);
		} else if (attempts_ > 3) {
			sleep_ms(100 * attempts_);
		}
		Start();
	}

	bool FailCurrentRequest(bool failed)
	{
		if (state_ == State::Handshaking)
			return failed && IsSet(msg_->flags, rpc::RequestFlag::ReturnError);
		if (state_ == State::Executing)
			return !failed || IsSet(msg_->flags, rpc::RequestFlag::ReturnError);
		return false;
	}

	void Start()
	{
		state_ = State::Started;
		freshness_ = 0;
		int req_pipe[2];
		if (pipe(req_pipe))
			fail("pipe failed");
		int resp_pipe[2];
		if (pipe(resp_pipe))
			fail("pipe failed");
		int stdout_pipe[2];
		if (pipe(stdout_pipe))
			fail("pipe failed");

		std::pair<int, int> fds[] = {
		    {req_pipe[0], STDIN_FILENO},
		    {resp_pipe[1], STDOUT_FILENO},
		    {stdout_pipe[1], STDERR_FILENO},
		    {req_mem_fd_, kInFd},
		    {resp_mem_fd_, kOutFd},
		    {max_signal_fd_, kMaxSignalFd},
		    {cover_fitler_fd_, kCoverFilterFd},
		};

		posix_spawn_file_actions_t actions;
		if (posix_spawn_file_actions_init(&actions))
			fail("posix_spawn_file_actions_init failed");
		for (auto pair : fds) {
			if (pair.first != -1) {
				if (posix_spawn_file_actions_adddup2(&actions, pair.first, pair.second))
					fail("posix_spawn_file_actions_adddup2 failed");
			} else {
				if (posix_spawn_file_actions_addclose(&actions, pair.second))
					fail("posix_spawn_file_actions_addclose failed");
			}
		}
		for (int i = kCoverFilterFd + 1; i < kFdLimit; i++) {
			if (posix_spawn_file_actions_addclose(&actions, i))
				fail("posix_spawn_file_actions_addclose failed");
		}

		posix_spawnattr_t attr;
		if (posix_spawnattr_init(&attr))
			fail("posix_spawnattr_init failed");
		// Create new process group so that we can kill all processes in the group.
		if (posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETPGROUP))
			fail("posix_spawnattr_setflags failed");

		const char* child_argv[] = {bin_, "exec", nullptr};
		const char* child_envp[] = {
		    // Tell ASAN to not mess with our NONFAILING.
		    "ASAN_OPTIONS=handle_segv=0 allow_user_segv_handler=1",
		    // Disable rseq since we don't use it and we want to [ab]use it ourselves for kernel testing.
		    "GLIBC_TUNABLES=glibc.pthread.rseq=0",
		    nullptr};
		for (int i = 0;; i++) {
			if (!posix_spawn(&pid_, bin_, &actions, &attr,
					 const_cast<char**>(child_argv), const_cast<char**>(child_envp)))
				break;
			// Sometimes this fails with EIO, try a bit harder before bringing down the VM.
			if (i == 10)
				fail("posix_spawn failed");
			sleep_ms(100 * i);
		}
		if (posix_spawn_file_actions_destroy(&actions))
			fail("posix_spawn_file_actions_destroy failed");
		if (posix_spawnattr_destroy(&attr))
			fail("posix_spawnattr_destroy failed");

		Select::Prepare(resp_pipe[0]);
		Select::Prepare(stdout_pipe[0]);

		close(req_pipe[0]);
		close(resp_pipe[1]);
		close(stdout_pipe[1]);

		close(req_pipe_);
		close(resp_pipe_);
		close(stdout_pipe_);

		req_pipe_ = req_pipe[1];
		resp_pipe_ = resp_pipe[0];
		stdout_pipe_ = stdout_pipe[0];

		if (msg_)
			Handshake();
	}

	void Handshake()
	{
		if (state_ != State::Started || !msg_)
			fail("wrong handshake state");
		debug("proc %d: handshaking to execute request %llu\n", id_, static_cast<uint64>(msg_->id));
		state_ = State::Handshaking;
		exec_start_ = current_time_ms();
		exec_env_ = msg_->exec_opts->env_flags() & ~rpc::ExecEnv::ResetState;
		sandbox_arg_ = msg_->exec_opts->sandbox_arg();
		handshake_req req = {
		    .magic = kInMagic,
		    .flags = exec_env_,
		    .pid = static_cast<uint64>(id_),
		    .sandbox_arg = static_cast<uint64>(sandbox_arg_),
		};
		if (write(req_pipe_, &req, sizeof(req)) != sizeof(req)) {
			debug("request pipe write failed (errno=%d)\n", errno);
			Restart();
		}
	}

	void Execute()
	{
		if (state_ != State::Idle || !msg_)
			fail("wrong state for execute");

		debug("proc %d: start executing request %llu\n", id_, static_cast<uint64>(msg_->id));

		rpc::ExecutingMessageRawT exec;
		exec.id = msg_->id;
		exec.proc_id = id_;
		exec.try_ = attempts_;

		if (wait_start_) {
			exec.wait_duration = (wait_end_ - wait_start_) * 1000 * 1000;
			wait_end_ = wait_start_ = 0;
		}

		rpc::ExecutorMessageRawT raw;
		raw.msg.Set(std::move(exec));
		conn_.Send(raw);

		uint64 all_call_signal = 0;
		bool all_extra_signal = false;
		for (int32_t call : msg_->all_signal) {
			if (call < -1 || call >= 64)
				failmsg("bad all_signal call", "call=%d", call);
			if (call < 0)
				all_extra_signal = true;
			else
				all_call_signal |= 1ull << call;
		}
		memcpy(req_mem_, msg_->prog_data.data(), std::min(msg_->prog_data.size(), kMaxInput));
		execute_req req{
		    .magic = kInMagic,
		    .id = static_cast<uint64>(msg_->id),
		    .env_flags = exec_env_,
		    .exec_flags = static_cast<uint64>(msg_->exec_opts->exec_flags()),
		    .pid = static_cast<uint64>(id_),
		    .syscall_timeout_ms = syscall_timeout_ms_,
		    .program_timeout_ms = program_timeout_ms_,
		    .slowdown_scale = slowdown_,
		    .all_call_signal = all_call_signal,
		    .all_extra_signal = all_extra_signal,
		};
		exec_start_ = current_time_ms();
		state_ = State::Executing;
		if (write(req_pipe_, &req, sizeof(req)) != sizeof(req)) {
			debug("request pipe write failed (errno=%d)\n", errno);
			Restart();
		}
	}

	void HandleCompletion(uint32 status)
	{
		if (!msg_)
			fail("don't have executed msg");

		// Note: if the child process crashed during handshake and the request has ReturnError flag,
		// we have not started executing the request yet.
		uint64 elapsed = (current_time_ms() - exec_start_) * 1000 * 1000;
		uint8* prog_data = msg_->prog_data.data();
		input_data = prog_data;
		uint32 num_calls = read_input(&prog_data);

		int output_size = resp_mem_->size.load(std::memory_order_relaxed) ?: kMaxOutput;
		uint32 completed = resp_mem_->completed.load(std::memory_order_relaxed);
		completed = std::min(completed, kMaxCalls);
		debug("handle completion: completed=%u output_size=%u\n", completed, output_size);
		ShmemBuilder fbb(resp_mem_, output_size);
		auto empty_call = rpc::CreateCallInfoRawDirect(fbb, rpc::CallFlag::NONE, 998);
		std::vector<flatbuffers::Offset<rpc::CallInfoRaw>> calls(num_calls, empty_call);
		std::vector<flatbuffers::Offset<rpc::CallInfoRaw>> extra;
		for (uint32_t i = 0; i < completed; i++) {
			const auto& call = resp_mem_->calls[i];
			if (call.index == -1) {
				extra.push_back(call.offset);
				continue;
			}
			if (call.index < 0 || call.index >= static_cast<int>(num_calls) || call.offset.o > kMaxOutput) {
				debug("bad call index/offset: proc=%d req=%llu call=%d/%d completed=%d offset=%u",
				      id_, static_cast<uint64>(msg_->id), call.index, num_calls,
				      completed, call.offset.o);
				continue;
			}
			calls[call.index] = call.offset;
		}

		auto prog_info_off = rpc::CreateProgInfoRawDirect(fbb, &calls, &extra, 0, elapsed, freshness_++);

		flatbuffers::Offset<flatbuffers::String> error_off = 0;
		if (status == kFailStatus)
			error_off = fbb.CreateString("process failed");
		flatbuffers::Offset<flatbuffers::Vector<uint8_t>> output_off = 0;
		if (IsSet(msg_->flags, rpc::RequestFlag::ReturnOutput)) {
			if (status) {
				char tmp[128];
				snprintf(tmp, sizeof(tmp), "\nprocess exited with status %d\n", status);
				output_.insert(output_.end(), tmp, tmp + strlen(tmp));
			}
			output_off = fbb.CreateVector(output_);
		}
		auto exec_off = rpc::CreateExecResultRaw(fbb, msg_->id, output_off, error_off, prog_info_off);
		auto msg_off = rpc::CreateExecutorMessageRaw(fbb, rpc::ExecutorMessagesRaw::ExecResult,
							     flatbuffers::Offset<void>(exec_off.o));
		fbb.FinishSizePrefixed(msg_off);
		auto data = fbb.GetBufferSpan();
		conn_.Send(data.data(), data.size());

		resp_mem_->Reset();
		msg_.reset();
		output_.clear();
		debug_output_pos_ = 0;
		state_ = State::Idle;
	}

	bool ReadResponse(bool empty)
	{
		uint32 status;
		ssize_t n = read(resp_pipe_, &status, sizeof(status));
		if (n == 0) {
			debug("proc %d: response pipe EOF\n", id_);
			return false;
		}
		if (n != sizeof(status))
			failmsg("proc resp pipe read failed", "n=%zd", n);
		if (state_ == State::Handshaking) {
			debug("proc %d: got handshake reply\n", id_);
			state_ = State::Idle;
			Execute();
		} else if (state_ == State::Executing) {
			debug("proc %d: got execute reply\n", id_);
			HandleCompletion(status);
			if (empty)
				wait_start_ = current_time_ms();
		} else {
			debug("got data on response pipe in wrong state %d\n", state_);
			return false;
		}
		return true;
	}

	bool ReadOutput()
	{
		const size_t kChunk = 1024;
		output_.resize(output_.size() + kChunk);
		ssize_t n = read(stdout_pipe_, output_.data() + output_.size() - kChunk, kChunk);
		if (n < 0) {
			if (errno == EINTR || errno == EAGAIN)
				return true;
			fail("proc stdout read failed");
		}
		output_.resize(output_.size() - kChunk + n);
		if (n == 0) {
			debug("proc %d: output pipe EOF\n", id_);
			return false;
		}
		if (flag_debug) {
			output_.resize(output_.size() + 1);
			debug("proc %d: got output: %s\n", id_, output_.data() + debug_output_pos_);
			output_.resize(output_.size() - 1);
			debug_output_pos_ = output_.size();
		}
		return true;
	}
};

class Runner
{
public:
	Runner(Connection& conn, const char* name, const char* bin)
	    : conn_(conn), name_(name)
	{
		size_t num_procs = Handshake();
		int max_signal_fd = max_signal_ ? max_signal_->FD() : -1;
		int cover_filter_fd = cover_filter_ ? cover_filter_->FD() : -1;
		for (size_t i = 0; i < num_procs; i++)
			procs_.emplace_back(new Proc(conn, bin, i, max_signal_fd, cover_filter_fd,
						     slowdown_, syscall_timeout_ms_, program_timeout_ms_));

		for (;;)
			Loop();
	}

private:
	Connection& conn_;
	const char* const name_;
	std::optional<CoverFilter> max_signal_;
	std::optional<CoverFilter> cover_filter_;
	std::vector<std::unique_ptr<Proc>> procs_;
	std::deque<rpc::ExecRequestRawT> requests_;
	std::vector<std::string> leak_frames_;
	uint32 slowdown_ = 0;
	uint32 syscall_timeout_ms_ = 0;
	uint32 program_timeout_ms_ = 0;

	friend std::ostream& operator<<(std::ostream& ss, const Runner& runner)
	{
		ss << "procs:\n";
		for (const auto& proc : runner.procs_)
			ss << *proc;
		ss << "\nqueued requests (" << runner.requests_.size() << "):\n";
		for (const auto& req : runner.requests_)
			ss << req;
		return ss;
	}

	void Loop()
	{
		Select select;
		select.Arm(conn_.FD());
		for (auto& proc : procs_)
			proc->Arm(select);
		select.Wait(1000);
		uint64 now = current_time_ms();

		if (select.Ready(conn_.FD())) {
			rpc::HostMessageRawT raw;
			conn_.Recv(raw);
			if (auto* msg = raw.msg.AsExecRequest())
				Handle(*msg);
			else if (auto* msg = raw.msg.AsSignalUpdate())
				Handle(*msg);
			else if (auto* msg = raw.msg.AsStartLeakChecks())
				Handle(*msg);
			else if (auto* msg = raw.msg.AsStateRequest())
				Handle(*msg);
			else
				failmsg("unknown host message type", "type=%d", static_cast<int>(raw.msg.type));
		}

		for (auto& proc : procs_) {
			proc->Ready(select, now, requests_.empty());
			if (!requests_.empty()) {
				if (proc->Execute(requests_.front()))
					requests_.pop_front();
			}
		}
	}

	size_t Handshake()
	{
		rpc::ConnectRequestRawT conn_req;
		conn_req.name = name_;
		conn_req.arch = GOARCH;
		conn_req.git_revision = GIT_REVISION;
		conn_req.syz_revision = SYZ_REVISION;
		conn_.Send(conn_req);

		rpc::ConnectReplyRawT conn_reply;
		conn_.Recv(conn_reply);
		if (conn_reply.debug)
			flag_debug = true;
		debug("connected to manager: procs=%d slowdown=%d syscall_timeout=%u"
		      " program_timeout=%u features=0x%llx\n",
		      conn_reply.procs, conn_reply.slowdown, conn_reply.syscall_timeout_ms,
		      conn_reply.program_timeout_ms, static_cast<uint64>(conn_reply.features));
		leak_frames_ = conn_reply.leak_frames;
		slowdown_ = conn_reply.slowdown;
		syscall_timeout_ms_ = conn_reply.syscall_timeout_ms;
		program_timeout_ms_ = conn_reply.program_timeout_ms;
		if (conn_reply.cover)
			max_signal_.emplace("syz-max-signal");

		rpc::InfoRequestRawT info_req;
		info_req.files = ReadFiles(conn_reply.files);
		info_req.globs = ReadGlobs(conn_reply.globs);

		// This does any one-time setup for the requested features on the machine.
		// Note: this can be called multiple times and must be idempotent.
		// is_kernel_64_bit = detect_kernel_bitness();
#if SYZ_HAVE_FEATURES
		setup_sysctl();
		setup_cgroups();
#endif
#if SYZ_HAVE_SETUP_EXT
		// This can be defined in common_ext.h.
		setup_ext();
#endif
		for (const auto& feat : features) {
			if (!(conn_reply.features & feat.id))
				continue;
			debug("setting up feature %s\n", rpc::EnumNameFeature(feat.id));
			const char* reason = feat.setup();
			conn_reply.features &= ~feat.id;
			std::unique_ptr<rpc::FeatureInfoRawT> res(new rpc::FeatureInfoRawT);
			res->id = feat.id;
			res->need_setup = true;
			if (reason) {
				debug("failed: %s\n", reason);
				res->reason = reason;
			}
			info_req.features.push_back(std::move(res));
		}
		for (auto id : rpc::EnumValuesFeature()) {
			if (!(conn_reply.features & id))
				continue;
			std::unique_ptr<rpc::FeatureInfoRawT> res(new rpc::FeatureInfoRawT);
			res->id = id;
			res->need_setup = false;
			info_req.features.push_back(std::move(res));
		}

#if SYZ_HAVE_KCSAN
		setup_kcsan_filter(conn_reply.race_frames);
#endif

		conn_.Send(info_req);

		rpc::InfoReplyRawT info_reply;
		conn_.Recv(info_reply);
		debug("received info reply: covfilter=%zu\n", info_reply.cover_filter.size());
		if (!info_reply.cover_filter.empty()) {
			cover_filter_.emplace("syz-cover-filer");
			for (auto pc : info_reply.cover_filter)
				cover_filter_->Insert(pc);
		}

		Select::Prepare(conn_.FD());
		return conn_reply.procs;
	}

	void Handle(rpc::ExecRequestRawT& msg)
	{
		debug("recv exec request %llu: flags=0x%llx env=0x%llx exec=0x%llx size=%zu\n",
		      static_cast<uint64>(msg.id),
		      static_cast<uint64>(msg.flags),
		      static_cast<uint64>(msg.exec_opts->env_flags()),
		      static_cast<uint64>(msg.exec_opts->exec_flags()),
		      msg.prog_data.size());
		if (IsSet(msg.flags, rpc::RequestFlag::IsBinary)) {
			ExecuteBinary(msg);
			return;
		}
		for (auto& proc : procs_) {
			if (proc->Execute(msg))
				return;
		}
		requests_.push_back(std::move(msg));
	}

	void Handle(const rpc::SignalUpdateRawT& msg)
	{
		debug("recv signal update: new=%zu drop=%zu\n", msg.new_max.size(), msg.drop_max.size());
		if (!max_signal_)
			fail("signal update when no signal filter installed");
		for (auto pc : msg.new_max)
			max_signal_->Insert(pc);
		for (auto pc : msg.drop_max)
			max_signal_->Remove(pc);
	}

	void Handle(const rpc::StartLeakChecksRawT& msg)
	{
		debug("recv start leak checks\n");
	}

	void Handle(const rpc::StateRequestRawT& msg)
	{
		std::ostringstream ss;
		ss << *this;
		const std::string& str = ss.str();
		rpc::StateResultRawT res;
		res.data.insert(res.data.begin(), str.data(), str.data() + str.size());
		rpc::ExecutorMessageRawT raw;
		raw.msg.Set(std::move(res));
		conn_.Send(raw);
	}

	void ExecuteBinary(rpc::ExecRequestRawT& msg)
	{
		rpc::ExecutingMessageRawT exec;
		exec.id = msg.id;
		rpc::ExecutorMessageRawT raw;
		raw.msg.Set(std::move(exec));
		conn_.Send(raw);

		char dir_template[] = "syz-bin-dirXXXXXX";
		char* dir = mkdtemp(dir_template);
		if (dir == nullptr)
			fail("mkdtemp failed");
		if (chmod(dir, 0777))
			fail("chmod failed");
		auto [err, output] = ExecuteBinaryImpl(msg, dir);
		if (!err.empty()) {
			char tmp[64];
			snprintf(tmp, sizeof(tmp), " (errno %d: %s)", errno, strerror(errno));
			err += tmp;
		}
		remove_dir(dir);
		rpc::ExecResultRawT res;
		res.id = msg.id;
		res.error = std::move(err);
		res.output = std::move(output);
		raw.msg.Set(std::move(res));
		conn_.Send(raw);
	}

	std::tuple<std::string, std::vector<uint8_t>> ExecuteBinaryImpl(rpc::ExecRequestRawT& msg, const char* dir)
	{
		std::string file = std::string(dir) + "/syz-executor";
		int fd = open(file.c_str(), O_WRONLY | O_CLOEXEC | O_CREAT, 0755);
		if (fd == -1)
			return {"binary file creation failed", {}};
		ssize_t wrote = write(fd, msg.prog_data.data(), msg.prog_data.size());
		close(fd);
		if (wrote != static_cast<ssize_t>(msg.prog_data.size()))
			return {"binary file write failed", {}};

		int stdin_pipe[2];
		if (pipe(stdin_pipe))
			fail("pipe failed");
		int stdout_pipe[2];
		if (pipe(stdout_pipe))
			fail("pipe failed");

		posix_spawn_file_actions_t actions;
		if (posix_spawn_file_actions_init(&actions))
			fail("posix_spawn_file_actions_init failed");
		if (posix_spawn_file_actions_adddup2(&actions, stdin_pipe[0], STDIN_FILENO))
			fail("posix_spawn_file_actions_adddup2 failed");
		if (posix_spawn_file_actions_adddup2(&actions, stdout_pipe[1], STDOUT_FILENO))
			fail("posix_spawn_file_actions_adddup2 failed");
		if (posix_spawn_file_actions_adddup2(&actions, stdout_pipe[1], STDERR_FILENO))
			fail("posix_spawn_file_actions_adddup2 failed");
		for (int i = STDERR_FILENO + 1; i < kFdLimit; i++) {
			if (posix_spawn_file_actions_addclose(&actions, i))
				fail("posix_spawn_file_actions_addclose failed");
		}

		posix_spawnattr_t attr;
		if (posix_spawnattr_init(&attr))
			fail("posix_spawnattr_init failed");
		// Create new process group so that we can kill all processes in the group.
		if (posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETPGROUP))
			fail("posix_spawnattr_setflags failed");

		const char* child_argv[] = {file.c_str(), nullptr};
		const char* child_envp[] = {
		    // Tell ASAN to not mess with our NONFAILING.
		    "ASAN_OPTIONS=handle_segv=0 allow_user_segv_handler=1",
		    // Disable rseq since we don't use it and we want to [ab]use it ourselves for kernel testing.
		    "GLIBC_TUNABLES=glibc.pthread.rseq=0",
		    nullptr};
		int pid = 0;
		if (posix_spawn(&pid, file.c_str(), &actions, &attr,
				const_cast<char**>(child_argv), const_cast<char**>(child_envp)))
			fail("posix_spawn failed");
		if (posix_spawn_file_actions_destroy(&actions))
			fail("posix_spawn_file_actions_destroy failed");
		if (posix_spawnattr_destroy(&attr))
			fail("posix_spawnattr_destroy failed");

		close(stdin_pipe[0]);
		close(stdout_pipe[1]);

		int wstatus = 0;
		uint64 start = current_time_ms();
		for (;;) {
			sleep_ms(10);
			if (waitpid(pid, &wstatus, WNOHANG | WAIT_FLAGS) == pid)
				break;
			if (current_time_ms() - start > 20 * 1000) {
				kill(-pid, SIGKILL);
				kill(pid, SIGKILL);
			}
		}

		std::vector<uint8_t> output;
		for (;;) {
			const size_t kChunk = 1024;
			output.resize(output.size() + kChunk);
			ssize_t n = read(stdout_pipe[0], output.data() + output.size() - kChunk, kChunk);
			if (n <= 0)
				break;
			output.resize(output.size() - kChunk + n);
		}
		close(stdin_pipe[1]);
		close(stdout_pipe[0]);

		return {WEXITSTATUS(wstatus) == kFailStatus ? "process failed" : "", std::move(output)};
	}
};

static void SigintHandler(int sig)
{
	// GCE VM preemption is signalled as SIGINT, notify syz-manager.
	exitf("SYZ-EXECUTOR: PREEMPTED");
}

static void SigchldHandler(int sig)
{
	// We need just blocking syscall preemption.
}

static void SigsegvHandler(int sig, siginfo_t* info, void* ucontext)
{
	auto& mctx = static_cast<ucontext_t*>(ucontext)->uc_mcontext;
#if GOARCH_amd64
	uintptr_t pc = mctx.gregs[REG_RIP];
#elif GOARCH_arm64
	uintptr_t pc = mctx.pc;
#else
	(void)mctx;
	uintptr_t pc = 0xdeadbeef;
#endif
	// Print the current function PC so that it's possible to map the failing PC
	// to a symbol in the binary offline (we usually compile as PIE).
	failmsg("SIGSEGV", "sig:%d handler:%p pc:%p addr:%p",
		sig, SigsegvHandler, info->si_addr, reinterpret_cast<void*>(pc));
}

void runner(char** argv, int argc)
{
	if (argc != 5)
		fail("usage: syz-executor runner <name> <manager-addr> <manager-port>");
	const char* const name = argv[2];
	const char* const manager_addr = argv[3];
	const char* const manager_port = argv[4];

	struct rlimit rlim;
	rlim.rlim_cur = rlim.rlim_max = kFdLimit;
	if (setrlimit(RLIMIT_NOFILE, &rlim))
		fail("setrlimit(RLIMIT_NOFILE) failed");

	if (signal(SIGPIPE, SIG_IGN))
		fail("signal(SIGPIPE) failed");
	if (signal(SIGINT, SigintHandler))
		fail("signal(SIGINT) failed");
	if (signal(SIGCHLD, SigchldHandler))
		fail("signal(SIGCHLD) failed");
	struct sigaction act = {};
	act.sa_flags = SA_SIGINFO;
	act.sa_sigaction = SigsegvHandler;
	if (sigaction(SIGSEGV, &act, nullptr))
		fail("signal(SIGSEGV) failed");
	if (sigaction(SIGBUS, &act, nullptr))
		fail("signal(SIGBUS) failed");

	Connection conn(manager_addr, manager_port);
	Runner(conn, name, argv[0]);
}
