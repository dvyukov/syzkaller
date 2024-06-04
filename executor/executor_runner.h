// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <spawn.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <deque>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

//!!! restore signal filter
//!!! track request wait time

static int connect_to_host(const char* addr, const char* ports);

class Select
{
public:
	Select()
	{
		FD_ZERO(&rdset_);
	}

	void Arm(int fd)
	{
		FD_SET(fd, &rdset_);
		max_fd_ = std::max(max_fd_, fd);
	}

	bool Ready(int fd) const
	{
		return FD_ISSET(fd, &rdset_);
	}

	void Wait(int ms)
	{
		timespec timeout = {.tv_sec = ms / 1000, .tv_nsec = (ms % 1000) * 1000 * 1000};
		if (TEMP_FAILURE_RETRY(pselect(max_fd_ + 1, &rdset_, nullptr, nullptr, &timeout, nullptr)) < 0)
			fail("pselect failed");
	}

	static void Prepare(int fd)
	{
		if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK))
			fail("fcntl(O_NONBLOCK) failed");
	}

private:
	fd_set rdset_;
	int max_fd_ = -1;

	Select(const Select&) = delete;
	Select& operator=(const Select&) = delete;
};

class Connection
{
public:
	Connection(int fd)
	    : fd_(fd)
	{
	}

	int FD() const
	{
		return fd_;
	}

	template <typename Msg>
	void Send(const Msg& msg)
	{
		typedef typename Msg::TableType Raw;
		auto off = Raw::Pack(fbb_, &msg);
		fbb_.FinishSizePrefixed(off);
		auto data = fbb_.GetBufferSpan();
		Send(data.data(), data.size());
		fbb_.Reset();
	}

	template <typename Msg>
	void Recv(Msg& msg)
	{
		typedef typename Msg::TableType Raw;
		flatbuffers::uoffset_t size;
		Recv(&size, sizeof(size));
		recv_buf_.resize(size);
		Recv(recv_buf_.data(), size);
		auto raw = flatbuffers::GetRoot<Raw>(recv_buf_.data());
		raw->UnPackTo(&msg);
	}

	void Send(const void* data, size_t size)
	{
		for (size_t sent = 0; sent < size;) {
			ssize_t n = write(fd_, static_cast<const char*>(data) + sent, size - sent);
			if (n > 0) {
				sent += n;
				continue;
			}
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN) {
				sleep_ms(1);
				continue;
			}
			failmsg("failed to send rpc", "fd=%d want=%zu sent=%zu n=%zd", fd_, size, sent, n);
		}
	}

private:
	const int fd_;
	flatbuffers::FlatBufferBuilder fbb_;
	std::vector<char> recv_buf_;

	void Recv(void* data, size_t size)
	{
		for (size_t recv = 0; recv < size;) {
			ssize_t n = read(fd_, static_cast<char*>(data) + recv, size - recv);
			if (n > 0) {
				recv += n;
				continue;
			}
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN) {
				sleep_ms(1);
				continue;
			}
			failmsg("failed to recv rpc", "fd=%d want=%zu sent=%zu n=%zd", fd_, size, recv, n);
		}
	}

	Connection(const Connection&) = delete;
	Connection& operator=(const Connection&) = delete;
};

class Proc
{
public:
	Proc(Connection& conn, const char* bin, int id, int max_signal_fd, int cover_fitler_fd)
	    : conn_(conn), bin_(bin), id_(id), max_signal_fd_(max_signal_fd), cover_fitler_fd_(cover_fitler_fd)
	{
		//!!! create binaries with unique names
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
		//!!! support rpc::RequestFlag::ResetState
		if (state_ == State::Idle && (exec_env_ != msg.exec_opts->env_flags() || sandbox_arg_ != msg.exec_opts->sandbox_arg()))
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
			now > exec_start_ + 10*1000) {
			Restart();
			return;
		}
	
		if (select.Ready(stdout_pipe_) && !ReadOutput()) {
			Restart();
			return;
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
	uint64 attempts_ = 0;
	uint64 freshness_ = 0;
	uint64 exec_start_ = 0;
	uint64 wait_start_ = 0;
	uint64 wait_end_ = 0;

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
		// Ignore all other errors.
		// Without fork server executor can legitimately exit (program contains exit_group),
		// with fork server the top process can exit with kFailStatus if it wants special handling.
		int status = WEXITSTATUS(wstatus) == kFailStatus ? kFailStatus : 0;
		if (msg_ && IsSet(msg_->flags, rpc::RequestFlag::ReturnError)) {
			// Read out all pening output until EOF.
			if (IsSet(msg_->flags, rpc::RequestFlag::ReturnOutput)) {
				while (ReadOutput()) {
				}
			}
			HandleCompletion(status);
		} else if (status == kFailStatus && ++attempts_ >= 10) {
			while (ReadOutput()) {
			}
			output_.push_back(0);
			failmsg("repeatedly failed to execute the program", "proc=%d output:\n%s",
				id_, output_.data());
		}
		Start();
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
		    //!!! add global debug flag in conn_reply and pipe output to stderr
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
		if (posix_spawn(&pid_, bin_, &actions, &attr,
				const_cast<char**>(child_argv), const_cast<char**>(child_envp)))
			fail("posix_spawn failed");
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
		exec_env_ = msg_->exec_opts->env_flags();
		sandbox_arg_ = msg_->exec_opts->sandbox_arg();
		handshake_req req = {
		    .magic = kInMagic,
		    .flags = static_cast<uint64>(exec_env_),
		    .pid = static_cast<uint64>(id_),
		    .sandbox_arg = static_cast<uint64>(sandbox_arg_),
		};
		if (flag_debug)
			req.flags |= static_cast<uint64>(rpc::ExecEnv::Debug);
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

		memset(static_cast<void*>(resp_mem_), 0, sizeof(*resp_mem_));
		//!!! check size
		memcpy(req_mem_, msg_->prog_data.data(), msg_->prog_data.size());
		execute_req req{
		    .magic = kInMagic,
		    .env_flags = static_cast<uint64>(exec_env_),
		    .exec_flags = static_cast<uint64>(msg_->exec_opts->exec_flags()),
		    .pid = static_cast<uint64>(id_),
		    .syscall_timeout_ms = 100, //!!!
		    .program_timeout_ms = 5000, //!!!
		    .slowdown_scale = 1, //!!!
		};
		if (flag_debug)
			req.env_flags |= static_cast<uint64>(rpc::ExecEnv::Debug);
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

		uint64 elapsed = (current_time_ms() - exec_start_) * 1000 * 1000;
		uint8* prog_data = msg_->prog_data.data();
		input_data = prog_data;
		size_t num_calls = read_input(&prog_data);

		uint32 calls_size = 0;
		int output_size = resp_mem_->output_size ?: kMaxOutput;
		uint32 completed = resp_mem_->completed.load(std::memory_order_relaxed);
		completed = std::min(completed, kMaxCalls);
		if (completed) {
			calls_size = resp_mem_->calls[completed - 1].data_size;
			//!!! move this check into ShmemBuilder
			/*
			if (builder_size <= 0)
				failmsg("negative output builder size",
					"size=%d output_size=%d header_size=%zu",
					builder_size, resp_mem_->output_size, sizeof(*resp_mem_));
			*/
		}
		// FixedAllocator alloc(resp_mem_ + 1, builder_size);
		// flatbuffers::FlatBufferBuilder fbb(builder_size, &alloc);
		// debug("XXX: completed=%u calls_size=%u output_size=%u\n", completed, calls_size, resp_mem_->output_size);
		ShmemBuilder fbb(resp_mem_ + 1, output_size - sizeof(*resp_mem_), calls_size);

		auto empty_call = rpc::CreateCallInfoRawDirect(fbb, rpc::CallFlag::NONE, 998);
		flatbuffers::Offset<rpc::CallInfoRaw> extra = 0;

		std::vector<flatbuffers::Offset<rpc::CallInfoRaw>> calls(num_calls, empty_call);
		for (uint32_t i = 0; i < completed; i++) {
			const auto& call = resp_mem_->calls[i];
			if (call.index == -1) {
				//!!! merge extra
				extra = call.offset;
				continue;
			}
			if (call.index < 0 || call.index >= static_cast<int>(num_calls))
				fail("bad call index"); //!!!
			calls[call.index] = call.offset /* - calls_size*/;
			// debug("XXX:   call %d/%d off=%u\n", i, call.index, call.offset.o);
		}

		auto prog_info_off = rpc::CreateProgInfoRawDirect(fbb, &calls, extra, elapsed, freshness_++);

		flatbuffers::Offset<flatbuffers::String> error_off = 0;
		if (status == kFailStatus)
			error_off = fbb.CreateString("process failed");
		flatbuffers::Offset<flatbuffers::Vector<uint8_t>> output_off = 0;
		if (IsSet(msg_->flags, rpc::RequestFlag::ReturnOutput)) {
			if (status) {
				char tmp[128];
				snprintf(tmp, sizeof(tmp), "\nprocess exited with status %d\n", status);
				// output_.insert(output_.end(), reinterpret_cast<uint8_t*>(tmp), strlen(tmp));
				output_.insert(output_.end(), tmp, tmp + strlen(tmp));
			}
			output_off = fbb.CreateVector(output_);
		}
		auto exec_off = rpc::CreateExecResultRaw(fbb, msg_->id, output_off, error_off, prog_info_off);

		auto msg_off = rpc::CreateExecutorMessageRaw(fbb, rpc::ExecutorMessagesRaw::ExecResult, flatbuffers::Offset<void>(exec_off.o));

		fbb.FinishSizePrefixed(msg_off);
		auto data = fbb.GetBufferSpan();

		// debug("SENDING: %zu\n", data.size());
		// debug_dump_data((char*)data.data(), data.size());

		conn_.Send(data.data(), data.size());

		msg_.reset();
		output_.clear();
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
		// size_t size = output_.size();
		output_.resize(output_.size() + kChunk);

		// uint8_t*

		// char buf[1024];
		ssize_t n = read(stdout_pipe_, output_.data() + output_.size() - kChunk, kChunk);
		if (n < 0) {
			if (errno == EINTR || errno == EAGAIN)
				return true;
			fail("proc stdout read failed");
		}
		if (n == 0) {
			debug("proc %d: output pipe EOF\n", id_);
			return false;
		}
		output_.resize(output_.size() - kChunk + n);
		// if (n != 0 && buf[n - 1] == '\n')
		//	n--;
		// buf[n] = 0;
		// debug("proc %d: got output: %s\n", id_, buf);
		return true;
	}
};

class Runner
{
public:
	Runner(Connection& conn, const char* name, const char* bin)
	    : conn_(conn), name_(name)
	{
		size_t num_procs = handshake();

		int max_signal_fd = max_signal_ ? max_signal_->FD() : -1;
		int cover_filter_fd = cover_filter_ ? cover_filter_->FD() : -1;
		for (size_t i = 0; i < num_procs; i++)
			procs_.emplace_back(new Proc(conn, bin, i, max_signal_fd, cover_filter_fd));

		for (;;)
			loop();
	}

private:
	Connection& conn_;
	const char* const name_;
	std::optional<CoverFilter> max_signal_;
	std::optional<CoverFilter> cover_filter_;
	std::vector<std::unique_ptr<Proc>> procs_;
	std::deque<rpc::ExecRequestRawT> requests_;

	//!!! change all to Pascal
	void loop()
	{
		Select select;
		select.Arm(conn_.FD());
		for (auto& proc : procs_)
			proc->Arm(select);
		select.Wait(1000);
		uint64 now = current_time_ms();

		//!!! check if any process is in executing state for too long
		//!!! or in handshake and kill.

		if (select.Ready(conn_.FD())) {
			rpc::HostMessageRawT raw;
			conn_.Recv(raw);
			if (auto* msg = raw.msg.AsExecRequest())
				handle(*msg);
			else if (auto* msg = raw.msg.AsSignalUpdate())
				handle(*msg);
			else if (auto* msg = raw.msg.AsStartLeakChecks())
				handle(*msg);
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

	size_t handshake()
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
		debug("connected to manager: procs=%d slowdown=%d features=0x%llx\n",
		      conn_reply.procs, conn_reply.slowdown, static_cast<uint64>(conn_reply.features));

		rpc::InfoRequestRawT info_req;

		// This does any one-time setup for the requested features on the machine.
		// Note: this can be called multiple times and must be idempotent.
		is_kernel_64_bit = detect_kernel_bitness();
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

		//!!! std::vector<std::string> leak_frames{};
#if SYZ_HAVE_KCSAN
		setup_kcsan_filter(conn_reply.race_frames);
#endif

		// std::string error{};
		//!!! std::vector<std::unique_ptr<rpc::GlobInfoRawT>> globs{};
		std::vector<uint8_t> tmp(1 << 20);
		for (const auto& file : conn_reply.files) {
			auto info = std::make_unique<rpc::FileInfoRawT>();
			info->name = file;
			int fd = open(file.c_str(), O_RDONLY);
			if (fd == -1) {
				info->exists = errno != EEXIST && errno != ENOENT;
				info->error = strerror(errno);
			} else {
				info->exists = true;
				ssize_t n = read(fd, tmp.data(), tmp.size());
				if (n < 0) {
					info->error = strerror(errno);
				} else {
					info->data.assign(tmp.begin(), tmp.begin() + n);
				}
				close(fd);
			}
			debug("reading file %s: size=%zu exists=%d error=%s\n",
			      info->name.c_str(), info->data.size(), info->exists, info->error.c_str());
			info_req.files.push_back(std::move(info));
		}

		conn_.Send(info_req);

		rpc::InfoReplyRawT info_reply;
		conn_.Recv(info_reply);
		debug("received info reply: covfilter=%zu\n", info_reply.cover_filter.size());

		// if (conn_reply.signal)
		max_signal_.emplace("syz-max-signal");

		if (!info_reply.cover_filter.empty()) {
			cover_filter_.emplace("syz-cover-filer");
			for (auto pc : info_reply.cover_filter)
				cover_filter_->Insert(pc);
		}

		Select::Prepare(conn_.FD());
		return conn_reply.procs;
	}

	void handle(rpc::ExecRequestRawT& msg)
	{
		debug("recv exec request %llu: flags=0x%llx env=0x%llx exec=0x%llx size=%zu\n",
		      static_cast<uint64>(msg.id),
		      static_cast<uint64>(msg.flags),
		      static_cast<uint64>(msg.exec_opts->env_flags()),
		      static_cast<uint64>(msg.exec_opts->exec_flags()),
		      msg.prog_data.size());
		for (auto& proc : procs_) {
			if (proc->Execute(msg))
				return;
		}
		requests_.push_back(std::move(msg));
	}

	void handle(const rpc::SignalUpdateRawT& msg)
	{
		debug("recv signal update: new=%zu drop=%zu\n", msg.new_max.size(), msg.drop_max.size());
		if (!max_signal_)
			fail("signal update when no signal filter installed");
		for (auto pc : msg.new_max)
			max_signal_->Insert(pc);
		for (auto pc : msg.drop_max)
			max_signal_->Remove(pc);
	}

	void handle(const rpc::StartLeakChecksRawT& msg)
	{
		debug("recv start leak checks\n");
	}
};

static void SignalHandler(int sig)
{
	// GCE VM preemption is signalled as SIGINT, notify syz-manager.
	if (sig == SIGINT)
		exitf("SYZ-EXECUTOR: PREEMPTED");
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
	if (signal(SIGINT, SignalHandler))
		fail("signal(SIGINT) failed");
	if (signal(SIGCHLD, SignalHandler))
		fail("signal(SIGCHLD) failed");

	int fd = connect_to_host(manager_addr, manager_port);
	if (fd == -1)
		fail("can't connect to manager");
	Connection conn(fd);
	Runner(conn, name, argv[0]);
}

template <typename addr_t>
static int connect_to_addr(addr_t* addr, void* ip, int port)
{
	auto* saddr = reinterpret_cast<sockaddr*>(addr);
	int fd = socket(saddr->sa_family, SOCK_STREAM, IPPROTO_TCP);
	if (fd == -1)
		fail("failed to create socket");
	char str[128] = {};
	inet_ntop(saddr->sa_family, ip, str, sizeof(str));
	if (connect(fd, saddr, sizeof(*addr))) {
		printf("failed to connect to manager at %s:%d: %s\n", str, port, strerror(errno));
		close(fd);
		return -1;
	}
	return fd;
}

int connect_to_host(const char* addr, const char* ports)
{
	int port = atoi(ports);
	if (port == 0)
		failmsg("failed to parse manager port", "port=%s", ports);
	if (!strcmp(addr, "stdin"))
		return STDIN_FILENO;
	sockaddr_in saddr4 = {};
	saddr4.sin_family = AF_INET;
	saddr4.sin_port = htons(port);
	if (inet_pton(AF_INET, addr, &saddr4.sin_addr))
		return connect_to_addr(&saddr4, &saddr4.sin_addr, port);
	sockaddr_in6 saddr6 = {};
	saddr6.sin6_family = AF_INET6;
	saddr6.sin6_port = htons(port);
	if (inet_pton(AF_INET6, addr, &saddr6.sin6_addr))
		return connect_to_addr(&saddr6, &saddr6.sin6_addr, port);
	auto* hostent = gethostbyname(addr);
	if (!hostent)
		failmsg("failed to resolve manager addr", "addr=%s h_errno=%d", addr, h_errno);
	for (char** addr = hostent->h_addr_list; *addr; addr++) {
		int fd;
		if (hostent->h_addrtype == AF_INET) {
			memcpy(&saddr4.sin_addr, *addr, std::min<size_t>(hostent->h_length, sizeof(saddr4.sin_addr)));
			fd = connect_to_addr(&saddr4, &saddr4.sin_addr, port);
		} else if (hostent->h_addrtype == AF_INET6) {
			memcpy(&saddr6.sin6_addr, *addr, std::min<size_t>(hostent->h_length, sizeof(saddr6.sin6_addr)));
			fd = connect_to_addr(&saddr6, &saddr6.sin6_addr, port);
		} else {
			failmsg("unknown socket family", "family=%d", hostent->h_addrtype);
		}
		if (fd != -1)
			return fd;
	}
	return -1;
}
