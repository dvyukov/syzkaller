// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <spawn.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/socket.h>

#include <algorithm>
#include <memory>
#include <thread>
#include <vector>

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
};

class Proc
{
public:
	Proc(const char* bin, int id)
	    : bin_(bin), id_(id)
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
		if (fallocate(resp_mem_fd_, 0, 0, kMaxOutputComparisons))
			fail("fallocate failed");
		resp_mem_ = mmap(nullptr, kMaxInput, PROT_READ | PROT_WRITE, MAP_SHARED, resp_mem_fd_, 0);
		if (resp_mem_ == MAP_FAILED)
			fail("mmap failed");
	}

	void MaybeRestart()
	{
		if (state_ != State::Dead)
			return;
		state_ = State::Started;
		debug("proc %d: starting subprocess\n", id_);
		int req_pipe[2];
		if (pipe(req_pipe))
			fail("pipe failed");
		int resp_pipe[2];
		if (pipe(resp_pipe))
			fail("pipe failed");
		int stdout_pipe[2];
		if (pipe(stdout_pipe))
			fail("pipe failed");

		// int posix_spawnattr_setpgroup(posix_spawnattr_t *attr, pid_t pgroup);
		// int posix_spawnattr_destroy(posix_spawnattr_t *attr);
		// int posix_spawnattr_init(posix_spawnattr_t *attr);

		posix_spawn_file_actions_t actions;
		if (posix_spawn_file_actions_init(&actions))
			fail("posix_spawn_file_actions_init failed");
		if (posix_spawn_file_actions_adddup2(&actions, req_pipe[0], STDIN_FILENO))
			fail("posix_spawn_file_actions_adddup2 failed");
		if (posix_spawn_file_actions_adddup2(&actions, resp_pipe[1], STDOUT_FILENO))
			fail("posix_spawn_file_actions_adddup2 failed");
		if (posix_spawn_file_actions_adddup2(&actions, stdout_pipe[1], STDERR_FILENO))
			fail("posix_spawn_file_actions_adddup2 failed");
		if (posix_spawn_file_actions_adddup2(&actions, req_mem_fd_, kInFd))
			fail("posix_spawn_file_actions_adddup2 failed");
		if (posix_spawn_file_actions_adddup2(&actions, resp_mem_fd_, kOutFd))
			fail("posix_spawn_file_actions_adddup2 failed");
		for (int i = kOutFd + 1; i < kFdLimit; i++) {
			if (posix_spawn_file_actions_addclose(&actions, i))
				fail("posix_spawn_file_actions_addclose failed");
		}

		pid_t pid;
		char* child_argv[] = {const_cast<char*>(bin_), const_cast<char*>("exec"), nullptr};
		if (posix_spawn(&pid, bin_, &actions, nullptr, child_argv, nullptr))
			fail("posix_spawn failed");
		if (posix_spawn_file_actions_destroy(&actions))
			fail("posix_spawn_file_actions_destroy failed");

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
	}

	bool Execute(rpc::ExecRequestRawT& msg)
	{
		if (state_ != State::Idle || exec_env_ != msg.exec_opts->env_flags() ||
		    sandbox_arg_ != msg.exec_opts->sandbox_arg())
			return false;
		state_ = State::Executing;
		debug("proc %d: start executing request %llu\n", id_, static_cast<uint64>(msg.id));
		//!!! check size
		memcpy(req_mem_, msg.prog_data.data(), msg.prog_data.size());
		execute_req req{
		    .magic = kInMagic,
		    .env_flags = static_cast<uint64>(exec_env_),
		    .exec_flags = static_cast<uint64>(msg.exec_opts->exec_flags()),
		    .pid = static_cast<uint64>(id_),
		    .syscall_timeout_ms = 100,
		    .program_timeout_ms = 5000,
		    .slowdown_scale = 1,
		    //.prog_size = msg.prog_data.size(),
		};
		if (flag_debug)
			req.env_flags |= static_cast<uint64>(rpc::ExecEnv::Debug);
		if (write(req_pipe_, &req, sizeof(req)) != sizeof(req))
			fail("request pipe write failed");
		return true;
	}

	bool Handshake(rpc::ExecRequestRawT& msg)
	{
		if (state_ != State::Started)
			return false;
		debug("proc %d: handshaking to execute request\n", id_);
		state_ = State::Handshaking;
		exec_env_ = msg.exec_opts->env_flags();
		sandbox_arg_ = msg.exec_opts->sandbox_arg();
		handshake_req req = {
		    .magic = kInMagic,
		    .flags = static_cast<uint64>(exec_env_),
		    .pid = static_cast<uint64>(id_),
		    .sandbox_arg = static_cast<uint64>(sandbox_arg_),
		};
		if (flag_debug)
			req.flags |= static_cast<uint64>(rpc::ExecEnv::Debug);
		if (write(req_pipe_, &req, sizeof(req)) != sizeof(req))
			fail("request pipe write failed");
		pending_msg_ = std::move(msg);
		return true;
	}

	bool Restart(rpc::ExecRequestRawT& msg)
	{
		return false;
	}

	void Arm(Select& select)
	{
		select.Arm(resp_pipe_);
		select.Arm(stdout_pipe_);
	}

	void Ready(Select& select)
	{
		if (select.Ready(stdout_pipe_)) {
			char buf[128];
			ssize_t n = read(stdout_pipe_, buf, sizeof(buf) - 1);
			if (n < 0)
				fail("proc stdout read failed");
			if (n == 0) {
				state_ = State::Dead;
				return;
			}
			if (n != 0 && buf[n - 1] == '\n')
				n--;
			buf[n] = 0;
			debug("proc %d: got output: %s\n", id_, buf);
		}
		if (select.Ready(resp_pipe_)) {
			char buf[128];
			ssize_t n = read(resp_pipe_, buf, sizeof(buf) - 1);
			if (n < 0)
				fail("proc resp pipe read failed");
			if (n == 0) {
				state_ = State::Dead;
				return;
			}
			if (state_ == State::Handshaking) {
				if (n != sizeof(handshake_reply))
					failmsg("bad handshake reply size", "size=%zu want=%zu",
						n, sizeof(handshake_reply));
				const auto* reply = reinterpret_cast<handshake_reply*>(buf);
				if (reply->magic != kOutMagic)
					failmsg("bad handshake reply magic", "magic=0x%x want=0x%x",
						reply->magic, kOutMagic);
				debug("proc %d: got handshake reply\n", id_);
				state_ = State::Idle;
				if (!Execute(pending_msg_))
					fail("can't execute after handshake");
				pending_msg_ = rpc::ExecRequestRawT{};
			} else if (state_ == State::Executing) {
				if (n != sizeof(execute_reply))
					failmsg("bad execute reply size", "size=%zu want=%zu",
						n, sizeof(execute_reply));
				const auto* reply = reinterpret_cast<execute_reply*>(buf);
				if (reply->magic != kOutMagic)
					failmsg("bad execute reply magic", "magic=0x%x want=0x%x",
						reply->magic, kOutMagic);
				debug("proc %d: got execute reply: done=%d status=%d\n",
				      id_, reply->done, reply->status);
				state_ = State::Idle;
			} else {
				failmsg("got data on response pipe in wrong state", "state=%d", state_);
			}
		}
	}

private:
	enum State : uint8 {
		Dead,
		Started,
		Handshaking,
		Idle,
		Executing,
	};

	const char* const bin_;
	const int id_;
	State state_ = State::Dead;
	void* req_mem_ = nullptr;
	void* resp_mem_ = nullptr;
	int req_mem_fd_ = -1;
	int resp_mem_fd_ = -1;
	int req_pipe_ = -1;
	int resp_pipe_ = -1;
	int stdout_pipe_ = -1;
	rpc::ExecEnv exec_env_ = rpc::ExecEnv::NONE;
	int64_t sandbox_arg_ = 0;
	rpc::ExecRequestRawT pending_msg_;
};

class Runner
{
public:
	Runner(int conn, const char* name, const char* bin)
	    : conn_(conn), name_(name)
	{
		size_t num_procs = handshake();

		for (size_t i = 0; i < num_procs; i++)
			procs_.emplace_back(new Proc(bin, i));

		for (;;)
			loop();
	}

private:
	const int conn_;
	const char* const name_;
	std::vector<std::unique_ptr<Proc>> procs_;
	flatbuffers::FlatBufferBuilder fbb_;
	std::vector<char> recv_buf_;
	std::vector<rpc::ExecRequestRawT> requests_;

	void loop()
	{
		Select select;
		select.Arm(conn_);

		for (auto& proc : procs_) {
			proc->MaybeRestart();
			proc->Arm(select);
		}

		select.Wait(1000);

		if (select.Ready(conn_)) {
			rpc::HostMessageRawT raw;
			recv(raw);
			if (auto* msg = raw.msg.AsExecRequest())
				handle(*msg);
			else if (auto* msg = raw.msg.AsSignalUpdate())
				handle(*msg);
			else if (auto* msg = raw.msg.AsStartLeakChecks())
				handle(*msg);
			else
				failmsg("unknown host message type", "type=%d", static_cast<int>(raw.msg.type));
		}

		for (auto& proc : procs_)
			proc->Ready(select);
	}

	size_t handshake()
	{
		rpc::ConnectRequestRawT conn_req;
		conn_req.name = name_;
		conn_req.arch = GOARCH;
		conn_req.git_revision = GIT_REVISION;
		conn_req.syz_revision = SYZ_REVISION;
		send(conn_req);

		rpc::ConnectReplyRawT conn_reply;
		recv(conn_reply);
		if (conn_reply.debug)
			flag_debug = true;
		debug("connected to manager: procs=%d slowdown=%d features=0x%llx\n",
		      conn_reply.procs, conn_reply.slowdown, static_cast<uint64>(conn_reply.features));

		rpc::InfoRequestRawT info_req;
		/*
		  std::string error{};
		  std::vector<std::unique_ptr<rpc::FeatureInfoRawT>> features{};
		  std::vector<std::unique_ptr<rpc::FileInfoRawT>> files{};
		  std::vector<std::unique_ptr<rpc::GlobInfoRawT>> globs{};
		*/
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
		send(info_req);

		rpc::InfoReplyRawT info_reply;
		recv(info_reply);
		debug("received info reply: covfilter=%zu\n", info_reply.cover_filter.size());

		Select::Prepare(conn_);
		return conn_reply.procs;
	}

	void handle(rpc::ExecRequestRawT& msg)
	{
		debug("recv exec request %llu: env=0x%llx flags=0x%llx prog=%zu\n",
		      static_cast<uint64>(msg.id),
		      static_cast<uint64>(msg.exec_opts->env_flags()),
		      static_cast<uint64>(msg.exec_opts->exec_flags()),
		      msg.prog_data.size());
		for (auto& proc : procs_) {
			if (proc->Execute(msg))
				return;
		}
		for (auto& proc : procs_) {
			if (proc->Handshake(msg))
				return;
		}
		for (auto& proc : procs_) {
			if (proc->Restart(msg))
				return;
		}
		requests_.push_back(std::move(msg));
	}

	void handle(const rpc::SignalUpdateRawT& msg)
	{
		debug("recv signal update: new=%zu drop=%zu\n", msg.new_max.size(), msg.drop_max.size());
	}

	void handle(const rpc::StartLeakChecksRawT& msg)
	{
		debug("recv start leak checks\n");
	}

	template <typename Msg>
	void send(const Msg& msg)
	{
		typedef typename Msg::TableType Raw;
		auto off = Raw::Pack(fbb_, &msg);
		fbb_.FinishSizePrefixed(off);
		auto data = fbb_.GetBufferSpan();
		ssize_t n = write_all(conn_, data.data(), data.size());
		if (n != static_cast<ssize_t>(data.size()))
			fail("failed to send");
		fbb_.Reset();
	}

	template <typename Msg>
	void recv(Msg& msg)
	{
		typedef typename Msg::TableType Raw;
		flatbuffers::uoffset_t size;
		if (read(conn_, &size, sizeof(size)) != sizeof(size))
			fail("failed to recv");
		recv_buf_.resize(size);
		if (read(conn_, recv_buf_.data(), size) != size)
			fail("failed to recv");
		auto raw = flatbuffers::GetRoot<Raw>(recv_buf_.data());
		raw->UnPackTo(&msg);
	}

	ssize_t write_all(int fd, const void* data, size_t size)
	{
		return write(fd, data, size);
	}
};

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

	// TODO: handle SIGINTR

	int conn = connect_to_host(manager_addr, manager_port);
	if (conn == -1)
		fail("can't connect to manager");

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
