// AUTOGENERATED FILE

#if GOOS_akaros

static bool flag_debug;
static bool flag_threaded;
static bool flag_collide;
static bool flag_repeat;
static bool flag_multi_proc;
static bool flag_use_tmp_dir;
static bool flag_handle_segv;
static bool flag_sandbox_empty;
static bool flag_sandbox_none;

static const struct feature_t features[] = {
    [0] = {&flag_debug, "Debug"},
    [1] = {&flag_threaded, "Threaded"},
    [2] = {&flag_collide, "Collide"},
    [3] = {&flag_repeat, "Repeat"},
    [4] = {&flag_multi_proc, "MultiProc"},
    [5] = {&flag_use_tmp_dir, "UseTmpDir"},
    [6] = {&flag_handle_segv, "HandleSegv"},
    [12] = {&flag_sandbox_empty, "SandboxEmpty"},
    [13] = {&flag_sandbox_none, "SandboxNone"},
};
#endif

#if GOOS_freebsd

static bool flag_debug;
static bool flag_threaded;
static bool flag_collide;
static bool flag_repeat;
static bool flag_multi_proc;
static bool flag_use_tmp_dir;
static bool flag_handle_segv;
static bool flag_coverage;
static bool flag_comparisons;
static bool flag_raw_coverage;
static bool flag_trace_coverage;
static bool flag_sandbox_empty;
static bool flag_sandbox_none;
static bool flag_sandbox_setuid;
static bool flag_net_injection;

#define SYZ_HAVE_COVERAGE 1
#define SYZ_HAVE_COMPARISONS 1
#define SYZ_HAVE_RAW_COVERAGE 1
#define SYZ_HAVE_TRACE_COVERAGE 1
#define SYZ_HAVE_SANDBOX_SETUID 1
#define SYZ_HAVE_NET_INJECTION 1

static const struct feature_t features[] = {
    [0] = {&flag_debug, "Debug"},
    [1] = {&flag_threaded, "Threaded"},
    [2] = {&flag_collide, "Collide"},
    [3] = {&flag_repeat, "Repeat"},
    [4] = {&flag_multi_proc, "MultiProc"},
    [5] = {&flag_use_tmp_dir, "UseTmpDir"},
    [6] = {&flag_handle_segv, "HandleSegv"},
    [7] = {&flag_coverage, "Coverage"},
    [9] = {&flag_comparisons, "Comparisons"},
    [10] = {&flag_raw_coverage, "RawCoverage"},
    [11] = {&flag_trace_coverage, "TraceCoverage"},
    [12] = {&flag_sandbox_empty, "SandboxEmpty"},
    [13] = {&flag_sandbox_none, "SandboxNone"},
    [14] = {&flag_sandbox_setuid, "SandboxSetuid"},
    [20] = {&flag_net_injection, "NetInjection"},
};
#endif

#if GOOS_fuchsia

static bool flag_debug;
static bool flag_threaded;
static bool flag_collide;
static bool flag_repeat;
static bool flag_multi_proc;
static bool flag_use_tmp_dir;
static bool flag_handle_segv;
static bool flag_sandbox_empty;
static bool flag_sandbox_none;

static const struct feature_t features[] = {
    [0] = {&flag_debug, "Debug"},
    [1] = {&flag_threaded, "Threaded"},
    [2] = {&flag_collide, "Collide"},
    [3] = {&flag_repeat, "Repeat"},
    [4] = {&flag_multi_proc, "MultiProc"},
    [5] = {&flag_use_tmp_dir, "UseTmpDir"},
    [6] = {&flag_handle_segv, "HandleSegv"},
    [12] = {&flag_sandbox_empty, "SandboxEmpty"},
    [13] = {&flag_sandbox_none, "SandboxNone"},
};
#endif

#if GOOS_linux

static bool flag_debug;
static bool flag_threaded;
static bool flag_collide;
static bool flag_repeat;
static bool flag_multi_proc;
static bool flag_use_tmp_dir;
static bool flag_handle_segv;
static bool flag_coverage;
static bool flag_extra_coverage;
static bool flag_comparisons;
static bool flag_raw_coverage;
static bool flag_trace_coverage;
static bool flag_sandbox_empty;
static bool flag_sandbox_none;
static bool flag_sandbox_setuid;
static bool flag_sandbox_namespace;
static bool flag_sandbox_android;
static bool flag_fault;
static bool flag_leak;
static bool flag_kcsan;
static bool flag_net_injection;
static bool flag_net_devices;
static bool flag_net_reset;
static bool flag_devlink_pci;
static bool flag_cgroups;
static bool flag_close_fds;
static bool flag_binfmt_misc;

#define SYZ_HAVE_COVERAGE 1
#define SYZ_HAVE_EXTRA_COVERAGE 1
#define SYZ_HAVE_COMPARISONS 1
#define SYZ_HAVE_RAW_COVERAGE 1
#define SYZ_HAVE_TRACE_COVERAGE 1
#define SYZ_HAVE_SANDBOX_SETUID 1
#define SYZ_HAVE_SANDBOX_NAMESPACE 1
#define SYZ_HAVE_SANDBOX_ANDROID 1
#define SYZ_HAVE_FAULT 1
#define SYZ_HAVE_LEAK 1
#define SYZ_HAVE_KCSAN 1
#define SYZ_HAVE_NET_INJECTION 1
#define SYZ_HAVE_NET_DEVICES 1
#define SYZ_HAVE_NET_RESET 1
#define SYZ_HAVE_DEVLINK_PCI 1
#define SYZ_HAVE_CGROUPS 1
#define SYZ_HAVE_CLOSE_FDS 1
#define SYZ_HAVE_BINFMT_MISC 1

static void setup_fault();
static void setup_leak();
static void setup_kcsan();
static void setup_binfmt_misc();

static const struct feature_t features[] = {
    [0] = {&flag_debug, "Debug"},
    [1] = {&flag_threaded, "Threaded"},
    [2] = {&flag_collide, "Collide"},
    [3] = {&flag_repeat, "Repeat"},
    [4] = {&flag_multi_proc, "MultiProc"},
    [5] = {&flag_use_tmp_dir, "UseTmpDir"},
    [6] = {&flag_handle_segv, "HandleSegv"},
    [7] = {&flag_coverage, "Coverage"},
    [8] = {&flag_extra_coverage, "ExtraCoverage"},
    [9] = {&flag_comparisons, "Comparisons"},
    [10] = {&flag_raw_coverage, "RawCoverage"},
    [11] = {&flag_trace_coverage, "TraceCoverage"},
    [12] = {&flag_sandbox_empty, "SandboxEmpty"},
    [13] = {&flag_sandbox_none, "SandboxNone"},
    [14] = {&flag_sandbox_setuid, "SandboxSetuid"},
    [15] = {&flag_sandbox_namespace, "SandboxNamespace"},
    [16] = {&flag_sandbox_android, "SandboxAndroid"},
    [17] = {&flag_fault, "Fault", setup_fault},
    [18] = {&flag_leak, "Leak", setup_leak},
    [19] = {&flag_kcsan, "KCSAN", setup_kcsan},
    [20] = {&flag_net_injection, "NetInjection"},
    [21] = {&flag_net_devices, "NetDevices"},
    [22] = {&flag_net_reset, "NetReset"},
    [23] = {&flag_devlink_pci, "DevlinkPCI"},
    [24] = {&flag_cgroups, "Cgroups"},
    [25] = {&flag_close_fds, "CloseFDs"},
    [26] = {&flag_binfmt_misc, "BinfmtMisc", setup_binfmt_misc},
};
#endif

#if GOOS_netbsd

static bool flag_debug;
static bool flag_threaded;
static bool flag_collide;
static bool flag_repeat;
static bool flag_multi_proc;
static bool flag_use_tmp_dir;
static bool flag_handle_segv;
static bool flag_coverage;
static bool flag_comparisons;
static bool flag_raw_coverage;
static bool flag_trace_coverage;
static bool flag_sandbox_empty;
static bool flag_sandbox_none;
static bool flag_sandbox_setuid;

#define SYZ_HAVE_COVERAGE 1
#define SYZ_HAVE_COMPARISONS 1
#define SYZ_HAVE_RAW_COVERAGE 1
#define SYZ_HAVE_TRACE_COVERAGE 1
#define SYZ_HAVE_SANDBOX_SETUID 1

static const struct feature_t features[] = {
    [0] = {&flag_debug, "Debug"},
    [1] = {&flag_threaded, "Threaded"},
    [2] = {&flag_collide, "Collide"},
    [3] = {&flag_repeat, "Repeat"},
    [4] = {&flag_multi_proc, "MultiProc"},
    [5] = {&flag_use_tmp_dir, "UseTmpDir"},
    [6] = {&flag_handle_segv, "HandleSegv"},
    [7] = {&flag_coverage, "Coverage"},
    [9] = {&flag_comparisons, "Comparisons"},
    [10] = {&flag_raw_coverage, "RawCoverage"},
    [11] = {&flag_trace_coverage, "TraceCoverage"},
    [12] = {&flag_sandbox_empty, "SandboxEmpty"},
    [13] = {&flag_sandbox_none, "SandboxNone"},
    [14] = {&flag_sandbox_setuid, "SandboxSetuid"},
};
#endif

#if GOOS_openbsd

static bool flag_debug;
static bool flag_threaded;
static bool flag_collide;
static bool flag_repeat;
static bool flag_multi_proc;
static bool flag_use_tmp_dir;
static bool flag_handle_segv;
static bool flag_coverage;
static bool flag_comparisons;
static bool flag_raw_coverage;
static bool flag_trace_coverage;
static bool flag_sandbox_empty;
static bool flag_sandbox_none;
static bool flag_sandbox_setuid;
static bool flag_net_injection;

#define SYZ_HAVE_COVERAGE 1
#define SYZ_HAVE_COMPARISONS 1
#define SYZ_HAVE_RAW_COVERAGE 1
#define SYZ_HAVE_TRACE_COVERAGE 1
#define SYZ_HAVE_SANDBOX_SETUID 1
#define SYZ_HAVE_NET_INJECTION 1

static const struct feature_t features[] = {
    [0] = {&flag_debug, "Debug"},
    [1] = {&flag_threaded, "Threaded"},
    [2] = {&flag_collide, "Collide"},
    [3] = {&flag_repeat, "Repeat"},
    [4] = {&flag_multi_proc, "MultiProc"},
    [5] = {&flag_use_tmp_dir, "UseTmpDir"},
    [6] = {&flag_handle_segv, "HandleSegv"},
    [7] = {&flag_coverage, "Coverage"},
    [9] = {&flag_comparisons, "Comparisons"},
    [10] = {&flag_raw_coverage, "RawCoverage"},
    [11] = {&flag_trace_coverage, "TraceCoverage"},
    [12] = {&flag_sandbox_empty, "SandboxEmpty"},
    [13] = {&flag_sandbox_none, "SandboxNone"},
    [14] = {&flag_sandbox_setuid, "SandboxSetuid"},
    [20] = {&flag_net_injection, "NetInjection"},
};
#endif

#if GOOS_test

static bool flag_debug;
static bool flag_threaded;
static bool flag_collide;
static bool flag_repeat;
static bool flag_multi_proc;
static bool flag_use_tmp_dir;
static bool flag_handle_segv;
static bool flag_sandbox_empty;
static bool flag_sandbox_none;

static const struct feature_t features[] = {
    [0] = {&flag_debug, "Debug"},
    [1] = {&flag_threaded, "Threaded"},
    [2] = {&flag_collide, "Collide"},
    [3] = {&flag_repeat, "Repeat"},
    [4] = {&flag_multi_proc, "MultiProc"},
    [5] = {&flag_use_tmp_dir, "UseTmpDir"},
    [6] = {&flag_handle_segv, "HandleSegv"},
    [12] = {&flag_sandbox_empty, "SandboxEmpty"},
    [13] = {&flag_sandbox_none, "SandboxNone"},
};
#endif

#if GOOS_trusty

static bool flag_debug;
static bool flag_threaded;
static bool flag_collide;
static bool flag_repeat;
static bool flag_multi_proc;
static bool flag_use_tmp_dir;
static bool flag_handle_segv;
static bool flag_sandbox_empty;
static bool flag_sandbox_none;

static const struct feature_t features[] = {
    [0] = {&flag_debug, "Debug"},
    [1] = {&flag_threaded, "Threaded"},
    [2] = {&flag_collide, "Collide"},
    [3] = {&flag_repeat, "Repeat"},
    [4] = {&flag_multi_proc, "MultiProc"},
    [5] = {&flag_use_tmp_dir, "UseTmpDir"},
    [6] = {&flag_handle_segv, "HandleSegv"},
    [12] = {&flag_sandbox_empty, "SandboxEmpty"},
    [13] = {&flag_sandbox_none, "SandboxNone"},
};
#endif

#if GOOS_windows

static bool flag_debug;
static bool flag_threaded;
static bool flag_collide;
static bool flag_repeat;
static bool flag_multi_proc;
static bool flag_use_tmp_dir;
static bool flag_handle_segv;
static bool flag_sandbox_empty;
static bool flag_sandbox_none;

static const struct feature_t features[] = {
    [0] = {&flag_debug, "Debug"},
    [1] = {&flag_threaded, "Threaded"},
    [2] = {&flag_collide, "Collide"},
    [3] = {&flag_repeat, "Repeat"},
    [4] = {&flag_multi_proc, "MultiProc"},
    [5] = {&flag_use_tmp_dir, "UseTmpDir"},
    [6] = {&flag_handle_segv, "HandleSegv"},
    [12] = {&flag_sandbox_empty, "SandboxEmpty"},
    [13] = {&flag_sandbox_none, "SandboxNone"},
};
#endif
