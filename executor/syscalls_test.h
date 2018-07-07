// AUTOGENERATED FILE

#if 0
#define GOARCH "32"
#define SYZ_REVISION "17f0e197820547caba2ae18c65c67a5ed775a9c5"
#define SYZ_EXECUTOR_USES_FORK_SERVER false
#define SYZ_EXECUTOR_USES_SHMEM false
#define SYZ_PAGE_SIZE 8192
#define SYZ_NUM_PAGES 2048
#define SYZ_DATA_OFFSET 536870912
#define SYZ_SYSCALL_COUNT 106
const call_t syscalls[] = {
	{"foo$any0", 0, (syscall_t)foo},
	{"foo$anyres", 0, (syscall_t)foo},
	{"foo$fmt0", 0, (syscall_t)foo},
	{"foo$fmt1", 0, (syscall_t)foo},
	{"foo$fmt2", 0, (syscall_t)foo},
	{"foo$fmt3", 0, (syscall_t)foo},
	{"foo$fmt4", 0, (syscall_t)foo},
	{"foo$fmt5", 0, (syscall_t)foo},
	{"mutate0", 0, (syscall_t)mutate0},
	{"mutate1", 0, (syscall_t)mutate1},
	{"mutate2", 0, (syscall_t)mutate2},
	{"mutate3", 0, (syscall_t)mutate3},
	{"mutate4", 0, (syscall_t)mutate4},
	{"mutate5", 0, (syscall_t)mutate5},
	{"mutate6", 0, (syscall_t)mutate6},
	{"mutate7", 0, (syscall_t)mutate7},
	{"mutate8", 0, (syscall_t)mutate8},
	{"serialize0", 0, (syscall_t)serialize0},
	{"serialize1", 0, (syscall_t)serialize1},
	{"syz_mmap", 0, (syscall_t)syz_mmap},
	{"syz_test", 0, (syscall_t)syz_test},
	{"syz_test$align0", 0, (syscall_t)syz_test},
	{"syz_test$align1", 0, (syscall_t)syz_test},
	{"syz_test$align2", 0, (syscall_t)syz_test},
	{"syz_test$align3", 0, (syscall_t)syz_test},
	{"syz_test$align4", 0, (syscall_t)syz_test},
	{"syz_test$align5", 0, (syscall_t)syz_test},
	{"syz_test$align6", 0, (syscall_t)syz_test},
	{"syz_test$align7", 0, (syscall_t)syz_test},
	{"syz_test$array0", 0, (syscall_t)syz_test},
	{"syz_test$array1", 0, (syscall_t)syz_test},
	{"syz_test$array2", 0, (syscall_t)syz_test},
	{"syz_test$bf0", 0, (syscall_t)syz_test},
	{"syz_test$bf1", 0, (syscall_t)syz_test},
	{"syz_test$csum_encode", 0, (syscall_t)syz_test},
	{"syz_test$csum_ipv4", 0, (syscall_t)syz_test},
	{"syz_test$csum_ipv4_tcp", 0, (syscall_t)syz_test},
	{"syz_test$csum_ipv4_udp", 0, (syscall_t)syz_test},
	{"syz_test$csum_ipv6_icmp", 0, (syscall_t)syz_test},
	{"syz_test$csum_ipv6_tcp", 0, (syscall_t)syz_test},
	{"syz_test$csum_ipv6_udp", 0, (syscall_t)syz_test},
	{"syz_test$end0", 0, (syscall_t)syz_test},
	{"syz_test$end1", 0, (syscall_t)syz_test},
	{"syz_test$excessive_args1", 0, (syscall_t)syz_test},
	{"syz_test$excessive_args2", 0, (syscall_t)syz_test},
	{"syz_test$excessive_fields1", 0, (syscall_t)syz_test},
	{"syz_test$hint_data", 0, (syscall_t)syz_test},
	{"syz_test$int", 0, (syscall_t)syz_test},
	{"syz_test$length0", 0, (syscall_t)syz_test},
	{"syz_test$length1", 0, (syscall_t)syz_test},
	{"syz_test$length10", 0, (syscall_t)syz_test},
	{"syz_test$length11", 0, (syscall_t)syz_test},
	{"syz_test$length12", 0, (syscall_t)syz_test},
	{"syz_test$length13", 0, (syscall_t)syz_test},
	{"syz_test$length14", 0, (syscall_t)syz_test},
	{"syz_test$length15", 0, (syscall_t)syz_test},
	{"syz_test$length16", 0, (syscall_t)syz_test},
	{"syz_test$length17", 0, (syscall_t)syz_test},
	{"syz_test$length18", 0, (syscall_t)syz_test},
	{"syz_test$length19", 0, (syscall_t)syz_test},
	{"syz_test$length2", 0, (syscall_t)syz_test},
	{"syz_test$length20", 0, (syscall_t)syz_test},
	{"syz_test$length21", 0, (syscall_t)syz_test},
	{"syz_test$length22", 0, (syscall_t)syz_test},
	{"syz_test$length23", 0, (syscall_t)syz_test},
	{"syz_test$length24", 0, (syscall_t)syz_test},
	{"syz_test$length25", 0, (syscall_t)syz_test},
	{"syz_test$length26", 0, (syscall_t)syz_test},
	{"syz_test$length27", 0, (syscall_t)syz_test},
	{"syz_test$length28", 0, (syscall_t)syz_test},
	{"syz_test$length29", 0, (syscall_t)syz_test},
	{"syz_test$length3", 0, (syscall_t)syz_test},
	{"syz_test$length4", 0, (syscall_t)syz_test},
	{"syz_test$length5", 0, (syscall_t)syz_test},
	{"syz_test$length6", 0, (syscall_t)syz_test},
	{"syz_test$length7", 0, (syscall_t)syz_test},
	{"syz_test$length8", 0, (syscall_t)syz_test},
	{"syz_test$length9", 0, (syscall_t)syz_test},
	{"syz_test$missing_resource", 0, (syscall_t)syz_test},
	{"syz_test$missing_struct", 0, (syscall_t)syz_test},
	{"syz_test$opt0", 0, (syscall_t)syz_test},
	{"syz_test$opt1", 0, (syscall_t)syz_test},
	{"syz_test$opt2", 0, (syscall_t)syz_test},
	{"syz_test$opt3", 0, (syscall_t)syz_test},
	{"syz_test$recur0", 0, (syscall_t)syz_test},
	{"syz_test$recur1", 0, (syscall_t)syz_test},
	{"syz_test$recur2", 0, (syscall_t)syz_test},
	{"syz_test$regression0", 0, (syscall_t)syz_test},
	{"syz_test$regression1", 0, (syscall_t)syz_test},
	{"syz_test$regression2", 0, (syscall_t)syz_test},
	{"syz_test$res0", 0, (syscall_t)syz_test},
	{"syz_test$res1", 0, (syscall_t)syz_test},
	{"syz_test$struct", 0, (syscall_t)syz_test},
	{"syz_test$syz_union3", 0, (syscall_t)syz_test},
	{"syz_test$syz_union4", 0, (syscall_t)syz_test},
	{"syz_test$text_x86_16", 0, (syscall_t)syz_test},
	{"syz_test$text_x86_32", 0, (syscall_t)syz_test},
	{"syz_test$text_x86_64", 0, (syscall_t)syz_test},
	{"syz_test$text_x86_real", 0, (syscall_t)syz_test},
	{"syz_test$type_confusion1", 0, (syscall_t)syz_test},
	{"syz_test$union0", 0, (syscall_t)syz_test},
	{"syz_test$union1", 0, (syscall_t)syz_test},
	{"syz_test$union2", 0, (syscall_t)syz_test},
	{"syz_test$vma0", 0, (syscall_t)syz_test},
	{"unsupported$0", 0, (syscall_t)unsupported},
	{"unsupported$1", 0, (syscall_t)unsupported},

};
#endif

#if 0
#define GOARCH "64"
#define SYZ_REVISION "61f15ef8197569e37704fff170d17ff7164f5fae"
#define SYZ_EXECUTOR_USES_FORK_SERVER false
#define SYZ_EXECUTOR_USES_SHMEM false
#define SYZ_PAGE_SIZE 4096
#define SYZ_NUM_PAGES 4096
#define SYZ_DATA_OFFSET 536870912
#define SYZ_SYSCALL_COUNT 106
const call_t syscalls[] = {
	{"foo$any0", 0, (syscall_t)foo},
	{"foo$anyres", 0, (syscall_t)foo},
	{"foo$fmt0", 0, (syscall_t)foo},
	{"foo$fmt1", 0, (syscall_t)foo},
	{"foo$fmt2", 0, (syscall_t)foo},
	{"foo$fmt3", 0, (syscall_t)foo},
	{"foo$fmt4", 0, (syscall_t)foo},
	{"foo$fmt5", 0, (syscall_t)foo},
	{"mutate0", 0, (syscall_t)mutate0},
	{"mutate1", 0, (syscall_t)mutate1},
	{"mutate2", 0, (syscall_t)mutate2},
	{"mutate3", 0, (syscall_t)mutate3},
	{"mutate4", 0, (syscall_t)mutate4},
	{"mutate5", 0, (syscall_t)mutate5},
	{"mutate6", 0, (syscall_t)mutate6},
	{"mutate7", 0, (syscall_t)mutate7},
	{"mutate8", 0, (syscall_t)mutate8},
	{"serialize0", 0, (syscall_t)serialize0},
	{"serialize1", 0, (syscall_t)serialize1},
	{"syz_mmap", 0, (syscall_t)syz_mmap},
	{"syz_test", 0, (syscall_t)syz_test},
	{"syz_test$align0", 0, (syscall_t)syz_test},
	{"syz_test$align1", 0, (syscall_t)syz_test},
	{"syz_test$align2", 0, (syscall_t)syz_test},
	{"syz_test$align3", 0, (syscall_t)syz_test},
	{"syz_test$align4", 0, (syscall_t)syz_test},
	{"syz_test$align5", 0, (syscall_t)syz_test},
	{"syz_test$align6", 0, (syscall_t)syz_test},
	{"syz_test$align7", 0, (syscall_t)syz_test},
	{"syz_test$array0", 0, (syscall_t)syz_test},
	{"syz_test$array1", 0, (syscall_t)syz_test},
	{"syz_test$array2", 0, (syscall_t)syz_test},
	{"syz_test$bf0", 0, (syscall_t)syz_test},
	{"syz_test$bf1", 0, (syscall_t)syz_test},
	{"syz_test$csum_encode", 0, (syscall_t)syz_test},
	{"syz_test$csum_ipv4", 0, (syscall_t)syz_test},
	{"syz_test$csum_ipv4_tcp", 0, (syscall_t)syz_test},
	{"syz_test$csum_ipv4_udp", 0, (syscall_t)syz_test},
	{"syz_test$csum_ipv6_icmp", 0, (syscall_t)syz_test},
	{"syz_test$csum_ipv6_tcp", 0, (syscall_t)syz_test},
	{"syz_test$csum_ipv6_udp", 0, (syscall_t)syz_test},
	{"syz_test$end0", 0, (syscall_t)syz_test},
	{"syz_test$end1", 0, (syscall_t)syz_test},
	{"syz_test$excessive_args1", 0, (syscall_t)syz_test},
	{"syz_test$excessive_args2", 0, (syscall_t)syz_test},
	{"syz_test$excessive_fields1", 0, (syscall_t)syz_test},
	{"syz_test$hint_data", 0, (syscall_t)syz_test},
	{"syz_test$int", 0, (syscall_t)syz_test},
	{"syz_test$length0", 0, (syscall_t)syz_test},
	{"syz_test$length1", 0, (syscall_t)syz_test},
	{"syz_test$length10", 0, (syscall_t)syz_test},
	{"syz_test$length11", 0, (syscall_t)syz_test},
	{"syz_test$length12", 0, (syscall_t)syz_test},
	{"syz_test$length13", 0, (syscall_t)syz_test},
	{"syz_test$length14", 0, (syscall_t)syz_test},
	{"syz_test$length15", 0, (syscall_t)syz_test},
	{"syz_test$length16", 0, (syscall_t)syz_test},
	{"syz_test$length17", 0, (syscall_t)syz_test},
	{"syz_test$length18", 0, (syscall_t)syz_test},
	{"syz_test$length19", 0, (syscall_t)syz_test},
	{"syz_test$length2", 0, (syscall_t)syz_test},
	{"syz_test$length20", 0, (syscall_t)syz_test},
	{"syz_test$length21", 0, (syscall_t)syz_test},
	{"syz_test$length22", 0, (syscall_t)syz_test},
	{"syz_test$length23", 0, (syscall_t)syz_test},
	{"syz_test$length24", 0, (syscall_t)syz_test},
	{"syz_test$length25", 0, (syscall_t)syz_test},
	{"syz_test$length26", 0, (syscall_t)syz_test},
	{"syz_test$length27", 0, (syscall_t)syz_test},
	{"syz_test$length28", 0, (syscall_t)syz_test},
	{"syz_test$length29", 0, (syscall_t)syz_test},
	{"syz_test$length3", 0, (syscall_t)syz_test},
	{"syz_test$length4", 0, (syscall_t)syz_test},
	{"syz_test$length5", 0, (syscall_t)syz_test},
	{"syz_test$length6", 0, (syscall_t)syz_test},
	{"syz_test$length7", 0, (syscall_t)syz_test},
	{"syz_test$length8", 0, (syscall_t)syz_test},
	{"syz_test$length9", 0, (syscall_t)syz_test},
	{"syz_test$missing_resource", 0, (syscall_t)syz_test},
	{"syz_test$missing_struct", 0, (syscall_t)syz_test},
	{"syz_test$opt0", 0, (syscall_t)syz_test},
	{"syz_test$opt1", 0, (syscall_t)syz_test},
	{"syz_test$opt2", 0, (syscall_t)syz_test},
	{"syz_test$opt3", 0, (syscall_t)syz_test},
	{"syz_test$recur0", 0, (syscall_t)syz_test},
	{"syz_test$recur1", 0, (syscall_t)syz_test},
	{"syz_test$recur2", 0, (syscall_t)syz_test},
	{"syz_test$regression0", 0, (syscall_t)syz_test},
	{"syz_test$regression1", 0, (syscall_t)syz_test},
	{"syz_test$regression2", 0, (syscall_t)syz_test},
	{"syz_test$res0", 0, (syscall_t)syz_test},
	{"syz_test$res1", 0, (syscall_t)syz_test},
	{"syz_test$struct", 0, (syscall_t)syz_test},
	{"syz_test$syz_union3", 0, (syscall_t)syz_test},
	{"syz_test$syz_union4", 0, (syscall_t)syz_test},
	{"syz_test$text_x86_16", 0, (syscall_t)syz_test},
	{"syz_test$text_x86_32", 0, (syscall_t)syz_test},
	{"syz_test$text_x86_64", 0, (syscall_t)syz_test},
	{"syz_test$text_x86_real", 0, (syscall_t)syz_test},
	{"syz_test$type_confusion1", 0, (syscall_t)syz_test},
	{"syz_test$union0", 0, (syscall_t)syz_test},
	{"syz_test$union1", 0, (syscall_t)syz_test},
	{"syz_test$union2", 0, (syscall_t)syz_test},
	{"syz_test$vma0", 0, (syscall_t)syz_test},
	{"unsupported$0", 0, (syscall_t)unsupported},
	{"unsupported$1", 0, (syscall_t)unsupported},

};
#endif
