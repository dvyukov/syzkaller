// gcc covertest/test.c covertest/dir1/file11.c covertest/dir1/file12.c covertest/dir2/file21.c covertest/dir2/file22.c -g -fsanitize-coverage=trace-pc -o vmlinux
// go install ./tools/syz-cover && syz-cover -kernel_src=covertest -kernel_obj=. covertest/cover
// go install ./tools/syz-cover && syz-cover -kernel_src=/home/dvyukov/src/linux -kernel_obj=/home/dvyukov/src/linux rawcover
// build on f2c7c76c5d0a443053e94adb9f0918fa2fb85c3a
#include <stdio.h>

void __sanitizer_cov_trace_pc() {}

int main() {
	printf("aaa");
}
