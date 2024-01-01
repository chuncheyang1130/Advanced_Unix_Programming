#include <stdio.h>

typedef int (*printf_ptr_t)(const char *format, ...);

void solver(printf_ptr_t fptr) {
	char msg[16] = "hello, world!";

    fptr("%016lx\n", *(unsigned long*)(&msg[0x18]));
    fptr("%016lx\n", *(unsigned long*)(&msg[0x20]));
    fptr("%016lx\n", *(unsigned long*)(&msg[0x28]) + 0xab);
	
}

int main() {
	char fmt[16] = "** main = %p\n";
	printf(fmt, main);
	solver(printf);
	return 0;
}