#include <stdio.h>

typedef int (*printf_ptr_t)(const char *format, ...);

void solver(printf_ptr_t fptr) {
	char msg[16] = "Hello World!";
    long canary = *((unsigned long *)&msg[0x18]);
    long rbp = *((unsigned long *)&msg[0x20]);
    long return_addr = *((unsigned long *)&msg[0x28]);
    return_addr += 0xab;
    fptr("canary      : %016lx\n", canary);
    fptr("solver_rbp  : %016lx\n", rbp);
    fptr("return_addr : %016lx\n", return_addr);
    // long rbp;

    // for(int i = 0x18; i < 0x100; i+=8){     
    //     fptr("%016lx", *((unsigned long *)&msg[i]));
    //     fptr("\n");

    // }
    // long magic_addr = rbp - 0x60;
    // fptr("%016lx", *((unsigned long *)&msg[magic_addr]));
    // fptr("after!\n");
    // long *change =  (unsigned long *)&msg[0x18];
    // *change = canary;
    // int j = 0;
	
}

int main() {
	char fmt[16] = "** main = %p\n";
	printf(fmt, main);
	solver(printf);
	return 0;
}