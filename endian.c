#include <stdio.h>

int main() {
	unsigned int d = 0x12345678;
	char *a = (char *)&d;

	printf("%d: %x %x %x %x\n", d, *a, *(a+1), *(a+2), *(a+3) );


	d = __builtin_bswap32(d);
	asm("roll $0x8, %1;"
			:"=r"(d) // out
			:"r"(d)  // in
			);

	printf("%d: %x %x %x %x\n", d, *a, *(a+1), *(a+2), *(a+3) );

	return 0;
}
