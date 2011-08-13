#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>

// For debugging
void print_hex(const unsigned char *s, size_t len) {

	// Only support strings of length 16, 2*16, ...
	assert (len % 16 == 0);

	printf("\n");

	for (size_t row = 0; row < len/16; row++) {
		for (size_t col = 0; col < 16; col++) {
			printf("%.2x ", s[(row+1)*col]);
		}
		printf("\n");
	}
}
