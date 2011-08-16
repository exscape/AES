#include <stdio.h>
#include <stdlib.h> /* exit */
#include <string.h> /* memcmp */
#include <assert.h>
#include "keyschedule.h"
#include "debug.h"
#include "aes.h"

int main() {
	uint64_t text[2] = {0};
	unsigned char *plaintext_ptr = (unsigned char *)text;
	const unsigned char key[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
	unsigned char expanded_key[176] = {0};
	unsigned char ciphertext[16] = {0};

	aes_expand_key(key, expanded_key);

#define NUM_LOOPS 10000000
	for (int i=0; i < NUM_LOOPS; i++) {
		text[1]++;
		aes_encrypt_aesni(plaintext_ptr, ciphertext, expanded_key);
//		print_hex(ciphertext, 16);
	}

	return 0;
}
