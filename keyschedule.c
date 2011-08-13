#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h> /* memcpy */
#include "tables.h"
#include "debug.h" 

void RotWord(unsigned char *s) {
	// Rotates the first 4 bytes in s like this:
	// In : 1d 2c 3a 4f
	// Out: 2c 3a 4f 1d

	uint64_t *d = (uint64_t *)s; 
	asm("rorl $8, %0" : "=r"(*d) : "r"(*d));
}

void key_schedule_core(unsigned char *word, int i/*teration*/) {
	// Rotate
	RotWord(word);

	// Apply S-Box to each of the bytes
	for (int j=0; j<4; j++) {
		word[j] = sbox[ word[j] ];
	}

	// XOR with Rcon value
	word[0] ^= Rcon[i];
}

int aes_expand_key(const unsigned char *in_key, unsigned char *out_keys) {
	print_hex(in_key, 16);

#define n 16
#define b 176

	memcpy(out_keys, in_key, n); // The first n bytes of the expanded key are simply the encryption key

	int rcon_int = 1;
	int bytes_done = 16;

	while (bytes_done < b) {
		unsigned char tmp[4];

		// Assign the value of the previous four bytes in the expanded key to tmp
		memcpy(tmp, out_keys + bytes_done - 4, 4);

		key_schedule_core(tmp, rcon_int);

		rcon_int++;

		// XOR tmp with the 4-byte block n bytes before the new expanded key... (1)
		for (int i=0; i<4; i++) {
			tmp[i] ^= out_keys[bytes_done - n + i];
		}

		// ... this becomes the next 4 bytes in the expanded key. (2)
		memcpy(out_keys + bytes_done, tmp, 4);
		bytes_done += 4;

		// We then do {the following} three times to create the next 12 bytes of expanded key:
		for (int i=0; i<3; i++) {
			memcpy(tmp, out_keys + bytes_done - 4, 4); // TODO: kanske fel matte, vet inte när bytes_done ska ökas! Kanske fel offset alltså!

			// XOR tmp with the 4-byte block n bytes before the new expanded key... (2) 
			for (int j=0; j<4; j++) {
				tmp[j] ^= out_keys[bytes_done - n + j];
			}

			// ... this becomes the next 4 bytes in the expanded key. (2)
			memcpy(out_keys + bytes_done, tmp, 4);
			bytes_done += 4;
		} // 12-byte-key-loop

	} // main loop

printf("DEBUG: n = %d, b = %d, bytes_done = %d\n", n, b, bytes_done);




















	return 0;
}

