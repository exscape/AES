#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h> /* memcpy */
#ifndef _TABLES_H
#include "tables.h"
#endif

#ifndef _DEBUG_H
#include "debug.h" 
#endif

void RotWord(unsigned char *s) {
	// Rotates the first 4 bytes in s in this manner:
	// In : 1d 2c 3a 4f
	// Out: 2c 3a 4f 1d

	uint32_t *d = (uint32_t *)s; 
	asm("rorl $8, %0" : "=g"(*d) : "0"(*d));
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
	#define n 16
	memcpy(out_keys, in_key, n); // The first n bytes of the expanded key are simply the encryption key

	int rcon_int = 1;
	int bytes_done = 16;

	while (bytes_done < 11*16) { // 11 keys, 16 bytes each
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
			// XOR tmp with the 4-byte block n bytes before the new expanded key... (1) 
			memcpy(tmp, out_keys + bytes_done - 4, 4);
			for (int j=0; j<4; j++) {
				tmp[j] ^= out_keys[bytes_done - n + j];
			}

			// ... this becomes the next 4 bytes in the expanded key. (2)
			memcpy(out_keys + bytes_done, tmp, 4);
			bytes_done += 4;
		} // 12-byte-key-loop

	} // main loop

	return 0;
}

