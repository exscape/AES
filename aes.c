#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h> /* memcpy */

#include "tables.h"
#include "debug.h" 
/*
void RotWord(unsigned char *s) {
	// Rotates the first 4 bytes in s in this manner:
	// In : 1d 2c 3a 4f
	// Out: 2c 3a 4f 1d

	uint64_t *d = (uint64_t *)s; 
	asm("rorl $8, %0" : "=r"(*d) : "r"(*d));
}
*/
void AddRoundKey(unsigned char *state, const unsigned char *keys) {
	// The caller is responsible for specifying the offset in keys!
	for (int i=0; i<16; i++) {
		state[i] ^= keys[i];
	}
}

void SubBytes(unsigned char *state) {
	for (int i=0; i<16; i++) {
		state[i] = sbox [ state[i] ];
	}
}

void aes_encrypt(const unsigned char *plaintext, unsigned char *state, const unsigned char *keys) {
	memcpy(state, plaintext, 16);

	AddRoundKey(state, keys /*+ 0 */);

}
