#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h> /* memcpy */

#include "tables.h"
#include "debug.h" 

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

void ShiftRow(uint32_t *word, uint8_t steps) {
    steps *= 8; // bytes -> bits

    asm("rorl %1, %0"
            : "=g"(*word)
            : "cI"(steps), "0"(*word));
}

void ShiftRows(unsigned char *state) {
    uint32_t *words[4];
    for (int i=0; i < 4; i++) {
        words[i] = (uint32_t *) (state + 4*i);
    }

    // words[0] should be left untouched
    ShiftRow(words[1], 1);
    ShiftRow(words[2], 2);
    ShiftRow(words[3], 3);
}

void MixColumns(unsigned char *state) {
}

void aes_encrypt(const unsigned char *plaintext, unsigned char *state, const unsigned char *keys) {
	memcpy(state, plaintext, 16);

	// Initial round
	AddRoundKey(state, keys /*+ 0 */);

	// Rounds
	for (int round = 1; round </*= eller inte? */ 9; round++) { // TODO FIXME: bekräfta att det är rätt antal
		SubBytes(state);
		ShiftRows(state);
		MixColumns(state);
		AddRoundKey(state, keys + (round * 16));
	}

	// Final round	
	SubBytes(state);
	ShiftRows(state);
	AddRoundKey(state, keys + 10*16);
}
