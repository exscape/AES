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

    asm(//"bswap %0;"
		"rorl %1, %0"
            : "=g"(*word)
            : "cI"(steps), "0"(*word));
}

void ShiftRows(unsigned char *state) {
/*	
    uint32_t *words[4];
    for (int i=0; i < 4; i++) {
        words[i] = (uint32_t *) (state + 4*i);
    }

    // words[0] should be left untouched
    ShiftRow(words[1], 1);
    ShiftRow(words[2], 2);
    ShiftRow(words[3], 3);
*/

	register uint8_t i, j;
    i = state[1]; state[1] = state[5]; state[5] = state[9]; state[9] = state[13]; state[13] = i;
    i = state[10]; state[10] = state[2]; state[2] = i;
    j = state[3]; state[3] = state[15]; state[15] = state[11]; state[11] = state[7]; state[7] = j;
    j = state[14]; state[14] = state[6]; state[6]  = j;
	
}

void MixColumn(unsigned char *part_state) {
	unsigned char a[4];
	unsigned char r[4];
	memcpy(a, part_state, 4);

	r[0] = gmul2[a[0]] ^ gmul3[a[1]] ^ a[2] ^ a[3];
	r[1] = a[0] ^ gmul2[a[1]] ^ gmul3[a[2]] ^ a[3];
	r[2] = a[0] ^ a[1] ^ gmul2[a[2]] ^ gmul3[a[3]];
	r[3] = gmul3[a[0]] ^ a[1] ^ a[2] ^ gmul2[a[3]];

	memcpy(part_state, r, 4);
}

void MixColumns(unsigned char *state) {
	for (int i=0; i<4; i++) {
		MixColumn(state + i*4);
	}
}

void aes_encrypt(const unsigned char *plaintext, unsigned char *state, const unsigned char *keys) {
	memcpy(state, plaintext, 16);

		printf("round[ 0].input    ");
		for (int i=0; i<16; i++) {
			printf("%02x", state[i]);
		}
		printf("\n");

		printf("round[ 0].k_sch    ");
		for (int i=0; i<16; i++) {
			printf("%02x", keys[i]);
		}
		printf("\n");

	// Initial round
	AddRoundKey(state, keys /*+ 0 */);

	// Rounds
	for (int round = 1; round </*= eller inte? */ 10; round++) { // TODO FIXME: bekräfta att det är rätt antal
		printf("round[%2d].start    ", round);
		for (int i=0; i<16; i++) {
			printf("%02x", state[i]);
		}
		printf("\n");

		
		
		SubBytes(state);
		printf("round[%2d].s_box    ", round);
		for (int i=0; i<16; i++) {
			printf("%02x", state[i]);
		}
		printf("\n");



		ShiftRows(state);
		printf("round[%2d].s_row    ", round);
		for (int i=0; i<16; i++) {
			printf("%02x", state[i]);
		}
		printf("\n");


		MixColumns(state);
		printf("round[%2d].m_col    ", round);
		for (int i=0; i<16; i++) {
			printf("%02x", state[i]);
		}
		printf("\n");

		AddRoundKey(state, keys + (round * 16));
	}

	// Final round	
	SubBytes(state);
	ShiftRows(state);
	AddRoundKey(state, keys + 10*16);
}
