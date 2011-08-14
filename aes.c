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

void InvSubBytes(unsigned char *state) {
	for (int i=0; i<16; i++) {
		state[i] = invsbox [ state[i] ];
	}
}

void ShiftWord(uint32_t *d, uint8_t steps) {
	steps *= 8; // bytes -> bits

	asm("roll %1, %0"
	: "=g"(*d)
	: "cI"(steps), "0"(*d));
}

void ShiftRows(unsigned char *state) {
	uint32_t cols[4];

	for (int i=1; i<=3; i++) {
		cols[i] = (state[4*0 + i] << 24) | (state[4*1 + i] << 16) | (state[4*2 + i] << 8) | (state[4*3 + i]);
		ShiftWord(&cols[i], i);

		for (int j = 0; j<4; j++) {
			state[4*j + i] = ((cols[i] >> (3-j) * 8) & 0xff);
		}
	}
}

void InvShiftRows(unsigned char *state) {
}

void InvMixColumns(unsigned char *state) {
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

/*		printf("round[ 0].input    ");
		for (int i=0; i<16; i++) {
			printf("%02x", state[i]);
		}
		printf("\n");

		printf("round[ 0].k_sch    ");
		for (int i=0; i<16; i++) {
			printf("%02x", keys[i]);
		}
		printf("\n");
*/
	// Initial round
	AddRoundKey(state, keys /*+ 0 */);

	// Rounds
	for (int round = 1; round </*= eller inte? */ 10; round++) { // TODO FIXME: bekräfta att det är rätt antal
/*
		printf("round[%2d].start    ", round);
		for (int i=0; i<16; i++) {
			printf("%02x", state[i]);
		}
		printf("\n");

		
*/		
		SubBytes(state);
/*		printf("round[%2d].s_box    ", round);
		for (int i=0; i<16; i++) {
			printf("%02x", state[i]);
		}
		printf("\n");


*/
		ShiftRows(state);
/*		printf("round[%2d].s_row    ", round);
		for (int i=0; i<16; i++) {
			printf("%02x", state[i]);
		}
		printf("\n");

*/
		MixColumns(state);
/*		printf("round[%2d].m_col    ", round);
		for (int i=0; i<16; i++) {
			printf("%02x", state[i]);
		}
		printf("\n");
*/
		AddRoundKey(state, keys + (round * 16));
	}

	// Final round	
	SubBytes(state);
	ShiftRows(state);
	AddRoundKey(state, keys + 10*16);
}

void aes_decrypt(const unsigned char *ciphertext, unsigned char *state, const unsigned char *keys) {

	memcpy(state, ciphertext, 16);

	// Initial round
	AddRoundKey(state, keys + 10*16);

	// Rounds
	for (int round = 9 /* Nr - 1 */; round >=/* >= eller inte? */ 1; round--) { // TODO FIXME: bekräfta att det är rätt antal
		InvShiftRows(state);
		InvSubBytes(state);
		AddRoundKey(state, keys + (round * 16));
		InvMixColumns(state);
	}

	// Final round	
	InvShiftRows(state);
	InvSubBytes(state);
	AddRoundKey(state, keys + 0);
}
