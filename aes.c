#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h> /* memcpy */

#include "tables.h"
#include "debug.h" 

#define VDEBUG 1 /* verbose debug; prints the state during lots of steps */

void AddRoundKey(unsigned char *state, const unsigned char *keys) {
	// The caller is responsible for specifying the offset in keys!
	// We simply process the first 16 bytes.
	for (int i=0; i<16; i++) {
		state[i] ^= keys[i];
	}
}

void SubBytes(unsigned char *state) {
	// Replace all bytes in the state with corresponding values from the S-Box
	for (int i=0; i<16; i++) {
		state[i] = sbox [ state[i] ];
	}
}

void InvSubBytes(unsigned char *state) {
	// Replace all bytes in the state with corresponding values from the inverse S-Box
	for (int i=0; i<16; i++) {
		state[i] = invsbox [ state[i] ];
	}
}

void ShiftRows(unsigned char *state) {
	uint32_t cols[4];

	for (int i=1; i<=3; i++) {
		// Since we map bytes to different places than the AES spec, we can't just shift "rows";
		// we have to shift the first byte in each row, and thus shift columns upwards/downwards
		// rather than shift rows left/right.
		// This extracts the correct bytes into a word-sized integer.
		cols[i] = (state[4*0 + i] << 24) | (state[4*1 + i] << 16) | (state[4*2 + i] << 8) | (state[4*3 + i]);

		// Move the bits around the correct amount
		uint8_t steps = 8*i;
		asm("roll %1, %0"
		: "=g"(cols[i])
		: "cI"(steps), "0"(cols[i]));

		// Extract the bits back from the integer and place it back into the state
		// This loop isn't as scary as it looks.
		// (3-j) * 8 is used to create the inverse of the bitshifts in the above loop (24, 16, 8 and 0 in that order)
		// We then AND the bits, which are now in the 8 least significats bits, with 0xff (1111 1111) to extract the value,
		// then store it back where we fetched it from the state.
		for (int j = 0; j<4; j++) {
			state[4*j + i] = ((cols[i] >> (3-j) * 8) & 0xff);
		}
	}
}

void InvShiftRows(unsigned char *state) {
	//
	// The logic for this function is virtually identical to ShiftRows, so see that for an explanation.
	// The only difference is that the rotation is reversed.
	//
	uint32_t cols[4];

	for (int i=1; i<=3; i++) {
		cols[i] = (state[4*0 + i] << 24) | (state[4*1 + i] << 16) | (state[4*2 + i] << 8) | (state[4*3 + i]);

		uint8_t steps = 8*i;
		asm("rorl %1, %0"
		: "=g"(cols[i])
		: "cI"(steps), "0"(cols[i]));

		for (int j = 0; j<4; j++) {
			state[4*j + i] = ((cols[i] >> (3-j) * 8) & 0xff);
		}
	}
}

void MixColumn(unsigned char *part_state) {
	//
	// TODO: KOMMENTERA
	//
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

void InvMixColumn(unsigned char *part_state) {
	unsigned char a[4];
	unsigned char r[4];
	memcpy(a, part_state, 4);

	r[0] = gmul14[a[0]] ^ gmul11[a[1]] ^ gmul13[a[2]] ^ gmul9[a[3]];
	r[1] = gmul9[a[0]] ^ gmul14[a[1]] ^ gmul11[a[2]] ^ gmul13[a[3]];
	r[2] = gmul13[a[0]] ^ gmul9[a[1]] ^ gmul14[a[2]] ^ gmul11[a[3]];
	r[3] = gmul11[a[0]] ^ gmul13[a[1]] ^ gmul9[a[2]] ^ gmul14[a[3]];

	memcpy(part_state, r, 4);
}

void InvMixColumns(unsigned char *state) {
	for (int i=0; i<4; i++) {
		InvMixColumn(state + i*4);
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
