#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h> /* memcpy */
#include <stdbool.h>

#include <emmintrin.h>

#include "tables.h"
#include "debug.h" 
#include "aes.h"

#define AESNI 1

void AddRoundKey(unsigned char *state, const unsigned char *keys) {
	// XOR the state with the round key
	// The caller is responsible for specifying the offset in keys!
	// We simply process the first 16 bytes.

	__m128i state_val = _mm_load_si128((__m128i const *)state);
	__m128i key_val = _mm_load_si128((__m128i const *)keys);
	__m128i result    = _mm_xor_si128(state_val, key_val);

	_mm_storeu_si128((__m128i *)state, result);
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

void ShiftRows(unsigned char *state, bool inverse  /* is this InvShiftRows? */) {
	uint32_t cols[4];

	for (int i=1; i<=3; i++) {
		// Since we map bytes to different places than the AES spec, we can't just shift "rows";
		// we have to shift the first byte in each row, and thus shift columns upwards/downwards
		// rather than shift rows left/right.
		// This extracts the correct bytes into a word-sized integer.
		cols[i] = (state[4*0 + i] << 24) | (state[4*1 + i] << 16) | (state[4*2 + i] << 8) | (state[4*3 + i]);

		//
		// Move the bits around the correct amount
		//
		uint8_t steps = 8*i;

		if (inverse == true) {
			// InvShiftRows()
			 asm("rorl %1, %0"
			: "=g"(cols[i])
			: "cI"(steps), "0"(cols[i]));
		}
		else {
			// ShiftRows()
			asm("roll %1, %0"
			: "=g"(cols[i])
			: "cI"(steps), "0"(cols[i]));
		}

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

void MixColumns(unsigned char *state) {
	// Thanks to the fact that we map the bytes differently than the AES spec, this function (and its inverse)
	// becomes quite a bit simpler (at the cost of making ShiftRows more complex).
	// This function does matrix multiplication in GF(2^8)
	// using precalculated tables for Galois Field multiplication.

	for (int col=0; col<4; col++) {
		unsigned char r[4];

		// Make a copy of the current column to manipulate
		unsigned char a[4];
		memcpy(a, state + col*4, 4);

		// Perform the matrix multiplication
		r[0] = gmul2[a[0]] ^ gmul3[a[1]] ^ a[2] ^ a[3];
		r[1] = a[0] ^ gmul2[a[1]] ^ gmul3[a[2]] ^ a[3];
		r[2] = a[0] ^ a[1] ^ gmul2[a[2]] ^ gmul3[a[3]];
		r[3] = gmul3[a[0]] ^ a[1] ^ a[2] ^ gmul2[a[3]];

		// Copy the answer back to the state
		memcpy(state + col*4, r, 4);
	}
}

void InvMixColumns(unsigned char *state) {
	// This function is virtually identical to its non-inverse counterpart,
	// the only difference is that the matrix used for multiplication is different.

/*
	__m128i state_val = _mm_load_si128((__m128i const *)state);
	__m128i result;

	asm("movdqa %1, %%xmm0;"
		"aesimc %%xmm0, %0;"
		: "=x"(result)
		: "x"(state_val)
		: "%xmm0");

	_mm_storeu_si128((__m128i *)state, result);
*/
	for (int col=0; col<4; col++) {
		unsigned char r[4];

		// Make a copy of the current colun to manipulate
		unsigned char a[4];
		memcpy(a, state + col*4, 4);

		// Perform the matrix multiplication
		r[0] = gmul14[a[0]] ^ gmul11[a[1]] ^ gmul13[a[2]] ^ gmul9[a[3]];
		r[1] = gmul9[a[0]] ^ gmul14[a[1]] ^ gmul11[a[2]] ^ gmul13[a[3]];
		r[2] = gmul13[a[0]] ^ gmul9[a[1]] ^ gmul14[a[2]] ^ gmul11[a[3]];
		r[3] = gmul11[a[0]] ^ gmul13[a[1]] ^ gmul9[a[2]] ^ gmul14[a[3]];

		// Copy the answer back to the state
		memcpy(state + col*4, r, 4);
	}
}

void aes_encrypt_aesni(const unsigned char *plaintext, unsigned char *state, const unsigned char *keys) {
	asm __volatile__ (
			"movq %[keys], %%r15;"         // keep the pointer for easy pointer arithmetic
			"movdqa %[plaintext], %%xmm0;" // load plaintext
			"pxor (%%r15), %%xmm0;"        // perform whitening

			"mov $1, %%ecx;"          // initialize round counter
			"_encrypt_roundloop:"             
			"addq $16, %%r15;"        // move the pointer to the next round key
			"aesenc (%%r15), %%xmm0;" // perform AES round
			"inc %%ecx;"
			"cmp $10, %%ecx;"
			"jl _encrypt_roundloop;" // for (i=1; i<10; i++)

			"addq $16, %%r15;"            // move the pointer one last time
			"aesenclast (%%r15), %%xmm0;" // perform the final AES round
			"movdqa %%xmm0, %[state];"    // move the state back to the memory address

			:[state] "=m"(*state)
			:[plaintext] "m"(*plaintext), [keys] "m"(keys)
			:"%xmm0", "memory", "%ecx", "cc", "%r15"
			);
}

void aes_encrypt_c(const unsigned char *plaintext, unsigned char *state, const unsigned char *keys) {

	// Initialize the state
	memcpy(state, plaintext, 16);

	// Initial round
	AddRoundKey(state, keys /*+ 0 */);

	// Rounds
	for (int round = 1; round < 10; round++) {
		SubBytes(state);
		ShiftRows(state, 0 /* not inverse */);
		MixColumns(state);
		AddRoundKey(state, keys + (round * 16));
	}

	// Final round	
	SubBytes(state);
	ShiftRows(state, 0 /* not inverse */);
	AddRoundKey(state, keys + 10*16);
}

void aes_decrypt_aesni(const unsigned char *ciphertext, unsigned char *state, const unsigned char *keys) {
	   asm __volatile__ (
            "movq %[keys], %%r15;"         // keep the pointer for easy pointer arithmetic
			"addq $160, %%r15;"            // move the pointer to keys + 10*16
            "movdqa %[plaintext], %%xmm0;" // load plaintext
            "pxor (%%r15), %%xmm0;"        // perform whitening

            "mov $9, %%ecx;"          // initialize round counter
            "_decrypt_roundloop:"
            "subq $16, %%r15;"        // move the pointer to the "next" round key
            "aesdec (%%r15), %%xmm0;" // perform AES round
            "dec %%ecx;"
            "cmp $1, %%ecx;"
            "jge _decrypt_roundloop;" // for (i=9; i >= 1; i--)

            "subq $16, %%r15;"            // move the pointer one last time
            "aesdeclast (%%r15), %%xmm0;" // perform the final AES round
            "movdqa %%xmm0, %[state];"    // move the state back to the memory address

            :[state] "=m"(*state)
            :[plaintext] "m"(*ciphertext), [keys] "m"(keys)
            :"%xmm0", "memory", "%ecx", "cc", "%r15"
            );
}

void aes_decrypt_c(const unsigned char *ciphertext, unsigned char *state, const unsigned char *keys) {
	//
	// This function implement the AES Equivalent Inverse cipher described in the AES specification.
	//

	// Initialize the state
	memcpy(state, ciphertext, 16);

	// Initial round
	AddRoundKey(state, keys + 10*16);

	// Rounds
	for (int round = 9 /* Nr - 1 */; round >= 1; round--) {
		InvSubBytes(state);
		InvShiftRows(state);
		InvMixColumns(state);
		AddRoundKey(state, keys + (round * 16));
	}

	// Final round	
	InvSubBytes(state);
	InvShiftRows(state);
	AddRoundKey(state, keys + 0);
}
