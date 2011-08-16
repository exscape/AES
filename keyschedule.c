#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h> /* memcpy */
#include "tables.h"
#include "debug.h" 

#include "aes.h" /* InvMixColumns */
#include "misc.h" /* test_aesni_support */

void RotWord(unsigned char *s) {
	// Rotates the first 4 bytes in s in this manner:
	// In : 1d 2c 3a 4f
	// Out: 2c 3a 4f 1d

	uint32_t *d = (uint32_t *)s; 
	asm("rorl $8, %0" : "=g"(*d) : "0"(*d));
}

void key_schedule_core(unsigned char *word, int i/*teration*/) {
	// This function appears to exist in newer Intel CPUs as AESKEYGENASSIST.
	// However, that instruction requires the RCON value as an immediate value,
	// which makes a loop impossible. Since this isn't really performance critical
	// (unlike aes_{en,de}crypt, this isn't called over and over), I'll just ignore that.
	// My laptop can perform 2 million key expansions per second, and since only ONE is needed per key (aka per session)...

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
	//
	// Creates the round keys needed for encryption and decryption.
	// in_key is the 16-byte key
	// out_key needs to be a 176-byte char array; 11 16-byte keys will be stored in sequential order.
	//
	#define n 16
	memcpy(out_keys, in_key, n); // The first n bytes of the expanded key are simply the encryption key

	int rcon_int = 1;
	int bytes_done = 16;

	while (bytes_done < 11*16) { // 11 keys, 16 bytes each
		unsigned char tmp[4];

		// Assign the value of the previous four bytes in the expanded key to tmp
		memcpy(tmp, out_keys + bytes_done - 4, 4);

		// Perform the key schedule core, and increase the iteration value
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

void aes_prepare_decryption_keys(unsigned char *keys) {
	// This function is called after aes_expand_key, to prepare the keys for decryption
	// DO NOT call this function on the keys prior to encryption, or the encryption will fail!
	bool aesni = test_aesni_support();

	// Use the AESIMC instruction if CPU support is available.
	if (aesni) {
		asm __volatile__ (
		"movq %[keys], %%r15;"    // save the keys pointer for easy pointer arithmetic
		"movl $1, %%ecx;"         // set loop counter (int round=1)
		"_loop:"                  
		"addq $16, %%r15;"        // move pointer to keys + (round*16)
		"aesimc (%%r15), %%xmm0;" // perform InverseMixColumns
		"movdqa %%xmm0, (%%r15);" // save result back to memory
		"inc %%ecx;"
		"cmp $9, %%ecx;"          
		"jle _loop;"              // loop while round <= 9
		:[keys] "=m"(keys)
		:
		: "%r15", "%ecx", "%xmm0", "cc", "memory"
		);
	}
	else {
		for (int round=1; round <= 9; round++) {
			InvMixColumns(keys + (round * 16));
		}
	}
}
