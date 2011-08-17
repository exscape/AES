#include <stdio.h>
#include <stdlib.h> /* exit */
#include <string.h> /* memcmp */
#include <assert.h>
#include <sys/stat.h>
#include <errno.h>

#include "keyschedule.h"
#include "aes.h"
#include "debug.h"
#include "misc.h" /* test_aesni_support */

/*
 * The file structure used by this program is quite simple:
 * [nonce, 8 bytes]
 * [ciphertext block #1], 16 bytes
 * [ciphertext block #2], 16 bytes
 * [ciphertext block #n], 16 bytes
 * [padding byte, 1 byte]
 * The value of the last byte (0 - 15) indicates how many bytes of the last ciphertext block are padding bytes
 * (and should be discarded after decryption).
 *
 * The counter starts at 1 and increases by one for each block that is read.
 */

off_t file_size(const char *path) {
	// Returns an integer-type variable containing the file size, in bytes.
	struct stat st;
	if (stat(path, &st) != 0) {
		perror(path);
		exit(1);
	}

	return (st.st_size);
}

uint64_t get_nonce(void) {
	// Fetches 64 bits of pseudorandom data from /dev/urandom and
	// returns it as a 64-bit integer.

	uint64_t nonce;
	FILE *urandom = fopen("/dev/urandom", "r");
	if (!urandom) {
		perror(NULL);
		exit(1);
	}
	if (fread(&nonce, 8, 1, urandom) != 1) {
		perror(NULL);
		exit(1);
	}

	return nonce;
}

void encrypt_file(const char *inpath, const char *outpath, const unsigned char *key) {
	// Create a pointer to the correct function to use for this CPU
	void (*aes_encrypt)(const unsigned char *, unsigned char *, const unsigned char *);
	if (test_aesni_support()) {
		aes_encrypt = aes_encrypt_aesni;
	}
	else {
		aes_encrypt = aes_encrypt_c;
	}

	// Expand the keys; AES-128 uses 11 keys (11*16 = 176 bytes) for encryption/decryption, one per round plus one before the rounds
	unsigned char expanded_keys[176] = {0};
	aes_expand_key(key, expanded_keys);

	// Sanity check: don't try to encrypt nothingness (or weird errors stemming from the signed type)
	off_t size = file_size(inpath);
	if (size <= 0) {
		fprintf(stderr, "Cannot encrypt a file of size zero!\n");
		exit(1);
	}

	// Since we can only encrypt full 16-byte blocks, we need to add padding to the last block
	// if its length isn't divisble by 16. This calculates how many padding bytes are needed
	// (in the range 0 - 15).
	uint8_t padding = 16 - (size % 16);
	if (padding == 16)
		padding = 0;

	FILE *infile = fopen(inpath, "r");
	if (!infile) {
		perror(inpath);
		exit(1);
	}

	FILE *outfile = fopen(outpath, "w");
	if (!outfile) {
		perror(outpath);
		exit(1);
	}

	// Bytes read in total
	off_t bytes_read = 0;
	// How many bytes we actually read this loop (0-16)
	size_t actual_read = 0;

	// The destination for fread; the plaintext
	unsigned char block[16] = {0};

	// Where we store the ciphertext
	unsigned char enc_block[16] = {0};

	// The counter (since this is CTR mode)
	// The layout is simple: the first 64 bits is the nonce, and the second 64 bits is a simple counter.
	// This should work for a maximum 2^64-1 blocks, which is 256 exabytes, so there's no need for a 128-bit counter.
	uint64_t counter[2];
	counter[0] = get_nonce();
	counter[1] = 1;

	// Prepend the nonce to the output file; it's needed for decryption, and doesn't need to be a secret
	fwrite((void *)&(counter[0]), 8, 1, outfile);

	// The main loop.
	// We loop until we've read the entire file, of course.
	while (bytes_read < size) {
		// Read one block
		actual_read = fread(block, 1, 16, infile);
		bytes_read += actual_read;

		// This isn't pretty, but it works.
		// If the amount of bytes read isn't 16, one of two things happened:
		// 1) A read error occured, because we've calculated how many bytes should be read in 16-byte blocks
		// 2) We simply read the last block, and need to add padding to this last, incomplete block.
		if (actual_read != 16) {
			if (bytes_read - actual_read /* total bytes read *BEFORE* the last fread() (the one that WASN'T 16 bytes) */
					!=
					size - (16-padding)) { /* number of bytes that SHOULD be read in 16-byte blocks */
				fprintf(stderr, "*** Some sort of read error occured.\n");
				exit(1);
			}
			else {
				// This is the last block, and it's not 16 bytes; add padding
				memset(block + (16-padding), 'A', padding);
			}
		}

		aes_encrypt((unsigned char *)counter, enc_block, expanded_keys);
		counter[1]++;

		for (int i=0; i<16; i++) {
			enc_block[i] ^= block[i];
		}

		if (fwrite(enc_block, 1, 16, outfile) != 16) {
			fprintf(stderr, "*** Write error!\n");
			exit(1);
		}
	}

	fclose(infile);
	fputc(padding, outfile); // write a final byte, whose value is the amount of padding used
	fclose(outfile);
}

void decrypt_file(const char *inpath, const char *outpath, const unsigned char *key) {
	// Create a pointer to the correct function to use for this CPU
	// [sic] on the aes_ENcrypt - CTR mode uses encryption for both ways (thanks to the fact that a XOR b XOR b == a)
	void (*aes_encrypt)(const unsigned char *, unsigned char *, const unsigned char *);
	if (test_aesni_support()) {
		aes_encrypt = aes_encrypt_aesni;
	}
	else {
		aes_encrypt = aes_encrypt_c;
	}

	unsigned char expanded_keys[176] = {0};
	aes_expand_key(key, expanded_keys);
	// Note to self: no need to call aes_prepare_decryption_keys since we use aes_ENcrypt here

	off_t size = file_size(inpath);
	if (size < 25) {
		fprintf(stderr, "Invalid file; all files encrypted with this program are 25 bytes or longer.\n");
		exit(1);
	}
	if (! ( (size-1-8) % 16 == 0)) { // size - padding byte - nonce must be divisible by the block length
		fprintf(stderr, "Invalid file size; file is either not encrypted by this program, or corrupt.\n");
		exit(1);
	}

	FILE *infile = fopen(inpath, "r");
	if (!infile) {
		perror(inpath);
		exit(1);
	}

	FILE *outfile = fopen(outpath, "w");
	if (!outfile) {
		perror(outpath);
		exit(1);
	}

	uint8_t padding;
	fseek(infile, -1, SEEK_END); // seek to the last byte
	fread(&padding, 1, 1, infile); // read the padding byte
	fseek(infile, 0, 0); // seek to the beginning of the file

	off_t bytes_read = 0;
	unsigned char block[16] = {0};
	unsigned char dec_block[16] = {0};
	size_t actual_read = 0;

	uint64_t counter[2];
	fread((void *)&(counter[0]), 8, 1, infile); // read nonce from file
	counter[1] = 1; // initialize counter

	bytes_read = 8; // nonce is 8 bytes

	size_t bytes_to_write = 16;

	while (bytes_read < size) {
		memset(block, 'a', 16);
		actual_read = fread(block, 1, 16, infile);
		bytes_read += actual_read;
		if (actual_read != 16 && actual_read != 1) { // all blocks are 16 bytes, padding byte is 1 byte; other values means something bad
			fprintf(stderr, "*** Some sort of read error occured\n");
			exit(1);
		}

		if (actual_read == 16) { // we found another block
			aes_encrypt((unsigned char *)counter, dec_block, expanded_keys);
			counter[1]++;

			for (int i=0; i<16; i++) {
				dec_block[i] ^= block[i];
			}

			if (bytes_read == size - 1) {
				// This is the very last block - the one with the padding, if there is any
				if (padding != 0) {
					bytes_to_write = 16 - padding;
				}
			}

			if (fwrite(dec_block, 1, bytes_to_write, outfile) != bytes_to_write) {
				fprintf(stderr, "*** Write error!\n");
				exit(1);
			}
		}
	}

	fclose(infile);
	fclose(outfile);
}

int main(int argc, char *argv[]) {
	unsigned char key[] = {0x2d, 0x7e, 0x86, 0xa3, 0x39, 0xd9, 0x39, 0x3e, 0xe6, 0x57, 0x0a, 0x11, 0x01, 0x90, 0x4e, 0x16};

	if (argc != 5 || strcmp(argv[3], "-o") != 0) {
		fprintf(stderr, "The arguments MUST be in the form of -d <infile> -o <outfile> *OR* -e <infile> -o <outfile>");
		exit(1);
	}
	if (strcmp(argv[1], "-e") == 0)
		encrypt_file(argv[2], argv[4], key);
	else if (strcmp(argv[1], "-d") == 0)
		decrypt_file(argv[2], argv[4], key);
	else {
		fprintf(stderr, "Need an argument: either -e or -d\n");
		exit(1);
	}

	return 0;
}
