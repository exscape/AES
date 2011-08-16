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
void aes_encrypt_{c,aesni}(const unsigned char *plaintext, unsigned char *ciphertext, const unsigned char *keys);
void aes_decrypt_{c,aesni}(const unsigned char *ciphertext, unsigned char *plaintext, const unsigned char *keys);

int aes_expand_key(const unsigned char *in_key, unsigned char *out_keys);
void aes_prepare_decryption_keys(const unsigned char *keys);
*/

off_t file_size(const char *path) {
	struct stat st;
	if (stat(path, &st) != 0) {
		perror(path);
		exit(1);
	}

	return (st.st_size);
}

void encrypt_file(const char *inpath, const char *outpath, const unsigned char *key) {
	unsigned char expanded_keys[176] = {0};
	aes_expand_key(key, expanded_keys);

	off_t size = file_size(inpath);
	if (size <= 0) {
		fprintf(stderr, "Cannot encrypt a file of size zero!\n");
		exit(1);
	}

	int8_t padding = 16 - (size % 16);

	printf("File to encrypt is %llu bytes; padding needed is %d bytes\n", file_size(inpath), (int)padding);

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

	off_t bytes_read = 0;
	unsigned char block[16] = {0};
	unsigned char enc_block[16] = {0};
	size_t actual_read = 0;

	printf("\"");

	while (bytes_read < size) {
		memset(block, 'a', 16);
		actual_read = fread(block, 1, 16, infile);
		bytes_read += actual_read;
		if (actual_read != 16) {
			if (bytes_read - actual_read /* total bytes read *BEFORE* the last fread() */
					!=
					size - (16-padding)) { /* number of bytes that should be read in 16-byte blocks */
				fprintf(stderr, "*** Some sort of read error occured.\n");
				exit(1);
			}
			else {
				// Add padding
				memset(block + (16-padding), 'A', padding);
			}
		}

		aes_encrypt_aesni(block, enc_block, expanded_keys);
		if (fwrite(enc_block, 1, 16, outfile) != 16) {
			fprintf(stderr, "*** Write error!\n");
			exit(1);
		}

		printf("%16s", block);
	}

	fclose(infile);
	fputc(padding, outfile); // write a final byte, whose value is the amount of padding used

	printf("\"\n");

}

int main() {
	unsigned char key[] = {0x2d, 0x7e, 0x86, 0xa3, 0x39, 0xd9, 0x39, 0x3e, 0xe6, 0x57, 0x0a, 0x11, 0x01, 0x90, 0x4e, 0x16};
	encrypt_file("/Users/serenity/Programming/AES/testing/plaintext", "/Users/serenity/Programming/AES/testing/ciphertext", key);

	return 0;
}
