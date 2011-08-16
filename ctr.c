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

	int8_t padding = file_size(inpath) % 16;

	printf("File to encrypt is %llu bytes; padding needed is %d bytes\n", file_size(inpath), (int)padding);

}

int main() {
	unsigned char key[] = {0x2d, 0x7e, 0x86, 0xa3, 0x39, 0xd9, 0x39, 0x3e, 0xe6, 0x57, 0x0a, 0x11, 0x01, 0x90, 0x4e, 0x16};
	encrypt_file("/Users/serenity/Programming/AES/testing/plaintext", "/Users/serenity/Programming/AES/testing/ciphertext", key);

	return 0;
}
