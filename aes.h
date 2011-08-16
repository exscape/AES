#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>

void AddRoundKey(unsigned char *state, const unsigned char *keys);
void SubBytes(unsigned char *state);
void aes_encrypt_aesni(const unsigned char *plaintext, unsigned char *ciphertext, const unsigned char *keys);
void aes_encrypt_c(const unsigned char *plaintext, unsigned char *ciphertext, const unsigned char *keys);
void aes_decrypt_aesni(const unsigned char *ciphertext, unsigned char *plaintext, const unsigned char *keys);
void aes_decrypt_c(const unsigned char *ciphertext, unsigned char *plaintext, const unsigned char *keys);
void ShiftRows(unsigned char *state, bool inverse);
void InvSubBytes(unsigned char *state);
#define InvShiftRows(state) ShiftRows(state, 1)
void InvMixColumns(unsigned char *state);
void MixColumns(unsigned char *state);
