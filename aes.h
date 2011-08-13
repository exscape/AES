#include <unistd.h>
#include <stdint.h>

void AddRoundKey(unsigned char *state, const unsigned char *keys);
void SubBytes(unsigned char *state);
void aes_encrypt(const unsigned char *plaintext, unsigned char *state, const unsigned char *keys);
void ShiftRow(uint32_t *word, uint8_t steps);
void ShiftRows(unsigned char *state);
