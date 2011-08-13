void AddRoundKey(unsigned char *state, const unsigned char *keys);
void SubBytes(unsigned char *state);
void aes_encrypt(const unsigned char *plaintext, unsigned char *state, const unsigned char *keys);
