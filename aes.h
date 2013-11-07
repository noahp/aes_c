
//
// aes.h
// API for simple AES 128-bit.
//

#if !defined(AES_H)
#define AES_H

// Encrypt in-place. Data and key should be 16 bytes.
void AES_Encrypt(char *data, char *key);
void AES_Decrypt(char *data, char *key);

#endif //AES_H
