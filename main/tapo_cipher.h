#ifndef TAPO_cipher_H
#define TAPO_cipher_H

#include <stdint.h>
#include <stdlib.h>

#define SEED_SIZE 16
#define SHA256_SIZE 32
#define LOCAL_HASH_SIZE (SEED_SIZE * 2 + SHA256_SIZE)

void tapo_cipher_init(uint8_t *local_seed, uint8_t *remote_seed, uint8_t *auth_hash);
void tapo_cipher_encrypt(uint8_t *input_data, size_t input_len, uint8_t *result);
void tapo_cipher_decrypt(uint8_t *combined_data, size_t combined_data_len, uint8_t *result, size_t result_len);
uint32_t tapo_cipher_get_seq();
int test_tapo_cipher();


#endif