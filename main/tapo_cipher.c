#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <mbedtls/sha1.h>
#include <mbedtls/sha256.h>
#include <mbedtls/aes.h>
#include "esp_log.h"
#include "tapo_cipher.h"

#define KEY_SIZE 16
#define IV_SIZE 12
#define SIG_SIZE 28
#define SEQ_BYTES_SIZE 4
#define IV_SEQ_SIZE (IV_SIZE + SEQ_BYTES_SIZE)

// static uint8_t local_seed[SEED_SIZE] = {0};
// static uint8_t remote_seed[SEED_SIZE] = {0};
// static uint8_t auth_hash[SHA256_SIZE] = {0};
// static uint8_t local_hash[LOCAL_HASH_SIZE] = {0};

static const char *TAG = "CIPHER";

uint8_t key[KEY_SIZE] = {0};
uint8_t iv[IV_SIZE] = {0};
uint8_t sig[SIG_SIZE] = {0};
uint8_t iv_seq[IV_SEQ_SIZE] = {0};
uint32_t seq = 0;

static void key_derive(uint8_t *local_hash);
static void iv_derive(uint8_t *local_hash);
static void sig_derive(uint8_t *local_hash);
static void iv_seq_derive();
static void to_bytes(uint32_t value, uint8_t *bytes);

void tapo_cipher_init(uint8_t *local_seed, uint8_t *remote_seed, uint8_t *auth_hash)
{
    uint8_t local_hash[LOCAL_HASH_SIZE] = {0};
    memcpy(&local_hash, local_seed, SEED_SIZE);
    memcpy(&local_hash[SEED_SIZE], remote_seed, SEED_SIZE);
    memcpy(&local_hash[SEED_SIZE * 2], auth_hash, SHA256_SIZE);

    key_derive(local_hash);
    iv_derive(local_hash);
    sig_derive(local_hash);

    ESP_LOGD(TAG, "key");
    ESP_LOG_BUFFER_HEXDUMP(TAG, key, KEY_SIZE, ESP_LOG_DEBUG);
    ESP_LOGD(TAG, "iv");
    ESP_LOG_BUFFER_HEXDUMP(TAG, iv, IV_SIZE, ESP_LOG_DEBUG);
    ESP_LOGD(TAG, "sig");
    ESP_LOG_BUFFER_HEXDUMP(TAG, sig, SIG_SIZE, ESP_LOG_DEBUG);
    ESP_LOGD(TAG, "seq: %lu", seq);
}

void tapo_cipher_encrypt(uint8_t *input_data, size_t input_len, uint8_t *result)
{
    uint8_t *encrypted_data = (uint8_t *)malloc(input_len);
    seq += 1;
    iv_seq_derive();
    mbedtls_aes_context aes_ctx;
    mbedtls_aes_init(&aes_ctx);
    mbedtls_aes_setkey_enc(&aes_ctx, key, KEY_SIZE * 8);

    mbedtls_aes_crypt_cbc(&aes_ctx, MBEDTLS_AES_ENCRYPT, input_len, iv_seq, input_data, encrypted_data);
    mbedtls_aes_free(&aes_ctx);

    ESP_LOGD(TAG, "ciphertext");
    ESP_LOG_BUFFER_HEXDUMP(TAG, encrypted_data, input_len, ESP_LOG_DEBUG);

    uint8_t seq_bytes[SEQ_BYTES_SIZE] = {0};
    uint8_t *combined_data = (uint8_t *)malloc(SIG_SIZE + SEQ_BYTES_SIZE + input_len);
    uint8_t signature[SHA256_SIZE] = {0};

    to_bytes(seq, seq_bytes);
    memcpy(combined_data, sig, SIG_SIZE);
    memcpy(&combined_data[SIG_SIZE], seq_bytes, SEQ_BYTES_SIZE);
    memcpy(&combined_data[SIG_SIZE + SEQ_BYTES_SIZE], encrypted_data, input_len);

    mbedtls_sha256(combined_data, SIG_SIZE + SEQ_BYTES_SIZE + input_len, signature, 0);

    memcpy(result, signature, SHA256_SIZE);
    memcpy(&result[SHA256_SIZE], encrypted_data, input_len);

    ESP_LOGD(TAG, "signature");
    ESP_LOG_BUFFER_HEXDUMP(TAG, signature, SHA256_SIZE, ESP_LOG_DEBUG);

    free(encrypted_data);
    free(combined_data);
}

void tapo_cipher_decrypt(uint8_t *combined_data, size_t combined_data_len, uint8_t *result, size_t result_len)
{
    uint8_t signature[SHA256_SIZE] = {0};
    memcpy(signature, combined_data, SHA256_SIZE);

    size_t encrypted_data_len = combined_data_len - SHA256_SIZE;

    iv_seq_derive();

    mbedtls_aes_context aes_ctx;
    mbedtls_aes_init(&aes_ctx);
    mbedtls_aes_setkey_dec(&aes_ctx, key, KEY_SIZE * 8);

    mbedtls_aes_crypt_cbc(&aes_ctx, MBEDTLS_AES_DECRYPT, encrypted_data_len, iv_seq, &combined_data[SHA256_SIZE], result);
    mbedtls_aes_free(&aes_ctx);
}

uint32_t tapo_cipher_get_seq()
{
    return seq;
}


static void key_derive(uint8_t *local_hash)
{
    uint8_t input[LOCAL_HASH_SIZE + 3] = {0};
    uint8_t output[SHA256_SIZE] = {0};
    input[0] = 'l';
    input[1] = 's';
    input[2] = 'k';

    memcpy(&input[3], local_hash, LOCAL_HASH_SIZE);
    mbedtls_sha256((const uint8_t *)&input, LOCAL_HASH_SIZE + 3, output, 0);
    memcpy(&key, output, KEY_SIZE);
}

static void iv_derive(uint8_t *local_hash)
{
    uint8_t input[LOCAL_HASH_SIZE + 2] = {0};
    uint8_t output[SHA256_SIZE] = {0};
    input[0] = 'i';
    input[1] = 'v';
    memcpy(&input[2], local_hash, LOCAL_HASH_SIZE);
    mbedtls_sha256((const uint8_t *)&input, LOCAL_HASH_SIZE + 2, output, 0);
    memcpy(&iv, output, IV_SIZE);
    seq = (output[28] << 24) | (output[29] << 16) | (output[30] << 8) | output[31];
}

static void sig_derive(uint8_t *local_hash)
{
    uint8_t input[LOCAL_HASH_SIZE + 3] = {0};
    uint8_t output[SHA256_SIZE] = {0};
    input[0] = 'l';
    input[1] = 'd';
    input[2] = 'k';

    memcpy(&input[3], local_hash, LOCAL_HASH_SIZE);
    mbedtls_sha256((const uint8_t *)&input, LOCAL_HASH_SIZE + 3, output, 0);
    memcpy(&sig, output, SIG_SIZE);
}

static void iv_seq_derive()
{
    uint8_t bytes[SEQ_BYTES_SIZE] = {0};
    to_bytes(seq, bytes);
    memcpy(&iv_seq, iv, IV_SIZE);
    memcpy(&iv_seq[IV_SIZE], bytes, SEQ_BYTES_SIZE);
    ESP_LOGD(TAG, "iv_seq:");
    ESP_LOG_BUFFER_HEXDUMP(TAG, iv_seq, IV_SEQ_SIZE, ESP_LOG_DEBUG);
}

static void to_bytes(uint32_t value, uint8_t *bytes)
{
    bytes[0] = (value >> 24) & 0xff;
    bytes[1] = (value >> 16) & 0xff;
    bytes[2] = (value >> 8) & 0xff;
    bytes[3] = value & 0xff;
}


int test_tapo_cipher()
{
    uint8_t local_seed[SEED_SIZE] = {0x07, 0x64, 0x25, 0xba, 0x83, 0x27, 0x28, 0x52, 0x27, 0xb7, 0x5b, 0xbd, 0x7f, 0x1a, 0x01, 0x8c, };

    uint8_t remote_seed[SEED_SIZE] = {0x65, 0x71, 0xa2, 0xf6, 0x6f, 0x99, 0xa1, 0xf6, 0x87, 0x9c, 0x21, 0xf7, 0x82, 0x68, 0x20, 0xf7, };

    uint8_t usr_pswd_hashes[40] = {0};
    uint8_t auth_hash[SHA256_SIZE] = {0};

    mbedtls_sha1((const uint8_t *)"dawid0planeta@gmail.com", strlen("dawid0planeta@gmail.com"), usr_pswd_hashes);
    mbedtls_sha1((const uint8_t *)"as95847586", strlen("as95847586"), &usr_pswd_hashes[20]);
    mbedtls_sha256(usr_pswd_hashes, 40, auth_hash, 0);

    ESP_LOGD(TAG, "Auth hash:");
    ESP_LOG_BUFFER_HEXDUMP(TAG, auth_hash, SHA256_SIZE, ESP_LOG_DEBUG);

    ESP_LOGD("CIPHER", "Before init");

    tapo_cipher_init(local_seed, remote_seed, auth_hash);

    ESP_LOGD("CIPHER", "After init");

    unsigned char test_text[240] = {0};
    char test[] = "{\"method\":\"multipleRequest\",\"request_time_milis\":1746354342890,\"terminal_uuid\":\"zb2T+ZuwvXCvdYWCiGW4Lg==\",\"params\":{\"requests\":[{\"method\":\"component_nego\"},{\"method\":\"get_device_info\"},{\"method\":\"get_connect_cloud_state\"}]}}";
    uint8_t padding = 240 - strlen(test);
    memcpy(test_text, test, strlen(test));
    memset(&test_text[strlen(test)], padding, padding);

    uint8_t combined_data[240 + SHA256_SIZE] = {0};
    uint8_t decrypted[240] = {0};

    ESP_LOGD("CIPHER", "Before encrypt");
    tapo_cipher_encrypt(test_text, 240, combined_data);
    ESP_LOGD("CIPHER", "After encrypt");

    tapo_cipher_decrypt(combined_data, 240 + SHA256_SIZE, decrypted, 240);

    ESP_LOGD("CIPHER", "Original text\n");
    ESP_LOG_BUFFER_HEXDUMP("CIPHER", test_text, 240, ESP_LOG_DEBUG); 
    ESP_LOGD("CIPHER", "Encrypted text\n");
    ESP_LOG_BUFFER_HEXDUMP("CIPHER", combined_data, 240 + SHA256_SIZE, ESP_LOG_DEBUG); 
    ESP_LOGD("CIPHER", "Decrypted text\n");
    ESP_LOG_BUFFER_HEXDUMP("CIPHER", test_text, 240, ESP_LOG_DEBUG); 


    return 0;
}