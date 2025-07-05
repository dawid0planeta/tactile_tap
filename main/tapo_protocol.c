#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <esp_log.h>
#include <mbedtls/sha1.h>
#include <mbedtls/sha256.h>
#include "tapo_cipher.h"
#include "http.h"

#define MAX_HTTP_RECV_BUFFER 512
#define MAX_HTTP_OUTPUT_BUFFER 2048
static const char *TAG = "PROTOCOL";
static uint8_t handshake2_hash[SHA256_SIZE] = {0};

static void handshake1(uint8_t *local_seed, uint8_t *auth_hash);
static void handshake2(uint8_t *local_seed, uint8_t *auth_hash);

void tapo_protocol_send(char* command)
{
    ESP_LOGI(TAG, "Sending command: %s", command);
    size_t command_len = strlen(command);
    size_t pad_len = 16 - (command_len % 16);
    size_t padded_len = command_len + pad_len;
    ESP_LOGD(TAG, "Command len: %u", command_len);
    char *padded_command = (char *)calloc(padded_len, sizeof(char));
    char *encrypted_command = (char *)calloc(padded_len + SHA256_SIZE, sizeof(char)); // \0 for http stack

    memcpy(padded_command, command, command_len);
    // PKCS7 padding
    memset(&padded_command[command_len], pad_len, pad_len);
    tapo_cipher_encrypt((uint8_t *)padded_command, padded_len, (uint8_t *)encrypted_command);

    ESP_LOGD(TAG, "padded_command, %d", padded_len);
    ESP_LOG_BUFFER_HEXDUMP(TAG, padded_command, padded_len, ESP_LOG_DEBUG);

    ESP_LOGD(TAG, "encrypted_command, %d", padded_len + SHA256_SIZE);
    ESP_LOG_BUFFER_HEXDUMP(TAG, encrypted_command, padded_len + SHA256_SIZE + 1, ESP_LOG_DEBUG);

    uint32_t seq = tapo_cipher_get_seq();

    char path[100] = {0};
    snprintf(path, sizeof(path), "%s%lu", "/request?seq=", seq);
    ESP_LOGD(TAG, "path: %s", path);

    uint8_t response_buffer[512] = {0};
    ESP_LOGI(TAG, "Posting command: %s", command);
    http_client_post(path, encrypted_command, padded_len + SHA256_SIZE, (char *)response_buffer);
    ESP_LOGI(TAG, "Response received");

    uint8_t decrypted_response[512] = {0};
    tapo_cipher_decrypt(response_buffer, padded_len + SHA256_SIZE, decrypted_response, 0);

    free(padded_command);
    free(encrypted_command);
}

uint8_t remote_seed[SEED_SIZE] = {0};

void tapo_protocol_handshake()
{
    uint8_t usr_pswd_hashes[40] = {0};
    uint8_t auth_hash[SHA256_SIZE] = {0};

    mbedtls_sha1((const uint8_t *)"dawid0planeta@gmail.com", strlen("dawid0planeta@gmail.com"), usr_pswd_hashes);
    mbedtls_sha1((const uint8_t *)"as95847586", strlen("as95847586"), &usr_pswd_hashes[20]);
    mbedtls_sha256(usr_pswd_hashes, 40, auth_hash, 0);

    uint8_t local_seed[SEED_SIZE] = {0x01, 0x02, 0x13, 0x04, 0x05, 0x16, 0x07, 0x08,
                                     0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};

    http_client_init();
    handshake1(local_seed, auth_hash);
    handshake2(local_seed, auth_hash);

    tapo_cipher_init(local_seed, remote_seed, auth_hash);
}

static void handshake1(uint8_t *local_seed, uint8_t *auth_hash)
{
    uint8_t response_buffer[512] = {0};
    uint8_t server_hash[SHA256_SIZE] = {0};
    uint8_t local_hash[SHA256_SIZE] = {0};
    uint8_t local_hash_input[SEED_SIZE + SEED_SIZE + SHA256_SIZE] = {0};

    http_client_post("/handshake1", (char *)local_seed, SEED_SIZE, (char *)response_buffer);


    memcpy(remote_seed, response_buffer, SEED_SIZE);
    memcpy(server_hash, &response_buffer[SEED_SIZE], SHA256_SIZE);

    memcpy(local_hash_input, local_seed, SEED_SIZE);
    memcpy(&local_hash_input[SEED_SIZE], remote_seed, SEED_SIZE);
    memcpy(&local_hash_input[SEED_SIZE * 2], auth_hash, SHA256_SIZE);

    mbedtls_sha256(local_hash_input, SEED_SIZE * 2 + SHA256_SIZE, local_hash, 0);

    ESP_LOGD(TAG, "Local hash");
    ESP_LOG_BUFFER_HEX(TAG, local_hash, SHA256_SIZE);


    ESP_LOGD(TAG, "Server hash");
    ESP_LOG_BUFFER_HEX(TAG, server_hash, SHA256_SIZE);


    ESP_LOGD("PROTOCOL", "Handshake1 success");

    uint8_t handshake2_hash_input[SEED_SIZE + SEED_SIZE + SHA256_SIZE] = {0};

    memset(handshake2_hash, 0x00, SHA256_SIZE);
    memcpy(handshake2_hash_input, remote_seed, SEED_SIZE);
    memcpy(&handshake2_hash_input[SEED_SIZE], local_seed, SEED_SIZE);
    memcpy(&handshake2_hash_input[SEED_SIZE * 2], auth_hash, SHA256_SIZE);

    mbedtls_sha256(handshake2_hash_input, SEED_SIZE * 2 + SHA256_SIZE, handshake2_hash, 0);

}

static void handshake2(uint8_t *local_seed, uint8_t *auth_hash)
{
    uint8_t response_buffer[512] = {0};
    http_client_post("/handshake2", (char *)handshake2_hash, SHA256_SIZE, (char *)response_buffer);
}
// void handshake1(const std::vector<uint8_t>& local_seed, const std::vector<uint8_t>& auth_hash) {
//     String response_str;
//     post("/handshake1", local_seed, [&response_str](HTTPClient& http) {
//         response_str = http.getString();
//     }, true);

//     std::vector<uint8_t> remote_seed(response_str.begin(), response_str.begin() + 16);
//     std::vector<uint8_t> server_hash(response_str.begin() + 16, response_str.end());
//     std::vector<uint8_t> local_hash = TapoCipher::sha256(TapoCipher::concat(local_seed, remote_seed, auth_hash));
//     if (local_hash != server_hash) {
//         Serial.println("TAPO_PROTOCOL: Invalid credentials during handshake1");
//         return {};
//     }
//     TAPO_PROTOCOL_DEBUG("Handshake1 successful");

//     return remote_seed;
// }

// void handshake2(const std::vector<uint8_t>& local_seed, const std::vector<uint8_t>& remote_seed, const std::vector<uint8_t>& auth_hash) {
//     std::vector<uint8_t> payload = TapoCipher::sha256(TapoCipher::concat(remote_seed, local_seed, auth_hash));
//     String response_str;
//     int response_code = post("/handshake2", payload, [&response_str](HTTPClient& http) {
//         response_str = http.getString();
//     });
//     if (response_code != 200) {
//         Serial.println("TAPO_PROTOCOL: Handshake2 failed with response code " + String(response_code));
//         return;
//     }
//     TAPO_PROTOCOL_DEBUG("Handshake2 successful");
// }