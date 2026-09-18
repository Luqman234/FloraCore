#ifndef FLORAOS_CRYPTO_H
#define FLORAOS_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"

#define FLORAOS_DEVICE_ID_MAX   48
#define FLORAOS_NONCE_LEN       12
#define FLORAOS_MESSAGE_ID_LEN  16

/*
 * Initializes PSA Crypto and derives two direction-specific
 * AES-256-GCM keys from the ESP32-S3's read-protected
 * HMAC_UP eFuse key.
 *
 * The raw eFuse key is never read by software.
 */
esp_err_t floraos_crypto_init(void);

/* Stable ID based on the Wi-Fi station MAC. */
const char *floraos_crypto_device_id(void);

/*
 * Encrypt plaintext for device -> server.
 *
 * Output contains AES-GCM ciphertext with the authentication
 * tag appended by PSA Crypto.
 */
esp_err_t floraos_crypto_encrypt_d2s(
    const uint8_t nonce[FLORAOS_NONCE_LEN],
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t *plaintext,
    size_t plaintext_len,
    uint8_t *ciphertext,
    size_t ciphertext_capacity,
    size_t *ciphertext_len
);

/* Decrypt and authenticate server -> device data. */
esp_err_t floraos_crypto_decrypt_s2d(
    const uint8_t nonce[FLORAOS_NONCE_LEN],
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    uint8_t *plaintext,
    size_t plaintext_capacity,
    size_t *plaintext_len
);

esp_err_t floraos_crypto_random(
    uint8_t *buffer,
    size_t length
);

void floraos_hex_encode(
    const uint8_t *input,
    size_t input_len,
    char *output
);

esp_err_t floraos_hex_decode(
    const char *input,
    uint8_t *output,
    size_t output_capacity,
    size_t *output_len
);

#endif
