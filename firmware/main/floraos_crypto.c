#include "floraos_crypto.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "esp_hmac.h"
#include "esp_log.h"
#include "esp_mac.h"

#include "mbedtls/platform_util.h"

#include "psa/crypto.h"


static const char *TAG = "FLORAOS_CRYPTO";

/*
 * This project currently has its HMAC_UP key in KEY0.
 *
 * Domain-separated HMAC messages are used to derive dedicated
 * network keys. The raw eFuse key never leaves the HMAC
 * peripheral.
 *
 * For a later production revision you can move network crypto
 * to a dedicated HMAC_UP eFuse key without changing the
 * protocol, as long as the backend registry is reprovisioned.
 */
#define FLORAOS_HMAC_KEY_ID HMAC_KEY0

#define FLORAOS_PROTOCOL_LABEL "floraos-e2ee-v1"

static char s_device_id[FLORAOS_DEVICE_ID_MAX];

static psa_key_id_t s_d2s_key = 0;
static psa_key_id_t s_s2d_key = 0;

static bool s_initialized = false;


static esp_err_t derive_hmac_key(
    const char *direction,
    uint8_t output[32]
)
{
    char context[128];

    int written = snprintf(
        context,
        sizeof(context),
        "%s|%s|%s",
        FLORAOS_PROTOCOL_LABEL,
        direction,
        s_device_id
    );

    if (
        written <= 0 ||
        (size_t)written >= sizeof(context)
    ) {
        return ESP_ERR_INVALID_SIZE;
    }

    return esp_hmac_calculate(
        FLORAOS_HMAC_KEY_ID,
        context,
        (size_t)written,
        output
    );
}


static esp_err_t import_aes_key(
    const uint8_t key_bytes[32],
    psa_key_usage_t usage,
    psa_key_id_t *key_id
)
{
    psa_key_attributes_t attributes =
        PSA_KEY_ATTRIBUTES_INIT;

    psa_set_key_type(
        &attributes,
        PSA_KEY_TYPE_AES
    );

    psa_set_key_bits(
        &attributes,
        256
    );

    psa_set_key_usage_flags(
        &attributes,
        usage
    );

    psa_set_key_algorithm(
        &attributes,
        PSA_ALG_GCM
    );

    psa_status_t status = psa_import_key(
        &attributes,
        key_bytes,
        32,
        key_id
    );

    psa_reset_key_attributes(
        &attributes
    );

    if (status != PSA_SUCCESS) {
        ESP_LOGE(
            TAG,
            "psa_import_key failed: %ld",
            (long)status
        );

        return ESP_FAIL;
    }

    return ESP_OK;
}


esp_err_t floraos_crypto_init(void)
{
    if (s_initialized) {
        return ESP_OK;
    }

    psa_status_t psa_status =
        psa_crypto_init();

    if (psa_status != PSA_SUCCESS) {
        ESP_LOGE(
            TAG,
            "psa_crypto_init failed: %ld",
            (long)psa_status
        );

        return ESP_FAIL;
    }


    uint8_t mac[6];

    esp_err_t err = esp_read_mac(
        mac,
        ESP_MAC_WIFI_STA
    );

    if (err != ESP_OK) {
        return err;
    }


    snprintf(
        s_device_id,
        sizeof(s_device_id),
        "floracore-%02x%02x%02x%02x%02x%02x",
        mac[0],
        mac[1],
        mac[2],
        mac[3],
        mac[4],
        mac[5]
    );


    uint8_t derived_key[32];


    err = derive_hmac_key(
        "d2s",
        derived_key
    );

    if (err != ESP_OK) {
        ESP_LOGE(
            TAG,
            "Could not derive device->server key: %s",
            esp_err_to_name(err)
        );

        mbedtls_platform_zeroize(
            derived_key,
            sizeof(derived_key)
        );

        return err;
    }


    err = import_aes_key(
        derived_key,
        PSA_KEY_USAGE_ENCRYPT,
        &s_d2s_key
    );

    mbedtls_platform_zeroize(
        derived_key,
        sizeof(derived_key)
    );

    if (err != ESP_OK) {
        return err;
    }


    err = derive_hmac_key(
        "s2d",
        derived_key
    );

    if (err != ESP_OK) {
        psa_destroy_key(
            s_d2s_key
        );

        s_d2s_key = 0;

        mbedtls_platform_zeroize(
            derived_key,
            sizeof(derived_key)
        );

        return err;
    }


    err = import_aes_key(
        derived_key,
        PSA_KEY_USAGE_DECRYPT,
        &s_s2d_key
    );

    mbedtls_platform_zeroize(
        derived_key,
        sizeof(derived_key)
    );

    if (err != ESP_OK) {
        psa_destroy_key(
            s_d2s_key
        );

        s_d2s_key = 0;

        return err;
    }


    s_initialized = true;


    ESP_LOGI(
        TAG,
        "E2EE ready for device %s",
        s_device_id
    );


    return ESP_OK;
}


const char *floraos_crypto_device_id(void)
{
    return s_device_id;
}


esp_err_t floraos_crypto_random(
    uint8_t *buffer,
    size_t length
)
{
    if (
        buffer == NULL ||
        length == 0
    ) {
        return ESP_ERR_INVALID_ARG;
    }


    psa_status_t status =
        psa_generate_random(
            buffer,
            length
        );


    return
        status == PSA_SUCCESS
        ? ESP_OK
        : ESP_FAIL;
}


esp_err_t floraos_crypto_encrypt_d2s(
    const uint8_t nonce[FLORAOS_NONCE_LEN],
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t *plaintext,
    size_t plaintext_len,
    uint8_t *ciphertext,
    size_t ciphertext_capacity,
    size_t *ciphertext_len
)
{
    if (
        !s_initialized ||
        nonce == NULL ||
        plaintext == NULL ||
        ciphertext == NULL ||
        ciphertext_len == NULL
    ) {
        return ESP_ERR_INVALID_STATE;
    }


    psa_status_t status =
        psa_aead_encrypt(
            s_d2s_key,
            PSA_ALG_GCM,
            nonce,
            FLORAOS_NONCE_LEN,
            aad,
            aad_len,
            plaintext,
            plaintext_len,
            ciphertext,
            ciphertext_capacity,
            ciphertext_len
        );


    if (status != PSA_SUCCESS) {
        ESP_LOGE(
            TAG,
            "AES-GCM encrypt failed: %ld",
            (long)status
        );

        return ESP_FAIL;
    }


    return ESP_OK;
}


esp_err_t floraos_crypto_decrypt_s2d(
    const uint8_t nonce[FLORAOS_NONCE_LEN],
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    uint8_t *plaintext,
    size_t plaintext_capacity,
    size_t *plaintext_len
)
{
    if (
        !s_initialized ||
        nonce == NULL ||
        ciphertext == NULL ||
        plaintext == NULL ||
        plaintext_len == NULL
    ) {
        return ESP_ERR_INVALID_STATE;
    }


    psa_status_t status =
        psa_aead_decrypt(
            s_s2d_key,
            PSA_ALG_GCM,
            nonce,
            FLORAOS_NONCE_LEN,
            aad,
            aad_len,
            ciphertext,
            ciphertext_len,
            plaintext,
            plaintext_capacity,
            plaintext_len
        );


    if (status != PSA_SUCCESS) {
        ESP_LOGE(
            TAG,
            "AES-GCM decrypt/authentication failed: %ld",
            (long)status
        );

        return ESP_ERR_INVALID_CRC;
    }


    return ESP_OK;
}


void floraos_hex_encode(
    const uint8_t *input,
    size_t input_len,
    char *output
)
{
    static const char hex[] =
        "0123456789abcdef";


    for (
        size_t i = 0;
        i < input_len;
        i++
    ) {
        output[
            i * 2
        ] = hex[
            input[i] >> 4
        ];

        output[
            i * 2 + 1
        ] = hex[
            input[i] & 0x0F
        ];
    }


    output[
        input_len * 2
    ] = '\0';
}


static int hex_nibble(
    char c
)
{
    if (
        c >= '0' &&
        c <= '9'
    ) {
        return c - '0';
    }

    if (
        c >= 'a' &&
        c <= 'f'
    ) {
        return c - 'a' + 10;
    }

    if (
        c >= 'A' &&
        c <= 'F'
    ) {
        return c - 'A' + 10;
    }

    return -1;
}


esp_err_t floraos_hex_decode(
    const char *input,
    uint8_t *output,
    size_t output_capacity,
    size_t *output_len
)
{
    if (
        input == NULL ||
        output == NULL ||
        output_len == NULL
    ) {
        return ESP_ERR_INVALID_ARG;
    }


    size_t input_len =
        strlen(input);


    if (
        input_len == 0 ||
        (input_len & 1U) != 0
    ) {
        return ESP_ERR_INVALID_ARG;
    }


    size_t required =
        input_len / 2;


    if (
        required >
        output_capacity
    ) {
        return ESP_ERR_INVALID_SIZE;
    }


    for (
        size_t i = 0;
        i < required;
        i++
    ) {
        int hi =
            hex_nibble(
                input[i * 2]
            );

        int lo =
            hex_nibble(
                input[i * 2 + 1]
            );


        if (
            hi < 0 ||
            lo < 0
        ) {
            return ESP_ERR_INVALID_ARG;
        }


        output[i] =
            (uint8_t)(
                (hi << 4) | lo
            );
    }


    *output_len =
        required;


    return ESP_OK;
}
