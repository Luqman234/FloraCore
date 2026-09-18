#include "floraos_claim.h"

#include <stdio.h>
#include <string.h>

#include "mbedtls/platform_util.h"

bool floraos_claim_token_is_valid(const char *token)
{
    if (token == NULL) {
        return false;
    }

    size_t length = strlen(token);
    if (length < FLORAOS_CLAIM_TOKEN_MIN_LEN ||
        length > FLORAOS_CLAIM_TOKEN_MAX_LEN) {
        return false;
    }

    for (size_t i = 0; i < length; i++) {
        char ch = token[i];
        bool ok =
            (ch >= 'a' && ch <= 'z') ||
            (ch >= 'A' && ch <= 'Z') ||
            (ch >= '0' && ch <= '9') ||
            ch == '-' ||
            ch == '_';

        if (!ok) {
            return false;
        }
    }

    return true;
}

esp_err_t floraos_claim_start(
    const char *token,
    floraos_client_result_cb_t callback,
    void *user_ctx
)
{
    if (!floraos_claim_token_is_valid(token)) {
        return ESP_ERR_INVALID_ARG;
    }

    esp_err_t err = floraos_client_init();
    if (err != ESP_OK) {
        return err;
    }

    char payload[180] = {0};

    int written = snprintf(
        payload,
        sizeof(payload),
        "{\"token\":\"%s\"}",
        token
    );

    if (written <= 0 || (size_t)written >= sizeof(payload)) {
        mbedtls_platform_zeroize(payload, sizeof(payload));
        return ESP_ERR_INVALID_SIZE;
    }

    err = floraos_client_queue_message_with_callback(
        "claim",
        payload,
        callback,
        user_ctx
    );

    mbedtls_platform_zeroize(payload, sizeof(payload));
    return err;
}
