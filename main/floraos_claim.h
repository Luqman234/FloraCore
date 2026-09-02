#ifndef FLORAOS_CLAIM_H
#define FLORAOS_CLAIM_H

#include <stdbool.h>
#include "esp_err.h"
#include "floraos_client.h"

#define FLORAOS_CLAIM_TOKEN_MIN_LEN 32
#define FLORAOS_CLAIM_TOKEN_MAX_LEN 128

bool floraos_claim_token_is_valid(const char *token);

esp_err_t floraos_claim_start(
    const char *token,
    floraos_client_result_cb_t callback,
    void *user_ctx
);

#endif
