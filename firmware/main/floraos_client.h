#ifndef FLORAOS_CLIENT_H
#define FLORAOS_CLIENT_H

#include <stdbool.h>
#include <stddef.h>
#include "esp_err.h"

typedef void (*floraos_client_result_cb_t)(
    esp_err_t result,
    const char *response_plaintext,
    void *user_ctx
);

esp_err_t floraos_client_init(void);

esp_err_t floraos_client_queue_message(
    const char *type,
    const char *payload_json
);

esp_err_t floraos_client_queue_message_with_callback(
    const char *type,
    const char *payload_json,
    floraos_client_result_cb_t callback,
    void *user_ctx
);

esp_err_t floraos_client_send_message(
    const char *type,
    const char *payload_json,
    char *response_plaintext,
    size_t response_capacity
);

bool floraos_client_is_ready(void);
const char *floraos_client_device_id(void);

#endif
