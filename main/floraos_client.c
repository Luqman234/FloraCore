#include "floraos_client.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"

#include "esp_crt_bundle.h"
#include "esp_heap_caps.h"
#include "esp_http_client.h"
#include "esp_log.h"

#include "mbedtls/platform_util.h"

#include "floraos_crypto.h"

static const char *TAG = "FLORAOS_CLIENT";

#define FLORAOS_ENDPOINT "https://floraos.life/api/device/v1/message"
#define FLORAOS_PATH "/api/device/v1/message"
#define FLORAOS_PROTOCOL_VERSION 1

#define MAX_PLAINTEXT 1200
#define MAX_CIPHERTEXT 1232
#define MAX_OUTER_JSON 2800
#define MAX_HTTP_RESPONSE 4096

#define FLORAOS_WORKER_STACK_SIZE (16 * 1024)
#define FLORAOS_WORKER_PRIORITY 5
#define FLORAOS_WORKER_QUEUE_DEPTH 8
#define FLORAOS_WORKER_CORE 1
#define FLORAOS_QUEUED_TYPE_MAX 32
#define FLORAOS_QUEUED_PAYLOAD_MAX 1024
#define FLORAOS_CALLBACK_RESPONSE_MAX 1024

static bool s_initialized = false;
static bool s_initializing = false;
static portMUX_TYPE s_init_lock = portMUX_INITIALIZER_UNLOCKED;
static QueueHandle_t s_worker_queue = NULL;
static TaskHandle_t s_worker_task = NULL;

typedef struct
{
    char type[FLORAOS_QUEUED_TYPE_MAX];
    char payload[FLORAOS_QUEUED_PAYLOAD_MAX];
    floraos_client_result_cb_t callback;
    void *user_ctx;
} floraos_queued_message_t;

typedef struct
{
    char data[MAX_HTTP_RESPONSE];
    size_t length;
    bool overflowed;
} http_response_buffer_t;

static void *floraos_alloc(size_t size)
{
    void *ptr = heap_caps_calloc(1, size, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (ptr == NULL) {
        ptr = heap_caps_calloc(1, size, MALLOC_CAP_8BIT);
    }
    return ptr;
}

static void secure_free(void *ptr, size_t size)
{
    if (ptr != NULL) {
        mbedtls_platform_zeroize(ptr, size);
        heap_caps_free(ptr);
    }
}

static esp_err_t http_event_handler(esp_http_client_event_t *event)
{
    if (event == NULL || event->user_data == NULL) {
        return ESP_OK;
    }

    http_response_buffer_t *response =
        (http_response_buffer_t *)event->user_data;

    if (event->event_id == HTTP_EVENT_ON_DATA) {
        size_t remaining =
            sizeof(response->data) - response->length - 1;

        if ((size_t)event->data_len > remaining) {
            response->overflowed = true;
            return ESP_OK;
        }

        memcpy(
            response->data + response->length,
            event->data,
            (size_t)event->data_len
        );
        response->length += (size_t)event->data_len;
        response->data[response->length] = '\0';
    }

    return ESP_OK;
}

static bool json_get_string(
    const char *json,
    const char *key,
    char *output,
    size_t output_capacity
)
{
    if (json == NULL || key == NULL || output == NULL || output_capacity == 0) {
        return false;
    }

    char needle[64];
    int written = snprintf(needle, sizeof(needle), "\"%s\"", key);
    if (written <= 0 || (size_t)written >= sizeof(needle)) {
        return false;
    }

    const char *position = strstr(json, needle);
    if (position == NULL) {
        return false;
    }

    position += strlen(needle);
    while (*position == ' ' || *position == '\t' ||
           *position == '\r' || *position == '\n') {
        position++;
    }

    if (*position++ != ':') {
        return false;
    }

    while (*position == ' ' || *position == '\t' ||
           *position == '\r' || *position == '\n') {
        position++;
    }

    if (*position++ != '"') {
        return false;
    }

    const char *end = strchr(position, '"');
    if (end == NULL) {
        return false;
    }

    size_t length = (size_t)(end - position);
    if (length + 1 > output_capacity) {
        return false;
    }

    memcpy(output, position, length);
    output[length] = '\0';
    return true;
}

static esp_err_t make_aad(
    const char *direction,
    char *output,
    size_t output_capacity
)
{
    int written = snprintf(
        output,
        output_capacity,
        "floraos-e2ee-v1|%s|%s|%s",
        floraos_crypto_device_id(),
        direction,
        FLORAOS_PATH
    );

    return (written > 0 && (size_t)written < output_capacity)
        ? ESP_OK
        : ESP_ERR_INVALID_SIZE;
}

static void floraos_worker_task(void *parameter)
{
    (void)parameter;

    ESP_LOGI(
        TAG,
        "FloraOS HTTPS worker started on core %d with %d-byte stack",
        xPortGetCoreID(),
        FLORAOS_WORKER_STACK_SIZE
    );

    while (1) {
        floraos_queued_message_t *message = NULL;

        if (xQueueReceive(s_worker_queue, &message, portMAX_DELAY) != pdTRUE ||
            message == NULL) {
            continue;
        }

        char response[FLORAOS_CALLBACK_RESPONSE_MAX] = {0};
        bool needs_response = message->callback != NULL;

        esp_err_t err = floraos_client_send_message(
            message->type,
            message->payload,
            needs_response ? response : NULL,
            needs_response ? sizeof(response) : 0
        );

        if (err != ESP_OK) {
            ESP_LOGW(
                TAG,
                "Queued FloraOS message \"%s\" failed: %s",
                message->type,
                esp_err_to_name(err)
            );
        } else {
            ESP_LOGI(TAG, "Queued FloraOS message \"%s\" sent", message->type);
        }

        if (message->callback != NULL) {
            message->callback(err, response, message->user_ctx);
        }

        mbedtls_platform_zeroize(response, sizeof(response));
        secure_free(message, sizeof(*message));
    }
}

static esp_err_t floraos_start_worker(void)
{
    if (s_worker_queue != NULL && s_worker_task != NULL) {
        return ESP_OK;
    }

    s_worker_queue = xQueueCreate(
        FLORAOS_WORKER_QUEUE_DEPTH,
        sizeof(floraos_queued_message_t *)
    );
    if (s_worker_queue == NULL) {
        return ESP_ERR_NO_MEM;
    }

    BaseType_t result = xTaskCreatePinnedToCore(
        floraos_worker_task,
        "floraos_https",
        FLORAOS_WORKER_STACK_SIZE,
        NULL,
        FLORAOS_WORKER_PRIORITY,
        &s_worker_task,
        FLORAOS_WORKER_CORE
    );

    if (result != pdPASS) {
        vQueueDelete(s_worker_queue);
        s_worker_queue = NULL;
        s_worker_task = NULL;
        return ESP_ERR_NO_MEM;
    }

    return ESP_OK;
}

esp_err_t floraos_client_queue_message_with_callback(
    const char *type,
    const char *payload_json,
    floraos_client_result_cb_t callback,
    void *user_ctx
)
{
    if (!s_initialized || s_worker_queue == NULL ||
        type == NULL || payload_json == NULL) {
        return ESP_ERR_INVALID_STATE;
    }

    size_t type_length = strlen(type);
    size_t payload_length = strlen(payload_json);

    if (type_length == 0 || type_length >= FLORAOS_QUEUED_TYPE_MAX ||
        payload_length == 0 || payload_length >= FLORAOS_QUEUED_PAYLOAD_MAX) {
        return ESP_ERR_INVALID_SIZE;
    }

    floraos_queued_message_t *message = floraos_alloc(sizeof(*message));
    if (message == NULL) {
        return ESP_ERR_NO_MEM;
    }

    strlcpy(message->type, type, sizeof(message->type));
    strlcpy(message->payload, payload_json, sizeof(message->payload));
    message->callback = callback;
    message->user_ctx = user_ctx;

    if (xQueueSend(s_worker_queue, &message, pdMS_TO_TICKS(100)) != pdTRUE) {
        secure_free(message, sizeof(*message));
        return ESP_ERR_TIMEOUT;
    }

    return ESP_OK;
}

esp_err_t floraos_client_queue_message(
    const char *type,
    const char *payload_json
)
{
    return floraos_client_queue_message_with_callback(
        type,
        payload_json,
        NULL,
        NULL
    );
}

esp_err_t floraos_client_init(void)
{
    while (1) {
        taskENTER_CRITICAL(&s_init_lock);

        if (s_initialized) {
            taskEXIT_CRITICAL(&s_init_lock);
            return ESP_OK;
        }

        if (!s_initializing) {
            s_initializing = true;
            taskEXIT_CRITICAL(&s_init_lock);
            break;
        }

        taskEXIT_CRITICAL(&s_init_lock);
        vTaskDelay(pdMS_TO_TICKS(10));
    }

    esp_err_t err = floraos_crypto_init();
    if (err == ESP_OK) {
        err = floraos_start_worker();
    }

    taskENTER_CRITICAL(&s_init_lock);
    if (err == ESP_OK) {
        s_initialized = true;
    }
    s_initializing = false;
    taskEXIT_CRITICAL(&s_init_lock);

    if (err != ESP_OK) {
        return err;
    }

    ESP_LOGI(TAG, "FloraOS secure client ready");
    ESP_LOGI(TAG, "Device ID: %s", floraos_crypto_device_id());
    return ESP_OK;
}

bool floraos_client_is_ready(void)
{
    return s_initialized && s_worker_queue != NULL && s_worker_task != NULL;
}

const char *floraos_client_device_id(void)
{
    return floraos_crypto_device_id();
}

esp_err_t floraos_client_send_message(
    const char *type,
    const char *payload_json,
    char *response_plaintext,
    size_t response_capacity
)
{
    if (!s_initialized || type == NULL || payload_json == NULL) {
        return ESP_ERR_INVALID_STATE;
    }

    esp_err_t err = ESP_OK;
    esp_http_client_handle_t client = NULL;

    char *plaintext = floraos_alloc(MAX_PLAINTEXT);
    uint8_t *ciphertext = floraos_alloc(MAX_CIPHERTEXT);
    char *ciphertext_hex = floraos_alloc(MAX_CIPHERTEXT * 2 + 1);
    char *body = floraos_alloc(MAX_OUTER_JSON);
    http_response_buffer_t *response = floraos_alloc(sizeof(*response));
    char *response_nonce_hex = floraos_alloc(FLORAOS_NONCE_LEN * 2 + 1);
    char *response_ciphertext_hex = floraos_alloc(MAX_HTTP_RESPONSE);
    uint8_t *response_ciphertext = floraos_alloc(MAX_HTTP_RESPONSE / 2);
    uint8_t *decrypted = floraos_alloc(MAX_HTTP_RESPONSE / 2);

    if (plaintext == NULL || ciphertext == NULL || ciphertext_hex == NULL ||
        body == NULL || response == NULL || response_nonce_hex == NULL ||
        response_ciphertext_hex == NULL || response_ciphertext == NULL ||
        decrypted == NULL) {
        err = ESP_ERR_NO_MEM;
        goto cleanup;
    }

    uint8_t message_id[FLORAOS_MESSAGE_ID_LEN];
    uint8_t nonce[FLORAOS_NONCE_LEN];
    char message_id_hex[FLORAOS_MESSAGE_ID_LEN * 2 + 1];
    char nonce_hex[FLORAOS_NONCE_LEN * 2 + 1];

    err = floraos_crypto_random(message_id, sizeof(message_id));
    if (err != ESP_OK) goto cleanup;

    err = floraos_crypto_random(nonce, sizeof(nonce));
    if (err != ESP_OK) goto cleanup;

    floraos_hex_encode(message_id, sizeof(message_id), message_id_hex);
    floraos_hex_encode(nonce, sizeof(nonce), nonce_hex);

    time_t now = time(NULL);
    long long unix_time = (now > 1700000000) ? (long long)now : 0;

    int plaintext_len = snprintf(
        plaintext,
        MAX_PLAINTEXT,
        "{\"message_id\":\"%s\",\"ts\":%lld,\"type\":\"%s\",\"payload\":%s}",
        message_id_hex,
        unix_time,
        type,
        payload_json
    );
    if (plaintext_len <= 0 || plaintext_len >= MAX_PLAINTEXT) {
        err = ESP_ERR_INVALID_SIZE;
        goto cleanup;
    }

    char aad[192];
    err = make_aad("d2s", aad, sizeof(aad));
    if (err != ESP_OK) goto cleanup;

    size_t ciphertext_len = 0;
    err = floraos_crypto_encrypt_d2s(
        nonce,
        (const uint8_t *)aad,
        strlen(aad),
        (const uint8_t *)plaintext,
        (size_t)plaintext_len,
        ciphertext,
        MAX_CIPHERTEXT,
        &ciphertext_len
    );
    if (err != ESP_OK) goto cleanup;

    floraos_hex_encode(ciphertext, ciphertext_len, ciphertext_hex);

    int body_len = snprintf(
        body,
        MAX_OUTER_JSON,
        "{\"v\":%d,\"device_id\":\"%s\",\"nonce\":\"%s\",\"ciphertext\":\"%s\"}",
        FLORAOS_PROTOCOL_VERSION,
        floraos_crypto_device_id(),
        nonce_hex,
        ciphertext_hex
    );
    if (body_len <= 0 || body_len >= MAX_OUTER_JSON) {
        err = ESP_ERR_INVALID_SIZE;
        goto cleanup;
    }

    esp_http_client_config_t config = {
        .url = FLORAOS_ENDPOINT,
        .method = HTTP_METHOD_POST,
        .timeout_ms = 12000,
        .crt_bundle_attach = esp_crt_bundle_attach,
        .event_handler = http_event_handler,
        .user_data = response,
    };

    client = esp_http_client_init(&config);
    if (client == NULL) {
        err = ESP_ERR_NO_MEM;
        goto cleanup;
    }

    ESP_ERROR_CHECK_WITHOUT_ABORT(
        esp_http_client_set_header(client, "Content-Type", "application/json")
    );
    ESP_ERROR_CHECK_WITHOUT_ABORT(
        esp_http_client_set_header(client, "User-Agent", "FloraCore-ESP32S3/1")
    );
    esp_http_client_set_post_field(client, body, body_len);

    err = esp_http_client_perform(client);
    if (err != ESP_OK) {
        goto cleanup;
    }

    int status_code = esp_http_client_get_status_code(client);
    if (status_code < 200 || status_code >= 300 || response->overflowed) {
        ESP_LOGW(TAG, "FloraOS HTTP status=%d", status_code);
        err = ESP_FAIL;
        goto cleanup;
    }

    if (!json_get_string(
            response->data,
            "nonce",
            response_nonce_hex,
            FLORAOS_NONCE_LEN * 2 + 1
        ) ||
        !json_get_string(
            response->data,
            "ciphertext",
            response_ciphertext_hex,
            MAX_HTTP_RESPONSE
        )) {
        err = ESP_ERR_INVALID_RESPONSE;
        goto cleanup;
    }

    uint8_t response_nonce[FLORAOS_NONCE_LEN];
    size_t response_nonce_len = 0;
    err = floraos_hex_decode(
        response_nonce_hex,
        response_nonce,
        sizeof(response_nonce),
        &response_nonce_len
    );
    if (err != ESP_OK || response_nonce_len != FLORAOS_NONCE_LEN) {
        err = ESP_ERR_INVALID_RESPONSE;
        goto cleanup;
    }

    size_t response_ciphertext_len = 0;
    err = floraos_hex_decode(
        response_ciphertext_hex,
        response_ciphertext,
        MAX_HTTP_RESPONSE / 2,
        &response_ciphertext_len
    );
    if (err != ESP_OK) goto cleanup;

    char response_aad[192];
    err = make_aad("s2d", response_aad, sizeof(response_aad));
    if (err != ESP_OK) goto cleanup;

    size_t decrypted_len = 0;
    err = floraos_crypto_decrypt_s2d(
        response_nonce,
        (const uint8_t *)response_aad,
        strlen(response_aad),
        response_ciphertext,
        response_ciphertext_len,
        decrypted,
        (MAX_HTTP_RESPONSE / 2) - 1,
        &decrypted_len
    );
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "response authentication failed");
        goto cleanup;
    }

    decrypted[decrypted_len] = '\0';
    ESP_LOGI(TAG, "Authenticated FloraOS response received");

    if (response_plaintext != NULL && response_capacity > 0) {
        size_t copy_len =
            decrypted_len < response_capacity - 1
            ? decrypted_len
            : response_capacity - 1;
        memcpy(response_plaintext, decrypted, copy_len);
        response_plaintext[copy_len] = '\0';
    }

cleanup:
    if (client != NULL) {
        esp_http_client_cleanup(client);
    }

    secure_free(plaintext, MAX_PLAINTEXT);
    secure_free(ciphertext, MAX_CIPHERTEXT);
    secure_free(ciphertext_hex, MAX_CIPHERTEXT * 2 + 1);
    secure_free(body, MAX_OUTER_JSON);
    secure_free(response, sizeof(*response));
    secure_free(response_nonce_hex, FLORAOS_NONCE_LEN * 2 + 1);
    secure_free(response_ciphertext_hex, MAX_HTTP_RESPONSE);
    secure_free(response_ciphertext, MAX_HTTP_RESPONSE / 2);
    secure_free(decrypted, MAX_HTTP_RESPONSE / 2);

    return err;
}
