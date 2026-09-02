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

    BaseType_t result = xTaskCreatePinn