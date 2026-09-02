#include "floraos_phase20.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sdkconfig.h"

#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "freertos/task.h"

#include "cJSON.h"
#include "esp_app_desc.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "nvs.h"

#include "floraos_client.h"

static const char *TAG = "FLORAOS_PHASE20";

#define PHASE20_COMMAND_PROTOCOL 1
#define PHASE20_CAPABILITY_SCHEMA 1
#define PHASE20_HARDWARE_REVISION "prototype-s3-n16r8"

#define PHASE20_COMMAND_ID_MAX 128
#define PHASE20_COMMAND_QUEUE_DEPTH 4
#define PHASE20_COMMAND_TASK_STACK 7168
#define PHASE20_COMMAND_TASK_PRIORITY 5

#define PHASE20_WATER_MIN_MS 500U
#define PHASE20_WATER_MAX_MS 30000U
#define PHASE20_GROW_LIGHT_MIN_SECONDS 60U
#define PHASE20_GROW_LIGHT_MAX_SECONDS 43200U

#define PHASE20_DEDUPE_NAMESPACE "cmdv1"
#define PHASE20_DEDUPE_SLOTS 8U

typedef enum
{
    RECORD_NONE = 0,
    RECORD_INFLIGHT = 1,
    RECORD_COMPLETED = 2,
    RECORD_FAILED = 3
} record_status_t;

typedef enum
{
    ACTION_WATER = 1,
    ACTION_GROW_LIGHT_ON = 2,
    ACTION_GROW_LIGHT_OFF = 3
} action_type_t;

typedef struct
{
    action_type_t type;
    char command_id[PHASE20_COMMAND_ID_MAX + 1];
    uint32_t duration;
    uint64_t accepted_at_ms;
} command_action_t;

typedef struct
{
    bool found;
    uint8_t slot;
    record_status_t status;
    char error[40];
    uint32_t actual_duration_ms;
} dedupe_record_t;

static bool s_initialized = false;
static floraos_phase20_ops_t s_ops = {0};

static SemaphoreHandle_t s_lock = NULL;
static QueueHandle_t s_command_queue = NULL;
static TaskHandle_t s_command_task = NULL;
#ifdef CONFIG_FLORACORE_GROW_LIGHT_ENABLE
static esp_timer_handle_t s_grow_light_timer = NULL;
#endif
static nvs_handle_t s_nvs = 0;
static bool s_nvs_open = false;

static bool s_water_lockout = false;
static char s_active_command_id[PHASE20_COMMAND_ID_MAX + 1] = {0};
static action_type_t s_active_action = 0;

static uint64_t monotonic_ms(void)
{
    return (uint64_t)(esp_timer_get_time() / 1000LL);
}

static const char *reset_reason_name(esp_reset_reason_t reason)
{
    switch (reason) {
        case ESP_RST_UNKNOWN:   return "UNKNOWN_RESET";
        case ESP_RST_POWERON:   return "POWERON_RESET";
        case ESP_RST_EXT:       return "EXTERNAL_RESET";
        case ESP_RST_SW:        return "SOFTWARE_RESET";
        case ESP_RST_PANIC:     return "PANIC_RESET";
        case ESP_RST_INT_WDT:   return "INT_WDT_RESET";
        case ESP_RST_TASK_WDT:  return "TASK_WDT_RESET";
        case ESP_RST_WDT:       return "WDT_RESET";
        case ESP_RST_DEEPSLEEP: return "DEEPSLEEP_RESET";
        case ESP_RST_BROWNOUT:  return "BROWNOUT_RESET";
        case ESP_RST_SDIO:      return "SDIO_RESET";
        default:                return "OTHER_RESET";
    }
}

static void make_slot_key(char *output, size_t capacity, const char *prefix, uint8_t slot)
{
    snprintf(output, capacity, "%s%u", prefix, (unsigned int)slot);
}

static bool read_slot_id_locked(uint8_t slot, char *output, size_t capacity)
{
    char key[16];
    make_slot_key(key, sizeof(key), "id", slot);

    size_t length = capacity;
    esp_err_t err = nvs_get_str(s_nvs, key, output, &length);
    return err == ESP_OK && output[0] != '\0';
}

static bool find_record_locked(const char *command_id, dedupe_record_t *record)
{
    if (command_id == NULL || record == NULL || !s_nvs_open) {
        return false;
    }

    memset(record, 0, sizeof(*record));

    for (uint8_t slot = 0; slot < PHASE20_DEDUPE_SLOTS; slot++) {
        char stored_id[PHASE20_COMMAND_ID_MAX + 1] = {0};
        if (!read_slot_id_locked(slot, stored_id, sizeof(stored_id))) {
            continue;
        }

        if (strcmp(stored_id, command_id) != 0) {
            continue;
        }

        uint8_t status = RECORD_NONE;
        char key[16];

        make_slot_key(key, sizeof(key), "st", slot);
        if (nvs_get_u8(s_nvs, key, &status) != ESP_OK) {
            status = RECORD_NONE;
        }

        record->found = true;
        record->slot = slot;
        record->status = (record_status_t)status;

        make_slot_key(key, sizeof(key), "du", slot);
        if (nvs_get_u32(s_nvs, key, &record->actual_duration_ms) != ESP_OK) {
            record->actual_duration_ms = 0;
        }

        make_slot_key(key, sizeof(key), "er", slot);
        size_t error_len = sizeof(record->error);
        if (nvs_get_str(s_nvs, key, record->error, &error_len) != ESP_OK) {
            record->error[0] = '\0';
        }

        return true;
    }

    return false;
}

static esp_err_t write_record_locked(
    uint8_t slot,
    const char *command_id,
    record_status_t status,
    const char *error,
    uint32_t actual_duration_ms
)
{
    char key[16];
    esp_err_t err;

    make_slot_key(key, sizeof(key), "id", slot);
    err = nvs_set_str(s_nvs, key, command_id);
    if (err != ESP_OK) return err;

    make_slot_key(key, sizeof(key), "st", slot);
    err = nvs_set_u8(s_nvs, key, (uint8_t)status);
    if (err != ESP_OK) return err;

    make_slot_key(key, sizeof(key), "du", slot);
    err = nvs_set_u32(s_nvs, key, actual_duration_ms);
    if (err != ESP_OK) return err;

    make_slot_key(key, sizeof(key), "er", slot);
    if (error != NULL && error[0] != '\0') {
        err = nvs_set_str(s_nvs, key, error);
    } else {
        err = nvs_erase_key(s_nvs, key);
        if (err == ESP_ERR_NVS_NOT_FOUND) err = ESP_OK;
    }
    if (err != ESP_OK) return err;

    return nvs_commit(s_nvs);
}

static esp_err_t create_inflight_record_locked(const char *command_id, uint8_t *slot_out)
{
    uint8_t head = 0;
    esp_err_t err = nvs_get_u8(s_nvs, "head", &head);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        head = 0;
    } else if (err != ESP_OK) {
        return err;
    }

    uint8_t slot = (uint8_t)(head % PHASE20_DEDU