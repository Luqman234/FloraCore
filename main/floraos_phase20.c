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

    uint8_t slot = (uint8_t)(head % PHASE20_DEDUPE_SLOTS);
    err = write_record_locked(slot, command_id, RECORD_INFLIGHT, NULL, 0);
    if (err != ESP_OK) return err;

    head = (uint8_t)((slot + 1U) % PHASE20_DEDUPE_SLOTS);
    err = nvs_set_u8(s_nvs, "head", head);
    if (err != ESP_OK) return err;
    err = nvs_commit(s_nvs);
    if (err != ESP_OK) return err;

    if (slot_out != NULL) *slot_out = slot;
    return ESP_OK;
}

static esp_err_t update_record_locked(
    const char *command_id,
    record_status_t status,
    const char *error,
    uint32_t actual_duration_ms
)
{
    dedupe_record_t existing;
    if (!find_record_locked(command_id, &existing)) {
        uint8_t slot = 0;
        esp_err_t err = create_inflight_record_locked(command_id, &slot);
        if (err != ESP_OK) return err;
        return write_record_locked(slot, command_id, status, error, actual_duration_ms);
    }

    return write_record_locked(
        existing.slot,
        command_id,
        status,
        error,
        actual_duration_ms
    );
}

static void recover_inflight_records_locked(void)
{
    for (uint8_t slot = 0; slot < PHASE20_DEDUPE_SLOTS; slot++) {
        char command_id[PHASE20_COMMAND_ID_MAX + 1] = {0};
        if (!read_slot_id_locked(slot, command_id, sizeof(command_id))) {
            continue;
        }

        char key[16];
        uint8_t status = RECORD_NONE;
        make_slot_key(key, sizeof(key), "st", slot);

        if (nvs_get_u8(s_nvs, key, &status) != ESP_OK) {
            continue;
        }

        if (status == RECORD_INFLIGHT) {
            /*
             * A reboot may have happened after physical actuation started but
             * before a terminal result was persisted. Fail closed: never replay
             * that command ID after reboot.
             */
            (void)write_record_locked(
                slot,
                command_id,
                RECORD_FAILED,
                "local_safety_lockout",
                0
            );
        }
    }
}

static esp_err_t queue_command_result_json(cJSON *payload)
{
    if (payload == NULL) return ESP_ERR_INVALID_ARG;

    char *text = cJSON_PrintUnformatted(payload);
    if (text == NULL) return ESP_ERR_NO_MEM;

    /*
     * Do not attach the command-response callback to command_result itself.
     * The next heartbeat/telemetry is the next command-delivery opportunity;
     * this avoids an accidental response/result feedback loop.
     */
    esp_err_t err = floraos_client_queue_message("command_result", text);
    free(text);
    return err;
}

static esp_err_t send_acknowledged(const char *command_id, uint64_t accepted_at_ms)
{
    cJSON *root = cJSON_CreateObject();
    cJSON *result = cJSON_CreateObject();
    if (root == NULL || result == NULL) {
        cJSON_Delete(root);
        cJSON_Delete(result);
        return ESP_ERR_NO_MEM;
    }

    cJSON_AddStringToObject(root, "command_id", command_id);
    cJSON_AddStringToObject(root, "status", "acknowledged");
    cJSON_AddNumberToObject(result, "accepted_at_ms", (double)accepted_at_ms);
    cJSON_AddItemToObject(root, "result", result);

    esp_err_t err = queue_command_result_json(root);
    cJSON_Delete(root);
    return err;
}

static esp_err_t send_completed(
    const char *command_id,
    uint64_t started_at_ms,
    uint64_t finished_at_ms,
    uint32_t actual_duration_ms,
    uint32_t armed_duration_seconds
)
{
    cJSON *root = cJSON_CreateObject();
    cJSON *result = cJSON_CreateObject();
    if (root == NULL || result == NULL) {
        cJSON_Delete(root);
        cJSON_Delete(result);
        return ESP_ERR_NO_MEM;
    }

    cJSON_AddStringToObject(root, "command_id", command_id);
    cJSON_AddStringToObject(root, "status", "completed");
    cJSON_AddNumberToObject(result, "started_at_ms", (double)started_at_ms);
    cJSON_AddNumberToObject(result, "finished_at_ms", (double)finished_at_ms);
    cJSON_AddNumberToObject(result, "actual_duration_ms", (double)actual_duration_ms);

    if (armed_duration_seconds > 0) {
        cJSON_AddNumberToObject(
            result,
            "armed_duration_seconds",
            (double)armed_duration_seconds
        );
    }

    cJSON_AddItemToObject(root, "result", result);

    esp_err_t err = queue_command_result_json(root);
    cJSON_Delete(root);
    return err;
}

static esp_err_t send_failed(const char *command_id, const char *error)
{
    cJSON *root = cJSON_CreateObject();
    if (root == NULL) return ESP_ERR_NO_MEM;

    cJSON_AddStringToObject(root, "command_id", command_id);
    cJSON_AddStringToObject(root, "status", "failed");
    cJSON_AddStringToObject(
        root,
        "error",
        (error != NULL && error[0] != '\0') ? error : "local_safety_lockout"
    );

    esp_err_t err = queue_command_result_json(root);
    cJSON_Delete(root);
    return err;
}

static bool setup_blocked_now(void)
{
    return s_ops.setup_blocked != NULL && s_ops.setup_blocked();
}

static bool ota_in_progress_now(void)
{
    return s_ops.ota_in_progress != NULL && s_ops.ota_in_progress();
}

static bool water_lockout_now(void)
{
    bool locked = true;

    if (s_lock != NULL && xSemaphoreTake(s_lock, portMAX_DELAY) == pdTRUE) {
        locked = s_water_lockout;
        xSemaphoreGive(s_lock);
    }

    return locked;
}

static void clear_active_command(const char *command_id)
{
    if (s_lock == NULL) return;

    if (xSemaphoreTake(s_lock, portMAX_DELAY) == pdTRUE) {
        if (
            command_id != NULL &&
            strcmp(s_active_command_id, command_id) == 0
        ) {
            s_active_command_id[0] = '\0';
            s_active_action = 0;
        }
        xSemaphoreGive(s_lock);
    }
}

static void finish_failed(const char *command_id, const char *error)
{
    if (s_lock != NULL && xSemaphoreTake(s_lock, portMAX_DELAY) == pdTRUE) {
        (void)update_record_locked(command_id, RECORD_FAILED, error, 0);
        xSemaphoreGive(s_lock);
    }

    (void)send_failed(command_id, error);
    clear_active_command(command_id);
}

static void finish_completed(
    const char *command_id,
    uint64_t started_at_ms,
    uint64_t finished_at_ms,
    uint32_t actual_duration_ms,
    uint32_t armed_duration_seconds
)
{
    if (s_lock != NULL && xSemaphoreTake(s_lock, portMAX_DELAY) == pdTRUE) {
        (void)update_record_locked(
            command_id,
            RECORD_COMPLETED,
            NULL,
            actual_duration_ms
        );
        xSemaphoreGive(s_lock);
    }

    (void)send_completed(
        command_id,
        started_at_ms,
        finished_at_ms,
        actual_duration_ms,
        armed_duration_seconds
    );

    clear_active_command(command_id);
}

#ifdef CONFIG_FLORACORE_GROW_LIGHT_ENABLE
static void grow_light_auto_off(void *argument)
{
    (void)argument;

    if (s_initialized && s_ops.grow_light_set != NULL) {
        (void)s_ops.grow_light_set(false);
    }
}
#endif

static void command_task(void *argument)
{
    (void)argument;

    while (1) {
        command_action_t action;
        memset(&action, 0, sizeof(action));

        if (xQueueReceive(s_command_queue, &action, portMAX_DELAY) != pdTRUE) {
            continue;
        }

        if (setup_blocked_now()) {
            finish_failed(action.command_id, "setup_in_progress");
            continue;
        }

        if (ota_in_progress_now()) {
            finish_failed(action.command_id, "ota_in_progress");
            continue;
        }

        if (action.type == ACTION_WATER) {
            if (water_lockout_now()) {
                finish_failed(action.command_id, "local_safety_lockout");
                continue;
            }

            uint64_t started_at_ms = monotonic_ms();

            if (s_ops.water_set == NULL || s_ops.water_set(true) != ESP_OK) {
                if (s_ops.water_set != NULL) (void)s_ops.water_set(false);
                finish_failed(action.command_id, "actuator_fault");
                continue;
            }

            const uint64_t target_ms = action.duration;
            bool aborted = false;
            const char *abort_error = NULL;

            while (monotonic_ms() - started_at_ms < target_ms) {
                if (setup_blocked_now()) {
                    aborted = true;
                    abort_error = "setup_in_progress";
                    break;
                }

                if (ota_in_progress_now()) {
                    aborted = true;
                    abort_error = "ota_in_progress";
                    break;
                }

                if (water_lockout_now()) {
                    aborted = true;
                    abort_error = "local_safety_lockout";
                    break;
                }

                vTaskDelay(pdMS_TO_TICKS(25));
            }

            esp_err_t off_err = s_ops.water_set(false);
            uint64_t finished_at_ms = monotonic_ms();

            if (off_err != ESP_OK) {
                finish_failed(action.command_id, "actuator_fault");
                continue;
            }

            if (aborted) {
                finish_failed(action.command_id, abort_error);
                continue;
            }

            uint64_t measured = finished_at_ms - started_at_ms;
            if (measured > UINT32_MAX) measured = UINT32_MAX;

            finish_completed(
                action.command_id,
                started_at_ms,
                finished_at_ms,
                (uint32_t)measured,
                0
            );
            continue;
        }

#ifdef CONFIG_FLORACORE_GROW_LIGHT_ENABLE
        if (
            action.type == ACTION_GROW_LIGHT_ON ||
            action.type == ACTION_GROW_LIGHT_OFF
        ) {
            if (s_ops.grow_light_set == NULL) {
                finish_failed(action.command_id, "actuator_fault");
                continue;
            }

            uint64_t started_at_ms = monotonic_ms();

            if (s_grow_light_timer != NULL) {
                (void)esp_timer_stop(s_grow_light_timer);
            }

            bool turn_on = action.type == ACTION_GROW_LIGHT_ON;
            if (s_ops.grow_light_set(turn_on) != ESP_OK) {
                (void)s_ops.grow_light_set(false);
                finish_failed(action.command_id, "actuator_fault");
                continue;
            }

            if (turn_on) {
                esp_err_t timer_err = esp_timer_start_once(
                    s_grow_light_timer,
                    (uint64_t)action.duration * 1000000ULL
                );

                if (timer_err != ESP_OK) {
                    (void)s_ops.grow_light_set(false);
                    finish_failed(action.command_id, "actuator_fault");
                    continue;
                }
            }

            uint64_t finished_at_ms = monotonic_ms();
            uint64_t measured = finished_at_ms - started_at_ms;
            if (measured > UINT32_MAX) measured = UINT32_MAX;

            /*
             * For grow_light=on, completion means the output changed and the
             * local auto-off timer was successfully armed. It does not wait
             * for the requested hours to elapse.
             */
            finish_completed(
                action.command_id,
                started_at_ms,
                finished_at_ms,
                (uint32_t)measured,
                turn_on ? action.duration : 0
            );
            continue;
        }
#endif

        finish_failed(action.command_id, "invalid_parameters");
    }
}

static bool valid_command_id(const char *command_id)
{
    if (command_id == NULL) return false;

    size_t len = strlen(command_id);
    if (len < 5 || len > PHASE20_COMMAND_ID_MAX) return false;
    return strncmp(command_id, "cmd_", 4) == 0;
}

static bool json_u32(cJSON *object, const char *key, uint32_t *value)
{
    cJSON *item = cJSON_GetObjectItemCaseSensitive(object, key);
    if (!cJSON_IsNumber(item) || item->valuedouble < 0 || item->valuedouble > UINT32_MAX) {
        return false;
    }

    double raw = item->valuedouble;
    uint32_t converted = (uint32_t)raw;
    if ((double)converted != raw) return false;

    *value = converted;
    return true;
}

static void remember_terminal_failure(const char *command_id, const char *error)
{
    if (s_lock != NULL && xSemaphoreTake(s_lock, portMAX_DELAY) == pdTRUE) {
        (void)update_record_locked(command_id, RECORD_FAILED, error, 0);
        xSemaphoreGive(s_lock);
    }
}

static void process_command(cJSON *command, int64_t server_time)
{
    if (!cJSON_IsObject(command)) return;

    cJSON *id_item = cJSON_GetObjectItemCaseSensitive(command, "id");
    cJSON *type_item = cJSON_GetObjectItemCaseSensitive(command, "type");
    cJSON *parameters = cJSON_GetObjectItemCaseSensitive(command, "parameters");
    cJSON *expires_item = cJSON_GetObjectItemCaseSensitive(command, "expires_at");

    if (!cJSON_IsString(id_item) || !valid_command_id(id_item->valuestring)) {
        ESP_LOGW(TAG, "Ignoring command with invalid command_id");
        return;
    }

    const char *command_id = id_item->valuestring;

    dedupe_record_t prior;
    bool same_active = false;
    bool another_active = false;

    if (s_lock != NULL && xSemaphoreTake(s_lock, portMAX_DELAY) == pdTRUE) {
        bool found = find_record_locked(command_id, &prior);
        if (!found) memset(&prior, 0, sizeof(prior));

        if (s_active_command_id[0] != '\0') {
            same_active = strcmp(s_active_command_id, command_id) == 0;
            another_active = !same_active;
        }

        xSemaphoreGive(s_lock);
    } else {
        return;
    }

    if (prior.found) {
        if (prior.status == RECORD_COMPLETED) {
            uint64_t now = monotonic_ms();
            (void)send_completed(
                command_id,
                now,
                now,
                prior.actual_duration_ms,
                0
            );
            return;
        }

        if (prior.status == RECORD_FAILED) {
            (void)send_failed(
                command_id,
                prior.error[0] != '\0'
                    ? prior.error
                    : "local_safety_lockout"
            );
            return;
        }

        if (prior.status == RECORD_INFLIGHT) {
            if (same_active) {
                (void)send_acknowledged(command_id, monotonic_ms());
            } else {
                /* Should only happen after an interrupted/rebooted execution. */
                remember_terminal_failure(command_id, "local_safety_lockout");
                (void)send_failed(command_id, "local_safety_lockout");
            }
            return;
        }
    }

    if (another_active) {
        remember_terminal_failure(command_id, "local_safety_lockout");
        (void)send_failed(command_id, "local_safety_lockout");
        return;
    }

    if (setup_blocked_now()) {
        remember_terminal_failure(command_id, "setup_in_progress");
        (void)send_failed(command_id, "setup_in_progress");
        return;
    }

    if (ota_in_progress_now()) {
        remember_terminal_failure(command_id, "ota_in_progress");
        (void)send_failed(command_id, "ota_in_progress");
        return;
    }

    if (
        !cJSON_IsNumber(expires_item) ||
        expires_item->valuedouble < 0 ||
        server_time < 0
    ) {
        remember_terminal_failure(command_id, "invalid_parameters");
        (void)send_failed(command_id, "invalid_parameters");
        return;
    }

    int64_t expires_at = (int64_t)expires_item->valuedouble;
    if ((double)expires_at != expires_item->valuedouble || expires_at <= server_time) {
        remember_terminal_failure(command_id, "invalid_parameters");
        (void)send_failed(command_id, "invalid_parameters");
        return;
    }

    if (!cJSON_IsString(type_item) || !cJSON_IsObject(parameters)) {
        remember_terminal_failure(command_id, "invalid_parameters");
        (void)send_failed(command_id, "invalid_parameters");
        return;
    }

    command_action_t action;
    memset(&action, 0, sizeof(action));
    strlcpy(action.command_id, command_id, sizeof(action.command_id));
    action.accepted_at_ms = monotonic_ms();

    if (strcmp(type_item->valuestring, "water") == 0) {
        uint32_t duration_ms = 0;
        if (
            !json_u32(parameters, "duration_ms", &duration_ms) ||
            duration_ms < PHASE20_WATER_MIN_MS ||
            duration_ms > PHASE20_WATER_MAX_MS
        ) {
            remember_terminal_failure(command_id, "invalid_parameters");
            (void)send_failed(command_id, "invalid_parameters");
            return;
        }

        if (water_lockout_now()) {
            remember_terminal_failure(command_id, "local_safety_lockout");
            (void)send_failed(command_id, "local_safety_lockout");
            return;
        }

        /*
         * Do not claim a bounded cloud watering duration when the local
         * controller had already energized the pump before this command.
         */
        if (s_ops.water_get != NULL && s_ops.water_get()) {
            remember_terminal_failure(command_id, "local_safety_lockout");
            (void)send_failed(command_id, "local_safety_lockout");
            return;
        }

        action.type = ACTION_WATER;
        action.duration = duration_ms;
    } else if (strcmp(type_item->valuestring, "grow_light") == 0) {
#ifdef CONFIG_FLORACORE_GROW_LIGHT_ENABLE
        cJSON *state = cJSON_GetObjectItemCaseSensitive(parameters, "state");
        if (!cJSON_IsString(state)) {
            remember_terminal_failure(command_id, "invalid_parameters");
            (void)send_failed(command_id, "invalid_parameters");
            return;
        }

        if (strcmp(state->valuestring, "off") == 0) {
            action.type = ACTION_GROW_LIGHT_OFF;
            action.duration = 0;
        } else if (strcmp(state->valuestring, "on") == 0) {
            uint32_t duration_seconds = 0;
            if (
                !json_u32(parameters, "duration_seconds", &duration_seconds) ||
                duration_seconds < PHASE20_GROW_LIGHT_MIN_SECONDS ||
                duration_seconds > PHASE20_GROW_LIGHT_MAX_SECONDS
            ) {
                remember_terminal_failure(command_id, "invalid_parameters");
                (void)send_failed(command_id, "invalid_parameters");
                return;
            }

            action.type = ACTION_GROW_LIGHT_ON;
            action.duration = duration_seconds;
        } else {
            remember_terminal_failure(command_id, "invalid_parameters");
            (void)send_failed(command_id, "invalid_parameters");
            return;
        }
#else
        remember_terminal_failure(command_id, "local_safety_lockout");
        (void)send_failed(command_id, "local_safety_lockout");
        return;
#endif
    } else {
        /* Includes fertilize until its physical local-safety implementation exists. */
        remember_terminal_failure(command_id, "invalid_parameters");
        (void)send_failed(command_id, "invalid_parameters");
        return;
    }

    esp_err_t persist_err = ESP_FAIL;

    if (xSemaphoreTake(s_lock, portMAX_DELAY) == pdTRUE) {
        persist_err = create_inflight_record_locked(command_id, NULL);
        if (persist_err == ESP_OK) {
            strlcpy(
                s_active_command_id,
                command_id,
                sizeof(s_active_command_id)
            );
            s_active_action = action.type;
        }
        xSemaphoreGive(s_lock);
    }

    if (persist_err != ESP_OK) {
        ESP_LOGE(TAG, "Could not persist command dedupe record: %s", esp_err_to_name(persist_err));
        (void)send_failed(command_id, "local_safety_lockout");
        return;
    }

    (void)send_acknowledged(command_id, action.accepted_at_ms);

    if (xQueueSend(s_command_queue, &action, 0) != pdTRUE) {
        finish_failed(command_id, "actuator_fault");
        return;
    }
}

static void response_callback(
    esp_err_t result,
    const char *response_plaintext,
    void *user_ctx
)
{
    (void)user_ctx;

    if (result != ESP_OK || response_plaintext == NULL || response_plaintext[0] == '\0') {
        return;
    }

    cJSON *root = cJSON_Parse(response_plaintext);
    if (!cJSON_IsObject(root)) {
        cJSON_Delete(root);
        return;
    }

    cJSON *commands = cJSON_GetObjectItemCaseSensitive(root, "commands");
    if (!cJSON_IsArray(commands) || cJSON_GetArraySize(commands) == 0) {
        cJSON_Delete(root);
        return;
    }

    cJSON *server_time_item = cJSON_GetObjectItemCaseSensitive(root, "server_time");
    int64_t server_time = -1;
    if (cJSON_IsNumber(server_time_item) && server_time_item->valuedouble >= 0) {
        server_time = (int64_t)server_time_item->valuedouble;
        if ((double)server_time != server_time_item->valuedouble) {
            server_time = -1;
        }
    }

    int count = cJSON_GetArraySize(commands);
    if (count > 1) {
        ESP_LOGW(TAG, "Server returned %d commands; protocol v1 executes at most one", count);
    }

    process_command(cJSON_GetArrayItem(commands, 0), server_time);
    cJSON_Delete(root);
}

esp_err_t floraos_phase20_init(const floraos_phase20_ops_t *ops)
{
    if (s_initialized) return ESP_OK;

    if (
        ops == NULL ||
        ops->setup_blocked == NULL ||
        ops->ota_in_progress == NULL ||
        ops->water_set == NULL ||
        ops->water_get == NULL
    ) {
        return ESP_ERR_INVALID_ARG;
    }

#ifdef CONFIG_FLORACORE_GROW_LIGHT_ENABLE
    if (ops->grow_light_set == NULL || ops->grow_light_get == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
#endif

    s_ops = *ops;

    s_lock = xSemaphoreCreateMutex();
    if (s_lock == NULL) return ESP_ERR_NO_MEM;

    esp_err_t err = nvs_open(
        PHASE20_DEDUPE_NAMESPACE,
        NVS_READWRITE,
        &s_nvs
    );
    if (err != ESP_OK) return err;

    s_nvs_open = true;

    if (xSemaphoreTake(s_lock, portMAX_DELAY) == pdTRUE) {
        recover_inflight_records_locked();
        xSemaphoreGive(s_lock);
    }

    s_command_queue = xQueueCreate(
        PHASE20_COMMAND_QUEUE_DEPTH,
        sizeof(command_action_t)
    );
    if (s_command_queue == NULL) return ESP_ERR_NO_MEM;

#ifdef CONFIG_FLORACORE_GROW_LIGHT_ENABLE
    esp_timer_create_args_t timer_args = {
        .callback = grow_light_auto_off,
        .arg = NULL,
        .dispatch_method = ESP_TIMER_TASK,
        .name = "grow_light_off",
        .skip_unhandled_events = true
    };

    err = esp_timer_create(&timer_args, &s_grow_light_timer);
    if (err != ESP_OK) return err;
#endif

    BaseType_t task_ok = xTaskCreate(
        command_task,
        "flora_cmd_v1",
        PHASE20_COMMAND_TASK_STACK,
        NULL,
        PHASE20_COMMAND_TASK_PRIORITY,
        &s_command_task
    );
    if (task_ok != pdPASS) return ESP_ERR_NO_MEM;

    s_initialized = true;
    ESP_LOGI(TAG, "Command protocol v1 ready; fertilizer remains disabled");
    return ESP_OK;
}

bool floraos_phase20_is_ready(void)
{
    return s_initialized;
}

static void add_diagnostics(cJSON *root, bool command_protocol_enabled)
{
    cJSON *diagnostics = cJSON_CreateObject();
    cJSON *faults = cJSON_CreateArray();
    if (diagnostics == NULL || faults == NULL) {
        cJSON_Delete(diagnostics);
        cJSON_Delete(faults);
        return;
    }

    wifi_ap_record_t ap_info;
    memset(&ap_info, 0, sizeof(ap_info));
    if (esp_wifi_sta_get_ap_info(&ap_info) == ESP_OK) {
        cJSON_AddNumberToObject(diagnostics, "wifi_rssi_dbm", ap_info.rssi);
    }

    cJSON_AddNumberToObject(
        diagnostics,
        "uptime_seconds",
        (double)(esp_timer_get_time() / 1000000LL)
    );
    cJSON_AddNumberToObject(
        diagnostics,
        "free_heap_bytes",
        (double)esp_get_free_heap_size()
    );
    cJSON_AddNumberToObject(
        diagnostics,
        "min_free_heap_bytes",
        (double)esp_get_minimum_free_heap_size()
    );

    size_t psram_free = heap_caps_get_free_size(MAL