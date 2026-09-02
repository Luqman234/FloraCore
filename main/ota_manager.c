#include "ota_manager.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "esp_app_desc.h"
#include "esp_crt_bundle.h"
#include "esp_err.h"
#include "esp_http_client.h"
#include "esp_https_ota.h"
#include "esp_log.h"
#include "esp_ota_ops.h"
#include "esp_partition.h"
#include "esp_system.h"


static const char *TAG = "OTA_MANAGER";

#define OTA_ALLOWED_URL_PREFIX \
    "https://floraos.life/firmware/floracore/"

#define OTA_REQUEST_URL_MAX 384
#define OTA_REQUEST_VERSION_MAX 32
#define OTA_TASK_STACK 12288
#define OTA_TASK_PRIORITY 5
#define OTA_HTTP_TIMEOUT_MS 15000
#define OTA_PROGRESS_STEP_PERCENT 10

typedef struct
{
    char url[OTA_REQUEST_URL_MAX];
    char expected_version[OTA_REQUEST_VERSION_MAX];
} ota_update_request_t;

static bool s_initialized = false;
static bool s_pending_verify = false;
static bool s_update_in_progress = false;
static portMUX_TYPE s_update_lock = portMUX_INITIALIZER_UNLOCKED;


static const char *ota_state_name(esp_ota_img_states_t state)
{
    switch (state) {
        case ESP_OTA_IMG_NEW:
            return "NEW";

        case ESP_OTA_IMG_PENDING_VERIFY:
            return "PENDING_VERIFY";

        case ESP_OTA_IMG_VALID:
            return "VALID";

        case ESP_OTA_IMG_INVALID:
            return "INVALID";

        case ESP_OTA_IMG_ABORTED:
            return "ABORTED";

        case ESP_OTA_IMG_UNDEFINED:
        default:
            return "UNDEFINED";
    }
}


static void set_update_in_progress(bool in_progress)
{
    taskENTER_CRITICAL(&s_update_lock);
    s_update_in_progress = in_progress;
    taskEXIT_CRITICAL(&s_update_lock);
}


bool ota_manager_update_in_progress(void)
{
    bool in_progress;

    taskENTER_CRITICAL(&s_update_lock);
    in_progress = s_update_in_progress;
    taskEXIT_CRITICAL(&s_update_lock);

    return in_progress;
}


static bool ota_url_is_allowed(const char *url)
{
    if (url == NULL) {
        return false;
    }

    const size_t prefix_len =
        sizeof(OTA_ALLOWED_URL_PREFIX) - 1;

    return
        strncmp(
            url,
            OTA_ALLOWED_URL_PREFIX,
            prefix_len
        ) == 0 &&
        url[prefix_len] != '\0';
}


static bool parse_semver_core(
    const char *version,
    unsigned long *major,
    unsigned long *minor,
    unsigned long *patch
)
{
    if (
        version == NULL ||
        major == NULL ||
        minor == NULL ||
        patch == NULL
    ) {
        return false;
    }

    char tail = '\0';

    /*
     * FloraCore OTA v1 intentionally accepts the stable X.Y.Z form only.
     * Beta/prerelease channel policy can be added later with the backend
     * rollout design instead of silently inventing SemVer precedence here.
     */
    int matched = sscanf(
        version,
        "%lu.%lu.%lu%c",
        major,
        minor,
        patch,
        &tail
    );

    return matched == 3;
}


static int compare_stable_semver(
    const char *candidate,
    const char *running
)
{
    unsigned long candidate_major = 0;
    unsigned long candidate_minor = 0;
    unsigned long candidate_patch = 0;

    unsigned long running_major = 0;
    unsigned long running_minor = 0;
    unsigned long running_patch = 0;

    if (
        !parse_semver_core(
            candidate,
            &candidate_major,
            &candidate_minor,
            &candidate_patch
        ) ||
        !parse_semver_core(
            running,
            &running_major,
            &running_minor,
            &running_patch
        )
    ) {
        return 0;
    }

    if (candidate_major != running_major) {
        return
            candidate_major > running_major
                ? 1
                : -1;
    }

    if (candidate_minor != running_minor) {
        return
            candidate_minor > running_minor
                ? 1
                : -1;
    }

    if (candidate_patch != running_patch) {
        return
            candidate_patch > running_patch
                ? 1
                : -1;
    }

    return 0;
}


static esp_err_t validate_candidate_description(
    const esp_app_desc_t *candidate,
    const char *expected_version
)
{
    if (
        candidate == NULL ||
        expected_version == NULL
    ) {
        return ESP_ERR_INVALID_ARG;
    }

    const esp_app_desc_t *running =
        esp_app_get_description();

    if (running == NULL) {
        ESP_LOGE(
            TAG,
            "Could not read running application description"
        );

        return ESP_FAIL;
    }

    ESP_LOGI(
        TAG,
        "Running firmware: project=%s version=%s",
        running->project_name,
        running->version
    );

    ESP_LOGI(
        TAG,
        "Candidate firmware: project=%s version=%s",
        candidate->project_name,
        candidate->version
    );

    if (
        strncmp(
            candidate->project_name,
            running->project_name,
            sizeof(candidate->project_name)
        ) != 0
    ) {
        ESP_LOGE(
            TAG,
            "Rejecting OTA image: project name does not match FloraCore"
        );

        return ESP_ERR_OTA_VALIDATE_FAILED;
    }

    if (
        strncmp(
            candidate->version,
            expected_version,
            sizeof(candidate->version)
        ) != 0
    ) {
        ESP_LOGE(
            TAG,
            "Rejecting OTA image: expected version %s but server image is %s",
      