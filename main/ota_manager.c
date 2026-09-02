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
            expected_version,
            candidate->version
        );

        return ESP_ERR_INVALID_VERSION;
    }

    if (
        compare_stable_semver(
            candidate->version,
            running->version
        ) <= 0
    ) {
        ESP_LOGE(
            TAG,
            "Rejecting OTA image: candidate %s is not newer than running %s",
            candidate->version,
            running->version
        );

        return ESP_ERR_INVALID_VERSION;
    }

    return ESP_OK;
}


static void ota_update_task(void *parameter)
{
    ota_update_request_t *request =
        (ota_update_request_t *)parameter;

    if (request == NULL) {
        set_update_in_progress(false);
        vTaskDelete(NULL);
        return;
    }

    esp_https_ota_handle_t ota_handle = NULL;
    bool ota_started = false;
    esp_err_t final_err = ESP_FAIL;

    ESP_LOGI(
        TAG,
        "Starting HTTPS OTA to expected version %s",
        request->expected_version
    );

    const esp_partition_t *next_partition =
        esp_ota_get_next_update_partition(NULL);

    if (next_partition == NULL) {
        ESP_LOGE(
            TAG,
            "No inactive OTA application partition is available"
        );

        final_err = ESP_ERR_NOT_FOUND;
        goto cleanup;
    }

    ESP_LOGI(
        TAG,
        "Inactive OTA target: %s @ 0x%08lx (%lu bytes)",
        next_partition->label,
        (unsigned long)next_partition->address,
        (unsigned long)next_partition->size
    );

    esp_http_client_config_t http_config = {
        .url = request->url,
        .crt_bundle_attach = esp_crt_bundle_attach,
        .timeout_ms = OTA_HTTP_TIMEOUT_MS,
        .disable_auto_redirect = true,
        .keep_alive_enable = true,
    };

    esp_https_ota_config_t ota_config = {
        .http_config = &http_config,
        .bulk_flash_erase = false,
    };

    final_err =
        esp_https_ota_begin(
            &ota_config,
            &ota_handle
        );

    if (final_err != ESP_OK) {
        ESP_LOGE(
            TAG,
            "esp_https_ota_begin failed: %s",
            esp_err_to_name(final_err)
        );

        goto cleanup;
    }

    ota_started = true;

    int status_code =
        esp_https_ota_get_status_code(
            ota_handle
        );

    if (status_code != 200) {
        ESP_LOGE(
            TAG,
            "OTA server returned HTTP %d; redirects and non-200 responses are rejected",
            status_code
        );

        final_err = ESP_FAIL;
        goto cleanup;
    }

    esp_app_desc_t candidate = {0};

    final_err =
        esp_https_ota_get_img_desc(
            ota_handle,
            &candidate
        );

    if (final_err != ESP_OK) {
        ESP_LOGE(
            TAG,
            "Could not read OTA image descriptor: %s",
            esp_err_to_name(final_err)
        );

        goto cleanup;
    }

    final_err =
        validate_candidate_description(
            &candidate,
            request->expected_version
        );

    if (final_err != ESP_OK) {
        goto cleanup;
    }

    int image_size =
        esp_https_ota_get_image_size(
            ota_handle
        );

    if (image_size > 0) {
        ESP_LOGI(
            TAG,
            "OTA image size: %d bytes",
            image_size
        );

        if (
            (uint64_t)image_size >
            (uint64_t)next_partition->size
        ) {
            ESP_LOGE(
                TAG,
                "OTA image is larger than inactive partition"
            );

            final_err = ESP_ERR_INVALID_SIZE;
            goto cleanup;
        }
    } else {
        ESP_LOGW(
            TAG,
            "OTA server did not provide a fixed image length; partition bounds remain enforced by ESP-IDF"
        );
    }

    int last_progress = -OTA_PROGRESS_STEP_PERCENT;

    while (1) {
        esp_err_t perform_err =
            esp_https_ota_perform(
                ota_handle
            );

        int bytes_read =
            esp_https_ota_get_image_len_read(
                ota_handle
            );

        if (
            image_size > 0 &&
            bytes_read >= 0
        ) {
            int progress =
                (int)(
                    ((int64_t)bytes_read * 100LL) /
                    image_size
                );

            if (
                progress >= 100 ||
                progress - last_progress >=
                    OTA_PROGRESS_STEP_PERCENT
            ) {
                if (progress > 100) {
                    progress = 100;
                }

                ESP_LOGI(
                    TAG,
                    "OTA progress: %d%% (%d/%d bytes)",
                    progress,
                    bytes_read,
                    image_size
                );

                last_progress = progress;
            }
        } else if (bytes_read >= 0) {
            ESP_LOGD(
                TAG,
                "OTA downloaded: %d bytes",
                bytes_read
            );
        }

        if (
            perform_err ==
            ESP_ERR_HTTPS_OTA_IN_PROGRESS
        ) {
            continue;
        }

        final_err = perform_err;
        break;
    }

    if (final_err != ESP_OK) {
        ESP_LOGE(
            TAG,
            "OTA download/write failed: %s",
            esp_err_to_name(final_err)
        );

        goto cleanup;
    }

    if (
        !esp_https_ota_is_complete_data_received(
            ota_handle
        )
    ) {
        E