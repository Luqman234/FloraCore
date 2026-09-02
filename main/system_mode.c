#include "system_mode.h"

#include <stdint.h>

#include "nvs.h"
#include "esp_log.h"


static const char *TAG = "SYSTEM_MODE";

#define NVS_NAMESPACE "system"
#define NVS_MODE_KEY   "boot_mode"


floracore_mode_t system_mode_load(void)
{
    nvs_handle_t handle;

    esp_err_t err = nvs_open(
        NVS_NAMESPACE,
        NVS_READONLY,
        &handle
    );


    if (
        err == ESP_ERR_NVS_NOT_FOUND
    ) {
        return FLORACORE_MODE_NORMAL;
    }


    if (err != ESP_OK) {
        ESP_LOGW(
            TAG,
            "Could not open system NVS: %s; using NORMAL mode",
            esp_err_to_name(err)
        );

        return FLORACORE_MODE_NORMAL;
    }


    uint8_t stored_mode =
        FLORACORE_MODE_NORMAL;


    err = nvs_get_u8(
        handle,
        NVS_MODE_KEY,
        &stored_mode
    );


    nvs_close(handle);


    if (
        err == ESP_ERR_NVS_NOT_FOUND
    ) {
        return FLORACORE_MODE_NORMAL;
    }


    if (err != ESP_OK) {
        ESP_LOGW(
            TAG,
            "Could not read boot mode: %s; using NORMAL mode",
            esp_err_to_name(err)
        );

        return FLORACORE_MODE_NORMAL;
    }


    if (
        stored_mode != FLORACORE_MODE_NORMAL &&
        stored_mode != FLORACORE_MODE_COM_DEV
    ) {
        ESP_LOGW(
            TAG,
            "Unknown boot mode %u; using NORMAL mode",
            stored_mode
        );

        return FLORACORE_MODE_NORMAL;
    }


    return (floracore_mode_t)stored_mode;
}


esp_err_t system_mode_save(
    floracore_mode_t mode
)
{
    if (
        mode != FLORACORE_MODE_NORMAL &&
        mode != FLORACORE_MODE_COM_DEV
    ) {
        return ESP_ERR_INVALID_ARG;
    }


    nvs_handle_t handle;

    esp_err_t err = nvs_open(
        NVS_NAMESPACE,
        NVS_READWRITE,
        &handle
    );


    if (err != ESP_OK) {
        return err;
    }


    err = nvs_set_u8(
        handle,
        NVS_MODE_KEY,
        (uint8_t)mode
    );


    if (err == ESP_OK) {
        err = nvs_commit(
            handle
        );
    }


    nvs_close(
        handle
    );


    if (err == ESP_OK) {
        ESP_LOGI(
            TAG,
            "Saved boot mode: %s",
            system_mode_name(mode)
        );
    }


    return err;
}


const char *system_mode_name(
    floracore_mode_t mode
)
{
    switch (mode) {
        case FLORACORE_MODE_COM_DEV:
            return "COM DEV";

        case FLORACORE_MODE_NORMAL:
        default:
            return "NORMAL";
    }
}
