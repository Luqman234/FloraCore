#include <stdio.h>
#include <string.h>

#include "nvs.h"
#include "esp_err.h"
#include "esp_log.h"

#include "wifi_credentials.h"

static const char *TAG = "WIFI_CREDS";

#define NVS_NAMESPACE "wifi_creds"
#define NVS_COUNT_KEY "count"

known_wifi_t known_networks[MAX_WIFI_NETWORKS];
size_t known_network_count = 0;

static void make_ssid_key(size_t index, char *buffer, size_t buffer_size)
{
    snprintf(buffer, buffer_size, "ssid%u", (unsigned int)index);
}

static void make_password_key(size_t index, char *buffer, size_t buffer_size)
{
    snprintf(buffer, buffer_size, "pass%u", (unsigned int)index);
}

bool wifi_credentials_load(void)
{
    memset(known_networks, 0, sizeof(known_networks));
    known_network_count = 0;

    nvs_handle_t handle;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READONLY, &handle);

    if (err == ESP_ERR_NVS_NOT_FOUND) {
        ESP_LOGW(TAG, "No saved Wi-Fi credential namespace");
        return false;
    }

    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs_open failed: %s", esp_err_to_name(err));
        return false;
    }

    uint8_t stored_count = 0;
    err = nvs_get_u8(handle, NVS_COUNT_KEY, &stored_count);

    if (err == ESP_ERR_NVS_NOT_FOUND) {
        ESP_LOGW(TAG, "No saved Wi-Fi credentials");
        nvs_close(handle);
        return false;
    }

    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to read credential count: %s", esp_err_to_name(err));
        nvs_close(handle);
        return false;
    }

    if (stored_count > MAX_WIFI_NETWORKS) {
        ESP_LOGW(TAG, "Stored count %u exceeds max %d; clamping", stored_count, MAX_WIFI_NETWORKS);
        stored_count = MAX_WIFI_NETWORKS;
    }

    for (size_t storage_index = 0; storage_index < stored_count; storage_index++) {
        char ssid_key[16];
        char password_key[16];
        make_ssid_key(storage_index, ssid_key, sizeof(ssid_key));
        make_password_key(storage_index, password_key, sizeof(password_key));

        known_wifi_t temp = {0};
        size_t ssid_length = sizeof(temp.ssid);
        err = nvs_get_str(handle, ssid_key, temp.ssid, &ssid_length);

        if (err != ESP_OK) {
            ESP_LOGW(TAG, "Skipping invalid credential slot %u (SSID read: %s)",
                     (unsigned int)storage_index, esp_err_to_name(err));
            continue;
        }

        size_t password_length = sizeof(temp.password);
        err = nvs_get_str(handle, password_key, temp.password, &password_length);

        if (err != ESP_OK) {
            ESP_LOGW(TAG, "Skipping invalid credential slot %u (password read: %s)",
                     (unsigned int)storage_index, esp_err_to_name(err));
            continue;
        }

        if (temp.ssid[0] == '\0') {
            ESP_LOGW(TAG, "Skipping empty SSID in slot %u", (unsigned int)storage_index);
            continue;
        }

        known_networks[known_network_count] = temp;
        ESP_LOGI(TAG, "Loaded saved network: %s", known_networks[known_network_count].ssid);
        known_network_count++;
    }

    nvs_close(handle);

    ESP_LOGI(TAG, "%u Wi-Fi credential(s) loaded from NVS",
             (unsigned int)known_network_count);

    return known_network_count > 0;
}

esp_err_t wifi_credentials_save(const char *ssid, const char *password)
{
    if (ssid == NULL || password == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    size_t ssid_length = strlen(ssid);
    size_t password_length = strlen(password);

    if (ssid_length == 0 || ssid_length >= WIFI_SSID_MAX_LEN ||
        password_length >= WIFI_PASSWORD_MAX_LEN) {
        ESP_LOGE(TAG, "Invalid SSID/password length");
        return ESP_ERR_INVALID_ARG;
    }

    nvs_handle_t handle;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &handle);

    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs_open failed: %s", esp_err_to_name(err));
        return err;
    }

    uint8_t stored_count = 0;
    err = nvs_get_u8(handle, NVS_COUNT_KEY, &stored_count);

    if (err == ESP_ERR_NVS_NOT_FOUND) {
        stored_count = 0;
    } else if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to read credential count: %s", esp_err_to_name(err));
        nvs_close(handle);
        return err;
    }

    if (stored_count > MAX_WIFI_NETWORKS) {
        stored_count = MAX_WIFI_NETWORKS;
    }

    int target_index = -1;

    for (size_t i = 0; i < stored_count; i++) {
        char ssid_key[16];
        make_ssid_key(i, ssid_key, sizeof(ssid_key));

        char stored_ssid[WIFI_SSID_MAX_LEN] = {0};
        size_t stored_ssid_length = sizeof(stored_ssid);

        esp_err_t read_err = nvs_get_str(handle, ssid_key, stored_ssid, &stored_ssid_length);

        if (read_err == ESP_OK && strcmp(stored_ssid, ssid) == 0) {
            target_index = (int)i;
            break;
        }
    }

    if (target_index < 0) {
        if (stored_count >= MAX_WIFI_NETWORKS) {
            ESP_LOGE(TAG, "Maximum of %d saved Wi-Fi networks reached", MAX_WIFI_NETWORKS);
            nvs_close(handle);
            return ESP_ERR_NO_MEM;
        }

        target_index = stored_count;
        stored_count++;
    }

    char ssid_key[16];
    char password_key[16];
    make_ssid_key((size_t)target_index, ssid_key, sizeof(ssid_key));
    make_password_key((size_t)target_index, password_key, sizeof(password_key));

    err = nvs_set_str(handle, ssid_key, ssid);
    if (err != ESP_OK) {
        nvs_close(handle);
        return err;
    }

    err = nvs_set_str(handle, password_key, password);
    if (err != ESP_OK) {
        nvs_close(handle);
        return err;
    }

    err = nvs_set_u8(handle, NVS_COUNT_KEY, stored_count);
    if (err != ESP_OK) {
        nvs_close(handle);
        return err;
    }

    err = nvs_commit(handle);
    nvs_close(handle);

    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to commit Wi-Fi credential: %s", esp_err_to_name(err));
        return err;
    }

    ESP_LOGI(TAG, "Saved Wi-Fi credential for SSID: %s", ssid);
    wifi_credentials_load();

    return ESP_OK;
}

esp_err_t wifi_credentials_erase_all(void)
{
    nvs_handle_t handle;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &handle);

    if (err == ESP_ERR_NVS_NOT_FOUND) {
        memset(known_networks, 0, sizeof(known_networks));
        known_network_count = 0;
        return ESP_OK;
    }

    if (err != ESP_OK) {
        return err;
    }

    err = nvs_erase_all(handle);

    if (err == ESP_OK) {
        err = nvs_commit(handle);
    }

    nvs_close(handle);

    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to erase Wi-Fi credentials: %s", esp_err_to_name(err));
        return err;
    }

    memset(known_networks, 0, sizeof(known_networks));
    known_network_count = 0;

    ESP_LOGI(TAG, "All saved Wi-Fi credentials erased");
    return ESP_OK;
}
