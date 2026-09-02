#include "wifi_manager.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/task.h"

#include "esp_err.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "nvs_flash.h"


static const char *TAG = "WIFI_MANAGER";

#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAILED_BIT BIT1

static EventGroupHandle_t wifi_event_group = NULL;
static bool wifi_initialized = false;
static volatile bool s_station_ready = false;
static volatile bool s_setup_ap_active = false;
static volatile uint8_t s_last_disconnect_reason = 0;

typedef struct
{
    size_t credential_index;
    int8_t rssi;
    uint8_t bssid[6];
    uint8_t channel;
} wifi_candidate_t;

static bool valid_ssid(const char *ssid)
{
    if (ssid == NULL) return false;
    size_t len = strlen(ssid);
    return len > 0 && len < WIFI_SSID_MAX_LEN;
}

static bool valid_password(const char *password)
{
    if (password == NULL) return false;
    size_t len = strlen(password);
    return len < WIFI_PASSWORD_MAX_LEN;
}

static void wifi_event_handler(
    void *arg,
    esp_event_base_t event_base,
    int32_t event_id,
    void *event_data
)
{
    (void)arg;

    if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;
        ESP_LOGI(TAG, "Got IP: " IPSTR, IP2STR(&event->ip_info.ip));
        s_station_ready = true;
        xEventGroupSetBits(wifi_event_group, WIFI_CONNECTED_BIT);
        return;
    }

    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        wifi_event_sta_disconnected_t *event =
            (wifi_event_sta_disconnected_t *)event_data;

        s_station_ready = false;
        s_last_disconnect_reason = event != NULL ? event->reason : 0;

        ESP_LOGW(TAG, "Wi-Fi disconnected (reason=%u)", s_last_disconnect_reason);
        xEventGroupSetBits(wifi_event_group, WIFI_FAILED_BIT);
        return;
    }
}

static int find_known_network(const char *ssid)
{
    for (size_t i = 0; i < known_network_count; i++) {
        if (strcmp(ssid, known_networks[i].ssid) == 0) {
            return (int)i;
        }
    }
    return -1;
}

static void sort_candidates(wifi_candidate_t *candidates, size_t count)
{
    for (size_t i = 0; i + 1 < count; i++) {
        for (size_t j = i + 1; j < count; j++) {
            if (candidates[j].rssi > candidates[i].rssi) {
                wifi_candidate_t temp = candidates[i];
                candidates[i] = candidates[j];
                candidates[j] = temp;
            }
        }
    }
}

static size_t scan_known_networks(
    wifi_candidate_t *candidates,
    size_t candidate_capacity
)
{
    if (known_network_count == 0 || candidate_capacity == 0) {
        return 0;
    }

    wifi_scan_config_t scan_config = {
        .ssid = NULL,
        .bssid = NULL,
        .channel = 0,
        .show_hidden = false
    };

    if (esp_wifi_scan_start(&scan_config, true) != ESP_OK) {
        return 0;
    }

    uint16_t ap_count = 0;
    if (esp_wifi_scan_get_ap_num(&ap_count) != ESP_OK || ap_count == 0) {
        return 0;
    }

    wifi_ap_record_t *records = calloc(ap_count, sizeof(*records));
    if (records == NULL) {
        return 0;
    }

    uint16_t record_count = ap_count;
    if (esp_wifi_scan_get_ap_records(&record_count, records) != ESP_OK) {
        free(records);
        return 0;
    }

    bool found[MAX_WIFI_NETWORKS] = {0};
    wifi_candidate_t best[MAX_WIFI_NETWORKS] = {0};

    for (uint16_t i = 0; i < record_count; i++) {
        int known_index = find_known_network((const char *)records[i].ssid);
        if (known_index < 0) continue;

        size_t index = (size_t)known_index;
        if (!found[index] || records[i].rssi > best[index].rssi) {
            found[index] = true;
            best[index].credential_index = index;
            best[index].rssi = records[i].rssi;
            best[index].channel = records[i].primary;
            memcpy(best[index].bssid, records[i].bssid, 6);
        }
    }

    free(records);

    size_t count = 0;
    for (size_t i = 0; i < known_network_count && count < candidate_capacity; i++) {
        if (found[i]) {
            candidates[count++] = best[i];
        }
    }

    sort_candidates(candidates, count);
    return count;
}

static bool connect_to_candidate(const wifi_candidate_t *candidate)
{
    if (candidate == NULL || candidate->credential_index >= known_network_count) {
        return false;
    }

    const known_wifi_t *network =
        &known_networks[candidate->credential_index];

    (void)esp_wifi_disconnect();
    vTaskDelay(pdMS_TO_TICKS(300));

    xEventGroupClearBits(
        wifi_event_group,
        WIFI_CONNECTED_BIT | WIFI_FAILED_BIT
    );

    wifi_config_t config = {0};
    strlcpy((char *)config.sta.ssid, network->ssid, sizeof(config.sta.ssid));
    strlcpy((char *)config.sta.password, network->password, sizeof(config.sta.password));
    memcpy(config.sta.bssid, candidate->bssid, sizeof(config.sta.bssid));
    config.sta.bssid_set = true;
    config.sta.channel = candidate->channel;

    if (esp_wifi_set_config(WIFI_IF_STA, &config) != ESP_OK ||
        esp_wifi_connect() != ESP_OK) {
        return false;
    }

    EventBits_t bits = xEventGroupWaitBits(
        wifi_event_group,
        WIFI_CONNECTED_BIT | WIFI_FAILED_BIT,
        pdTRUE,
        pdFALSE,
        pdMS_TO_TICKS(15000)
    );

    return (bits & WIFI_CONNECTED_BIT) != 0;
}

void wifi_manager_init(void)
{
    if (wifi_initialized) {
        return;
    }

    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES ||
        ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    ESP_ERROR_CHECK(esp_netif_init());

    ret = esp_event_loop_create_def