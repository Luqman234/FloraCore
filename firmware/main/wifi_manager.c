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

    ret = esp_event_loop_create_default();
    if (ret != ESP_OK && ret != ESP_ERR_INVALID_STATE) {
        ESP_ERROR_CHECK(ret);
    }

    if (esp_netif_get_handle_from_ifkey("WIFI_STA_DEF") == NULL) {
        esp_netif_create_default_wifi_sta();
    }
    if (esp_netif_get_handle_from_ifkey("WIFI_AP_DEF") == NULL) {
        esp_netif_create_default_wifi_ap();
    }

    wifi_init_config_t wifi_config = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&wifi_config));

    wifi_event_group = xEventGroupCreate();
    if (wifi_event_group == NULL) {
        abort();
    }

    ESP_ERROR_CHECK(
        esp_event_handler_register(
            WIFI_EVENT,
            ESP_EVENT_ANY_ID,
            wifi_event_handler,
            NULL
        )
    );
    ESP_ERROR_CHECK(
        esp_event_handler_register(
            IP_EVENT,
            IP_EVENT_STA_GOT_IP,
            wifi_event_handler,
            NULL
        )
    );

    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_start());

    wifi_initialized = true;
    ESP_LOGI(TAG, "Wi-Fi + NVS initialized");
}

bool wifi_manager_connect(void)
{
    if (!wifi_initialized || !wifi_credentials_load()) {
        return false;
    }

    s_station_ready = false;

    wifi_candidate_t candidates[MAX_WIFI_NETWORKS] = {0};
    size_t count = scan_known_networks(candidates, MAX_WIFI_NETWORKS);

    for (size_t i = 0; i < count; i++) {
        size_t index = candidates[i].credential_index;
        const char *ssid = known_networks[index].ssid;

        if (!connect_to_candidate(&candidates[i])) {
            continue;
        }

        /*
         * Association + DHCP is the Wi-Fi manager's responsibility.
         * Do not depend on Google, ICMP, or any third-party connectivity
         * probe. FloraOS HTTPS requests determine service reachability.
         */
        ESP_LOGI(TAG, "Wi-Fi ready on %s; FloraOS will verify service reachability", ssid);
        return true;
    }

    return false;
}

bool wifi_manager_station_ready(void)
{
    return s_station_ready;
}

bool wifi_manager_internet_available(void)
{
    return wifi_manager_station_ready();
}

uint8_t wifi_manager_last_disconnect_reason(void)
{
    return s_last_disconnect_reason;
}

esp_err_t wifi_manager_scan_visible(
    wifi_manager_scan_result_t *results,
    size_t capacity,
    size_t *out_count
)
{
    if (!wifi_initialized || results == NULL ||
        out_count == NULL || capacity == 0) {
        return ESP_ERR_INVALID_ARG;
    }

    *out_count = 0;
    memset(results, 0, capacity * sizeof(*results));

    wifi_scan_config_t scan_config = {
        .ssid = NULL,
        .bssid = NULL,
        .channel = 0,
        .show_hidden = false
    };

    esp_err_t err = esp_wifi_scan_start(&scan_config, true);
    if (err != ESP_OK) return err;

    uint16_t ap_count = 0;
    err = esp_wifi_scan_get_ap_num(&ap_count);
    if (err != ESP_OK || ap_count == 0) return err;

    if (ap_count > 64) ap_count = 64;

    wifi_ap_record_t *records = calloc(ap_count, sizeof(*records));
    if (records == NULL) return ESP_ERR_NO_MEM;

    uint16_t record_count = ap_count;
    err = esp_wifi_scan_get_ap_records(&record_count, records);
    if (err != ESP_OK) {
        free(records);
        return err;
    }

    size_t count = 0;

    for (uint16_t i = 0; i < record_count; i++) {
        const char *raw_ssid = (const char *)records[i].ssid;
        size_t ssid_len = strnlen(raw_ssid, 32);

        if (ssid_len == 0) continue;
        if (ssid_len >= 10 && memcmp(raw_ssid, "FloraCore-", 10) == 0) {
            continue;
        }

        char ssid[WIFI_SSID_MAX_LEN] = {0};
        memcpy(ssid, raw_ssid, ssid_len);

        size_t existing = count;
        for (size_t j = 0; j < count; j++) {
            if (strcmp(results[j].ssid, ssid) == 0) {
                existing = j;
                break;
            }
        }

        if (existing < count) {
            if (records[i].rssi > results[existing].rssi) {
                results[existing].rssi = records[i].rssi;
                results[existing].secure =
                    records[i].authmode != WIFI_AUTH_OPEN;
            }
            continue;
        }

        if (count >= capacity) continue;

        strlcpy(results[count].ssid, ssid, sizeof(results[count].ssid));
        results[count].rssi = records[i].rssi;
        results[count].secure = records[i].authmode != WIFI_AUTH_OPEN;
        count++;
    }

    free(records);

    for (size_t i = 0; i + 1 < count; i++) {
        for (size_t j = i + 1; j < count; j++) {
            if (results[j].rssi > results[i].rssi) {
                wifi_manager_scan_result_t temp = results[i];
                results[i] = results[j];
                results[j] = temp;
            }
        }
    }

    *out_count = count;
    return ESP_OK;
}

static wifi_manager_connect_result_t classify_disconnect(void)
{
    switch (s_last_disconnect_reason) {
        case WIFI_REASON_AUTH_EXPIRE:
        case WIFI_REASON_AUTH_FAIL:
        case WIFI_REASON_4WAY_HANDSHAKE_TIMEOUT:
        case WIFI_REASON_HANDSHAKE_TIMEOUT:
            return WIFI_MANAGER_CONNECT_AUTH_FAILED;

        case WIFI_REASON_NO_AP_FOUND:
            return WIFI_MANAGER_CONNECT_NO_AP;

        default:
            return WIFI_MANAGER_CONNECT_FAILED;
    }
}

wifi_manager_connect_result_t wifi_manager_connect_credentials(
    const char *ssid,
    const char *password
)
{
    if (!wifi_initialized || !valid_ssid(ssid) || !valid_password(password)) {
        return WIFI_MANAGER_CONNECT_FAILED;
    }

    s_station_ready = false;
    s_last_disconnect_reason = 0;

    wifi_mode_t desired_mode =
        s_setup_ap_active ? WIFI_MODE_APSTA : WIFI_MODE_STA;

    if (esp_wifi_set_mode(desired_mode) != ESP_OK) {
        return WIFI_MANAGER_CONNECT_FAILED;
    }

    (void)esp_wifi_disconnect();
    vTaskDelay(pdMS_TO_TICKS(250));

    xEventGroupClearBits(
        wifi_event_group,
        WIFI_CONNECTED_BIT | WIFI_FAILED_BIT
    );

    wifi_config_t config = {0};
    strlcpy((char *)config.sta.ssid, ssid, sizeof(config.sta.ssid));
    strlcpy((char *)config.sta.password, password, sizeof(config.sta.password));
    config.sta.scan_method = WIFI_ALL_CHANNEL_SCAN;
    config.sta.sort_method = WIFI_CONNECT_AP_BY_SIGNAL;

    esp_err_t err = esp_wifi_set_config(WIFI_IF_STA, &config);
    if (err != ESP_OK) {
        return WIFI_MANAGER_CONNECT_FAILED;
    }

    err = esp_wifi_connect();
    if (err != ESP_OK) {
        return WIFI_MANAGER_CONNECT_FAILED;
    }

    EventBits_t bits = xEventGroupWaitBits(
        wifi_event_group,
        WIFI_CONNECTED_BIT | WIFI_FAILED_BIT,
        pdTRUE,
        pdFALSE,
        pdMS_TO_TICKS(15000)
    );

    if ((bits & WIFI_CONNECTED_BIT) == 0) {
        if (bits & WIFI_FAILED_BIT) {
            return classify_disconnect();
        }
        return WIFI_MANAGER_CONNECT_TIMEOUT;
    }

    /*
     * Receiving an IP address means Wi-Fi provisioning succeeded.
     * Do not block setup on a Google/ICMP connectivity probe. The next
     * encrypted FloraOS claim is the authoritative service-reachability
     * check.
     */
    s_station_ready = true;
    ESP_LOGI(TAG, "Wi-Fi provisioning succeeded; proceeding directly to FloraOS claim");
    return WIFI_MANAGER_CONNECT_OK;
}

esp_err_t wifi_manager_start_setup_ap(
    const char *ssid,
    const char *password
)
{
    if (!wifi_initialized || !valid_ssid(ssid) || password == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    size_t password_len = strlen(password);
    if (password_len != 0 && (password_len < 8 || password_len > 63)) {
        return ESP_ERR_INVALID_ARG;
    }

    esp_err_t err = esp_wifi_set_mode(WIFI_MODE_APSTA);
    if (err != ESP_OK) return err;

    wifi_config_t ap_config = {0};
    strlcpy((char *)ap_config.ap.ssid, ssid, sizeof(ap_config.ap.ssid));
    ap_config.ap.ssid_len = strlen(ssid);
    ap_config.ap.channel = 1;
    ap_config.ap.max_connection = 4;
    ap_config.ap.pmf_cfg.required = false;

    if (password_len == 0) {
        ap_config.ap.authmode = WIFI_AUTH_OPEN;
    } else {
        strlcpy(
            (char *)ap_config.ap.password,
            password,
            sizeof(ap_config.ap.password)
        );
        ap_config.ap.authmode = WIFI_AUTH_WPA2_PSK;
    }

    err = esp_wifi_set_config(WIFI_IF_AP, &ap_config);
    if (err != ESP_OK) return err;

    esp_netif_t *ap_netif =
        esp_netif_get_handle_from_ifkey("WIFI_AP_DEF");

    if (ap_netif != NULL) {
        esp_netif_ip_info_t ip_info = {0};
        esp_netif_set_ip4_addr(&ip_info.ip, 192, 168, 4, 1);
        esp_netif_set_ip4_addr(&ip_info.gw, 192, 168, 4, 1);
        esp_netif_set_ip4_addr(&ip_info.netmask, 255, 255, 255, 0);

        (void)esp_netif_dhcps_stop(ap_netif);
        err = esp_netif_set_ip_info(ap_netif, &ip_info);
        if (err != ESP_OK) {
            (void)esp_netif_dhcps_start(ap_netif);
            return err;
        }
        (void)esp_netif_dhcps_start(ap_netif);
    }

    s_setup_ap_active = true;
    ESP_LOGI(TAG, "Setup SoftAP active: %s", ssid);
    return ESP_OK;
}

esp_err_t wifi_manager_stop_setup_ap(void)
{
    if (!wifi_initialized) {
        return ESP_ERR_INVALID_STATE;
    }

    if (!s_setup_ap_active) {
        return ESP_OK;
    }

    esp_err_t err = esp_wifi_set_mode(WIFI_MODE_STA);
    if (err == ESP_OK) {
        s_setup_ap_active = false;
        ESP_LOGI(TAG, "Setup SoftAP stopped; STA remains enabled");
    }

    return err;
}

bool wifi_manager_setup_ap_active(void)
{
    return s_setup_ap_active;
}

const char *wifi_manager_connect_result_name(
    wifi_manager_connect_result_t result
)
{
    switch (result) {
        case WIFI_MANAGER_CONNECT_OK:
            return "ok";
        case WIFI_MANAGER_CONNECT_AUTH_FAILED:
            return "wifi_auth_failed";
        case WIFI_MANAGER_CONNECT_NO_AP:
            return "wifi_not_found";
        case WIFI_MANAGER_CONNECT_NO_INTERNET:
            return "no_internet";
        case WIFI_MANAGER_CONNECT_TIMEOUT:
            return "wifi_timeout";
        default:
            return "wifi_failed";
    }
}
