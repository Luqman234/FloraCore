#ifndef WIFI_MANAGER_H
#define WIFI_MANAGER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"
#include "wifi_credentials.h"

#define WIFI_MANAGER_SCAN_MAX_RESULTS 24

typedef struct
{
    char ssid[WIFI_SSID_MAX_LEN];
    int8_t rssi;
    bool secure;
} wifi_manager_scan_result_t;

typedef enum
{
    WIFI_MANAGER_CONNECT_OK = 0,
    WIFI_MANAGER_CONNECT_AUTH_FAILED,
    WIFI_MANAGER_CONNECT_NO_AP,
    WIFI_MANAGER_CONNECT_NO_INTERNET,
    WIFI_MANAGER_CONNECT_TIMEOUT,
    WIFI_MANAGER_CONNECT_FAILED
} wifi_manager_connect_result_t;

void wifi_manager_init(void);
bool wifi_manager_connect(void);

/* True once STA has associated and received an IP address.
 * FloraOS service reachability is verified by the encrypted FloraOS request itself.
 */
bool wifi_manager_station_ready(void);

/* Compatibility alias. Prefer wifi_manager_station_ready(). */
bool wifi_manager_internet_available(void);

esp_err_t wifi_manager_scan_visible(
    wifi_manager_scan_result_t *results,
    size_t capacity,
    size_t *out_count
);

wifi_manager_connect_result_t wifi_manager_connect_credentials(
    const char *ssid,
    const char *password
);

esp_err_t wifi_manager_start_setup_ap(
    const char *ssid,
    const char *password
);

esp_err_t wifi_manager_stop_setup_ap(void);
bool wifi_manager_setup_ap_active(void);

uint8_t wifi_manager_last_disconnect_reason(void);
const char *wifi_manager_connect_result_name(wifi_manager_connect_result_t result);

#endif
