#ifndef WIFI_CREDENTIALS_H
#define WIFI_CREDENTIALS_H

#include <stdbool.h>
#include <stddef.h>
#include "esp_err.h"

#define MAX_WIFI_NETWORKS       8
#define WIFI_SSID_MAX_LEN       33
#define WIFI_PASSWORD_MAX_LEN   65

typedef struct
{
    char ssid[WIFI_SSID_MAX_LEN];
    char password[WIFI_PASSWORD_MAX_LEN];
} known_wifi_t;

extern known_wifi_t known_networks[MAX_WIFI_NETWORKS];
extern size_t known_network_count;

bool wifi_credentials_load(void);

esp_err_t wifi_credentials_save(
    const char *ssid,
    const char *password
);

esp_err_t wifi_credentials_erase_all(void);

#endif
