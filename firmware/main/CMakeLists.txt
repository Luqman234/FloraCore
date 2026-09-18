idf_component_register(
    SRCS
        "main.c"
        "wifi_manager.c"
        "wifi_credentials.c"
        "ble_terminal.c"
        "system_mode.c"
        "floraos_crypto.c"
        "floraos_client.c"
        "floraos_claim.c"
        "setup_portal.c"
        "ota_manager.c"
        "floraos_phase20.c"

    INCLUDE_DIRS "."

    REQUIRES
        esp_driver_i2c
        esp_driver_gpio
        esp_adc
        esp_wifi
        esp_event
        esp_netif
        nvs_flash
        esp_http_client
        esp_https_ota
        esp_http_server
        lwip
        bt
        esp_timer
        esp_security
        mbedtls
        app_update
        esp_app_format
        esp_partition
)
