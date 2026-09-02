#ifndef BLE_TERMINAL_H
#define BLE_TERMINAL_H

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"

typedef bool (*ble_terminal_command_handler_t)(
    uint16_t conn_handle,
    const char *command
);

esp_err_t ble_terminal_init(void);
void ble_terminal_set_command_handler(ble_terminal_command_handler_t handler);

esp_err_t ble_terminal_send(uint16_t conn_handle, const char *text);
esp_err_t ble_terminal_printf(uint16_t conn_handle, const char *format, ...);

bool ble_terminal_is_connected(void);
uint16_t ble_terminal_connection_handle(void);

#endif
