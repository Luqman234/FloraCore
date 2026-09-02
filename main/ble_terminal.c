#include "ble_terminal.h"

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"

#include "esp_log.h"
#include "esp_system.h"
#include "esp_timer.h"

#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"

#include "host/ble_att.h"
#include "host/ble_gap.h"
#include "host/ble_gatt.h"
#include "host/ble_hs.h"
#include "host/ble_store.h"
#include "host/ble_uuid.h"
#include "host/util/util.h"

#include "os/os_mbuf.h"

#include "services/gap/ble_svc_gap.h"
#include "services/gatt/ble_svc_gatt.h"

#include "wifi_credentials.h"
#include "wifi_manager.h"
#include "system_mode.h"
#include "floraos_client.h"
#include "floraos_claim.h"
#include "setup_portal.h"

static const char *TAG = "BLE_TERMINAL";

#define BLE_DEVICE_NAME "FloraCore"
#define BLE_TERMINAL_LINE_MAX 256
#define BLE_TERMINAL_TX_MAX 768
#define BLE_TERMINAL_QUEUE_DEPTH 8
#define BLE_TERMINAL_TASK_STACK 6144
#define BLE_TERMINAL_TASK_PRIORITY 5

static const ble_uuid128_t service_uuid =
    BLE_UUID128_INIT(
        0x01,0x00,0xDE,0xC0,0x0A,0xF1,0x10,0x8E,
        0x5D,0x4A,0x3B,0x7C,0x01,0x00,0x0A,0xF1
    );

static const ble_uuid128_t rx_uuid =
    BLE_UUID128_INIT(
        0x01,0x00,0xDE,0xC0,0x0A,0xF1,0x10,0x8E,
        0x5D,0x4A,0x3B,0x7C,0x02,0x00,0x0A,0xF1
    );

static const ble_uuid128_t tx_uuid =
    BLE_UUID128_INIT(
        0x01,0x00,0xDE,0xC0,0x0A,0xF1,0x10,0x8E,
        0x5D,0x4A,0x3B,0x7C,0x03,0x00,0x0A,0xF1
    );

typedef struct
{
    uint16_t conn_handle;
    char line[BLE_TERMINAL_LINE_MAX];
} terminal_command_t;

static QueueHandle_t command_queue = NULL;
static uint8_t own_addr_type;
static uint16_t tx_value_handle;
static uint16_t active_conn_handle = BLE_HS_CONN_HANDLE_NONE;
static bool tx_notifications_enabled = false;

static char rx_line_buffer[BLE_TERMINAL_LINE_MAX];
static size_t rx_line_length = 0;
static ble_terminal_command_handler_t custom_command_handler = NULL;

void ble_store_config_init(void);

static void terminal_advertise(void);

static void queue_complete_line(uint16_t conn_handle)
{
    if (command_queue == NULL || rx_line_length == 0) {
        rx_line_length = 0;
        return;
    }

    rx_line_buffer[rx_line_length] = '\0';

    terminal_command_t command = {.conn_handle = conn_handle};
    strlcpy(command.line, rx_line_buffer, sizeof(command.line));

    if (xQueueSend(command_queue, &command, 0) != pdTRUE) {
        ESP_LOGW(TAG, "Command queue full; dropping command");
    }

    memset(rx_line_buffer, 0, sizeof(rx_line_buffer));
    rx_line_length = 0;
}

static int terminal_rx_access(
    uint16_t conn_handle,
    uint16_t attr_handle,
    struct ble_gatt_access_ctxt *ctxt,
    void *arg
)
{
    (void)attr_handle;
    (void)arg;

    if (ctxt->op != BLE_GATT_ACCESS_OP_WRITE_CHR) {
        return BLE_ATT_ERR_UNLIKELY;
    }

    uint16_t packet_length = OS_MBUF_PKTLEN(ctxt->om);
    if (packet_length == 0 || packet_length > BLE_TERMINAL_LINE_MAX) {
        return BLE_ATT_ERR_INVALID_ATTR_VALUE_LEN;
    }

    uint8_t packet[BLE_TERMINAL_LINE_MAX];
    uint16_t flattened_length = 0;

    if (ble_hs_mbuf_to_flat(
            ctxt->om,
            packet,
            sizeof(packet),
            &flattened_length
        ) != 0) {
        return BLE_ATT_ERR_UNLIKELY;
    }

    for (uint16_t i = 0; i < flattened_length; i++) {
        char ch = (char)packet[i];

        if (ch == '\r') continue;

        if (ch == '\n') {
            queue_complete_line(conn_handle);
            continue;
        }

        if (rx_line_length >= sizeof(rx_line_buffer) - 1) {
            rx_line_length = 0;
            return BLE_ATT_ERR_INVALID_ATTR_VALUE_LEN;
        }

        rx_line_buffer[rx_line_length++] = ch;
    }

    return 0;
}

static int terminal_tx_access(
    uint16_t conn_handle,
    uint16_t attr_handle,
    struct ble_gatt_access_ctxt *ctxt,
    void *arg
)
{
    (void)conn_handle;
    (void)attr_handle;
    (void)arg;

    if (ctxt->op == BLE_GATT_ACCESS_OP_READ_CHR) {
        static const char text[] = "FloraCore BLE terminal ready\r\n";
        return os_mbuf_append(ctxt->om, text, sizeof(text) - 1) == 0
            ? 0
            : BLE_ATT_ERR_INSUFFICIENT_RES;
    }

    return BLE_ATT_ERR_UNLIKELY;
}

static const struct ble_gatt_svc_def terminal_services[] =
{
    {
        .type = BLE_GATT_SVC_TYPE_PRIMARY,
        .uuid = &service_uuid.u,
        .characteristics = (struct ble_gatt_chr_def[])
        {
            {
                .uuid = &rx_uuid.u,
                .access_cb = terminal_rx_access,
                .flags = BLE_GATT_CHR_F_WRITE | BLE_GATT_CHR_F_WRITE_ENC,
            },
            {
                .uuid = &tx_uuid.u,
                .access_cb = terminal_tx_access,
                .val_handle = &tx_value_handle,
                .flags = BLE_GATT_CHR_F_READ |
                         BLE_GATT_CHR_F_READ_ENC |
                         BLE_GATT_CHR_F_NOTIFY,
            },
            {0}
        }
    },
    {0}
};

esp_err_t ble_terminal_send(uint16_t conn_handle, const char *text)
{
    if (text == NULL) return ESP_ERR_INVALID_ARG;

    if (conn_handle == BLE_HS_CONN_HANDLE_NONE ||
        conn_handle != active_conn_handle ||
        !tx_notifications_enabled) {
        return ESP_ERR_INVALID_STATE;
    }

    size_t total_length = strlen(text);
    size_t offset = 0;

    while (offset < total_length) {
        uint16_t mtu = ble_att_mtu(conn_handle);
        size_t payload_max = mtu > 3 ? mtu - 3 : 20;
        size_t remaining = total_length - offset;
        size_t chunk_length =
            remaining < payload_max ? remaining : payload_max;

        struct os_mbuf *om =
            ble_hs_mbuf_from_flat(text + offset, chunk_length);
        if (om == NULL) return ESP_ERR_NO_MEM;

        if (ble_gatts_notify_custom(
                conn_handle,
                tx_value_handle,
                om
            ) != 0) {
   