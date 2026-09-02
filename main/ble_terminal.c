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
            return ESP_FAIL;
        }

        offset += chunk_length;
        if (offset < total_length) {
            vTaskDelay(pdMS_TO_TICKS(8));
        }
    }

    return ESP_OK;
}

esp_err_t ble_terminal_printf(
    uint16_t conn_handle,
    const char *format,
    ...
)
{
    if (format == NULL) return ESP_ERR_INVALID_ARG;

    char buffer[BLE_TERMINAL_TX_MAX];

    va_list args;
    va_start(args, format);
    int rc = vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);

    if (rc < 0) return ESP_FAIL;
    buffer[sizeof(buffer) - 1] = '\0';

    return ble_terminal_send(conn_handle, buffer);
}

static void command_help(uint16_t conn_handle)
{
    ble_terminal_send(
        conn_handle,
        "\r\nFloraCore commands\r\n"
        "------------------\r\n"
        "help\r\n"
        "info\r\n"
        "status\r\n"
        "uptime\r\n"
        "wifi list\r\n"
        "wifi add <SSID>|<PASSWORD>\r\n"
        "wifi erase\r\n"
        "wifi connect\r\n"
        "device id\r\n"
        "claim <ONE-TIME-TOKEN>\r\n"
        "setup start\r\n"
        "setup status\r\n"
        "init com dev\r\n"
        "init normal\r\n"
        "reboot\r\n\r\n"
    );
}

static void command_info(uint16_t conn_handle)
{
    ble_terminal_printf(
        conn_handle,
        "Device: FloraCore\r\n"
        "ESP-IDF: %s\r\n"
        "Free heap: %lu bytes\r\n",
        esp_get_idf_version(),
        (unsigned long)esp_get_free_heap_size()
    );
}

static void command_status(uint16_t conn_handle)
{
    wifi_credentials_load();
    floracore_mode_t mode = system_mode_load();
    bool ready = floraos_client_is_ready();

    ble_terminal_printf(
        conn_handle,
        "\r\nBLE connected: yes\r\n"
        "TX notifications: %s\r\n"
        "Boot mode: %s\r\n"
        "Saved Wi-Fi networks: %u\r\n"
        "Wi-Fi station ready: %s\r\n"
        "FloraOS secure client: %s\r\n"
        "Device ID: %s\r\n\r\n",
        tx_notifications_enabled ? "yes" : "no",
        system_mode_name(mode),
        (unsigned)known_network_count,
        wifi_manager_station_ready() ? "yes" : "no",
        ready ? "ready" : "not initialized",
        ready ? floraos_client_device_id() : "available after FloraOS init"
    );
}

static void command_uptime(uint16_t conn_handle)
{
    uint64_t seconds = (uint64_t)esp_timer_get_time() / 1000000ULL;
    ble_terminal_printf(
        conn_handle,
        "Uptime: %llu d %02llu:%02llu:%02llu\r\n",
        (unsigned long long)(seconds / 86400ULL),
        (unsigned long long)((seconds % 86400ULL) / 3600ULL),
        (unsigned long long)((seconds % 3600ULL) / 60ULL),
        (unsigned long long)(seconds % 60ULL)
    );
}

static void command_wifi_list(uint16_t conn_handle)
{
    if (!wifi_credentials_load()) {
        ble_terminal_send(conn_handle, "No Wi-Fi credentials saved.\r\n");
        return;
    }

    ble_terminal_printf(
        conn_handle,
        "Saved Wi-Fi networks (%u):\r\n",
        (unsigned)known_network_count
    );

    for (size_t i = 0; i < known_network_count; i++) {
        ble_terminal_printf(
            conn_handle,
            "  %u. %s\r\n",
            (unsigned)(i + 1),
            known_networks[i].ssid
        );
    }
}

static void command_wifi_add(uint16_t conn_handle, const char *arguments)
{
    if (arguments == NULL || arguments[0] == '\0') {
        ble_terminal_send(
            conn_handle,
            "Usage: wifi add <SSID>|<PASSWORD>\r\n"
        );
        return;
    }

    char buffer[BLE_TERMINAL_LINE_MAX];
    strlcpy(buffer, arguments, sizeof(buffer));

    char *separator = strchr(buffer, '|');
    if (separator == NULL) {
        memset(buffer, 0, sizeof(buffer));
        ble_terminal_send(
            conn_handle,
            "Missing '|'. Example: wifi add Home WiFi|password\r\n"
        );
        return;
    }

    *separator = '\0';
    const char *ssid = buffer;
    const char *password = separator + 1;

    esp_err_t err = wifi_credentials_save(ssid, password);
    if (err == ESP_OK) {
        ble_terminal_printf(
            conn_handle,
            "Saved Wi-Fi credential for: %s\r\n",
            ssid
        );
    } else {
        ble_terminal_printf(
            conn_handle,
            "Could not save Wi-Fi credential: %s\r\n",
            esp_err_to_name(err)
        );
    }

    memset(buffer, 0, sizeof(buffer));
}

static void command_wifi_erase(uint16_t conn_handle)
{
    esp_err_t err = wifi_credentials_erase_all();

    if (err != ESP_OK) {
        ble_terminal_printf(
            conn_handle,
            "Could not erase Wi-Fi credentials: %s\r\n",
            esp_err_to_name(err)
        );
        return;
    }

    ble_terminal_send(
        conn_handle,
        "All saved Wi-Fi credentials erased.\r\n"
    );

    esp_err_t setup_err = setup_portal_start();
    if (setup_err == ESP_OK) {
        ble_terminal_send(
            conn_handle,
            "Consumer setup portal started. Join FloraCore-XXXXXX Wi-Fi.\r\n"
        );
    } else {
        ble_terminal_printf(
            conn_handle,
            "Wi-Fi erased, but setup portal start failed: %s\r\n",
            esp_err_to_name(setup_err)
        );
    }
}

static void command_wifi_connect(uint16_t conn_handle)
{
    ble_terminal_send(
        conn_handle,
        "Scanning saved networks and connecting to Wi-Fi...\r\n"
    );

    if (!wifi_manager_connect()) {
        ble_terminal_send(
            conn_handle,
            "Could not connect to a saved Wi-Fi network.\r\n"
        );
        return;
    }

    ble_terminal_send(
        conn_handle,
        "Wi-Fi connected and DHCP completed. FloraOS will verify service reachability.\r\n"
    );

    esp_err_t err = floraos_client_init();
    if (err == ESP_OK) {
        ble_terminal_printf(
            conn_handle,
            "FloraOS secure client ready. Device ID: %s\r\n",
            floraos_client_device_id()
        );
    } else {
        ble_terminal_printf(
            conn_handle,
            "Wi-Fi is ready, but FloraOS init failed: %s\r\n",
            esp_err_to_name(err)
        );
    }
}

static void command_device_id(uint16_t conn_handle)
{
    esp_err_t err = floraos_client_init();
    if (err != ESP_OK) {
        ble_terminal_printf(
            conn_handle,
            "Could not initialize FloraOS identity: %s\r\n",
            esp_err_to_name(err)
        );
        return;
    }

    ble_terminal_printf(
        conn_handle,
        "Device ID: %s\r\n",
        floraos_client_device_id()
    );
}

static void command_claim(uint16_t conn_handle, const char *arguments)
{
    if (!floraos_claim_token_is_valid(arguments)) {
        ble_terminal_send(
            conn_handle,
            "Usage: claim <ONE-TIME-TOKEN>\r\n"
            "The token is generated by floraos.life/connect.\r\n"
        );
        return;
    }

    esp_err_t err = floraos_claim_start(arguments, NULL, NULL);

    if (err == ESP_OK) {
        ble_terminal_send(
            conn_handle,
            "Claim queued securely. Waiting for floraos.life to confirm ownership.\r\n"
        );
    } else {
        ble_terminal_printf(
            conn_handle,
            "Could not queue claim: %s\r\n",
            esp_err_to_name(err)
        );
    }
}

static void command_setup_start(uint16_t conn_handle)
{
    esp_err_t err = setup_portal_start();

    if (err == ESP_OK) {
        ble_terminal_send(
            conn_handle,
            "Setup portal active. Join the FloraCore-XXXXXX Wi-Fi network and open http://192.168.4.1/\r\n"
        );
    } else {
        ble_terminal_printf(
            conn_handle,
            "Could not start setup portal: %s\r\n",
            esp_err_to_name(err)
        );
    }
}

static void command_setup_status(uint16_t conn_handle)
{
    char reason[48] = {0};
    setup_portal_state_t state = setup_portal_state();
    setup_portal_reason(reason, sizeof(reason));

    ble_terminal_printf(
        conn_handle,
        "Setup portal: %s\r\n"
        "Setup state: %s\r\n"
        "Reason: %s\r\n",
        setup_portal_is_active() ? "active" : "inactive",
        setup_portal_state_name(state),
        reason[0] != '\0' ? reason : "none"
    );
}

static void set_mode_and_reboot(
    uint16_t conn_handle,
    floracore_mode_t mode
)
{
    esp_err_t err = system_mode_save(mode);
    if (err != ESP_OK) {
        ble_terminal_printf(
            conn_handle,
            "Could not save boot mode: %s\r\n",
            esp_err_to_name(err)
        );
        return;
    }

    ble_terminal_printf(
        conn_handle,
        "Saved %s mode. Rebooting...\r\n",
        system_mode_name(mode)
    );
    vTaskDelay(pdMS_TO_TICKS(250));
    esp_restart();
}

static void process_command(const terminal_command_t *command)
{
    if (command == NULL || command->line[0] == '\0') return;

    uint16_t conn_handle = command->conn_handle;
    const char *line = command->line;

    if (strncmp(line, "wifi add ", 9) == 0) {
        ESP_LOGI(TAG, "Command received: wifi add <redacted>");
    } else if (strncmp(line, "claim ", 6) == 0) {
        ESP_LOGI(TAG, "Command received: claim <redacted>");
    } else {
        ESP_LOGI(TAG, "Command received: %s", line);
    }

    if (strcmp(line, "help") == 0) command_help(conn_handle);
    else if (strcmp(line, "info") == 0) command_info(conn_handle);
    else if (strcmp(line, "status") == 0) command_status(conn_handle);
    else if (strcmp(line, "uptime") == 0) command_uptime(conn_handle);
    else if (strcmp(line, "wifi list") == 0) command_wifi_list(conn_handle);
    else if (strncmp(line, "wifi add ", 9) == 0)
        command_wifi_add(conn_handle, line + 9);
    else if (strcmp(line, "wifi erase") == 0)
        command_wifi_erase(conn_handle);
    else if (strcmp(line, "wifi connect") == 0)
        command_wifi_connect(conn_handle);
    else if (strcmp(line, "device id") == 0)
        command_device_id(conn_handle);
    else if (strncmp(line, "claim ", 6) == 0)
        command_claim(conn_handle, line + 6);
    else if (strcmp(line, "setup start") == 0)
        command_setup_start(conn_handle);
    else if (strcmp(line, "setup status") == 0)
        command_setup_status(conn_handle);
    else if (strcmp(line, "init com dev") == 0)
        set_mode_and_reboot(conn_handle, FLORACORE_MODE_COM_DEV);
    else if (strcmp(line, "init normal") == 0)
        set_mode_and_reboot(conn_handle, FLORACORE_MODE_NORMAL);
    else if (strcmp(line, "reboot") == 0) {
        ble_terminal_send(conn_handle, "Rebooting FloraCore...\r\n");
        vTaskDelay(pdMS_TO_TICKS(250));
        esp_restart();
    } else if (custom_command_handler != NULL &&
               custom_command_handler(conn_handle, line)) {
        return;
    } else {
        ble_terminal_send(
            conn_handle,
            "Unknown command. Type 'help'.\r\n"
        );
    }
}

static void command_task(void *parameter)
{
    (void)parameter;
    terminal_command_t command;

    while (1) {
        if (xQueueReceive(
                command_queue,
                &command,
                portMAX_DELAY
            ) == pdTRUE) {
            process_command(&command);
            memset(&command, 0, sizeof(command));
        }
    }
}

static int terminal_gap_event(
    struct ble_gap_event *event,
    void *arg
)
{
    (void)arg;

    switch (event->type) {
        case BLE_GAP_EVENT_CONNECT:
            if (event->connect.status == 0) {
                active_conn_handle = event->connect.conn_handle;
                ESP_LOGI(TAG, "BLE connected");
            } else {
                terminal_advertise();
            }
            break;

        case BLE_GAP_EVENT_DISCONNECT:
            active_conn_handle = BLE_HS_CONN_HANDLE_NONE;
            tx_notifications_enabled = false;
            rx_line_length = 0;
            memset(rx_line_buffer, 0, sizeof(rx_line_buffer));
            terminal_advertise();
            break;

        case BLE_GAP_EVENT_SUBSCRIBE:
            i