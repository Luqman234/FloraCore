#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "driver/gpio.h"
#include "driver/i2c_master.h"

#include "esp_adc/adc_oneshot.h"
#include "esp_err.h"
#include "esp_log.h"
#include "esp_netif_sntp.h"
#include "esp_timer.h"

#include "sdkconfig.h"

#include "ble_terminal.h"
#include "floraos_client.h"
#include "floraos_phase20.h"
#include "ota_manager.h"
#include "setup_portal.h"
#include "system_mode.h"
#include "wifi_credentials.h"
#include "wifi_manager.h"

#define I2C_SDA_GPIO 10
#define I2C_SCL_GPIO 11
#define SOIL_MOISTURE_GPIO 8
#define WATER_PUMP_GPIO GPIO_NUM_40

#ifdef CONFIG_FLORACORE_GROW_LIGHT_ENABLE
#define GROW_LIGHT_GPIO ((gpio_num_t)CONFIG_FLORACORE_GROW_LIGHT_GPIO)
#endif

#define BH1750_ADDRESS 0x23
#define DS3231_ADDRESS 0x68
#define BH1750_POWER_ON 0x01
#define BH1750_CONT_H_RES 0x10

#define PUMP_ON 1
#define PUMP_OFF 0
#define SAMPLE_COUNT 5
#define FLORAOS_HEARTBEAT_INTERVAL_SECONDS 60

/*
 * Only a newly-installed OTA candidate waits here.  This gives the common
 * FloraCore runtime a short settling period before the candidate is committed.
 * It deliberately does not require internet access or external plant sensors.
 */
#define OTA_CANDIDATE_SETTLE_MS 2000

#define SOIL_DRY_VALUE 1732
#define SOIL_WET_VALUE 1235
#define SOIL_OUT_OF_SOIL 2200
#define SOIL_DRY_PERCENT 30
#define SOIL_WET_PERCENT 70

#define TEMP_WIFI_PROVISIONING 0

static const char *TAG = "FLORACORE";

static i2c_master_dev_handle_t bh1750_handle;
static i2c_master_dev_handle_t ds3231_handle;
static adc_oneshot_unit_handle_t adc_handle;
static adc_channel_t soil_adc_channel;

typedef struct
{
    uint8_t seconds;
    uint8_t minutes;
    uint8_t hours;
    uint8_t day;
    uint8_t date;
    uint8_t month;
    uint8_t year;
} rtc_time_t;

static uint8_t bcd_to_decimal(uint8_t bcd)
{
    return ((bcd >> 4) * 10) + (bcd & 0x0F);
}

static uint8_t decimal_to_bcd(uint8_t decimal)
{
    return ((decimal / 10) << 4) | (decimal % 10);
}

static void water_pump_init(void)
{
    gpio_config_t config = {
        .pin_bit_mask = (1ULL << WATER_PUMP_GPIO),
        .mode = GPIO_MODE_OUTPUT,
        .pull_up_en = GPIO_PULLUP_DISABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE
    };

    ESP_ERROR_CHECK(gpio_config(&config));
    gpio_set_level(WATER_PUMP_GPIO, PUMP_OFF);
}

static void water_pump_on(void)
{
    /*
     * Never energize the watering actuator while firmware is being replaced.
     * The OTA task can reboot at any point after installation succeeds.
     */
    if (ota_manager_update_in_progress()) {
        gpio_set_level(WATER_PUMP_GPIO, PUMP_OFF);
        return;
    }

    gpio_set_level(WATER_PUMP_GPIO, PUMP_ON);
}

static void water_pump_off(void)
{
    gpio_set_level(WATER_PUMP_GPIO, PUMP_OFF);
}

static esp_err_t phase20_water_set(bool on)
{
    if (on && ota_manager_update_in_progress()) {
        (void)gpio_set_level(WATER_PUMP_GPIO, PUMP_OFF);
        return ESP_ERR_INVALID_STATE;
    }

    return gpio_set_level(
        WATER_PUMP_GPIO,
        on ? PUMP_ON : PUMP_OFF
    );
}

static bool phase20_water_get(void)
{
    return gpio_get_level(WATER_PUMP_GPIO) == PUMP_ON;
}

#ifdef CONFIG_FLORACORE_GROW_LIGHT_ENABLE
static void grow_light_init(void)
{
    gpio_config_t config = {
        .pin_bit_mask = (1ULL << GROW_LIGHT_GPIO),
        .mode = GPIO_MODE_OUTPUT,
        .pull_up_en = GPIO_PULLUP_DISABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE
    };

    ESP_ERROR_CHECK(gpio_config(&config));
    ESP_ERROR_CHECK(gpio_set_level(GROW_LIGHT_GPIO, 0));
}

static esp_err_t phase20_grow_light_set(bool on)
{
    if (on && ota_manager_update_in_progress()) {
        (void)gpio_set_level(GROW_LIGHT_GPIO, 0);
        return ESP_ERR_INVALID_STATE;
    }

    return gpio_set_level(GROW_LIGHT_GPIO, on ? 1 : 0);
}

static bool phase20_grow_light_get(void)
{
    return gpio_get_level(GROW_LIGHT_GPIO) != 0;
}
#endif

static esp_err_t bh1750_init(void)
{
    uint8_t command = BH1750_POWER_ON;
    esp_err_t err =
        i2c_master_transmit(bh1750_handle, &command, 1, 1000);

    if (err != ESP_OK) return err;

    command = BH1750_CONT_H_RES;
    err = i2c_master_transmit(bh1750_handle, &command, 1, 1000);

    vTaskDelay(pdMS_TO_TICKS(200));
    return err;
}

static esp_err_t bh1750_read_lux(float *lux)
{
    uint8_t data[2];
    esp_err_t err =
        i2c_master_receive(bh1750_handle, data, sizeof(data), 1000);

    if (err != ESP_OK) return err;

    uint16_t raw = ((uint16_t)data[0] << 8) | data[1];
    *lux = raw / 1.2f;
    return ESP_OK;
}

static esp_err_t bh1750_read_average(float *average_lux)
{
    float total = 0.0f;

    for (int i = 0; i < SAMPLE_COUNT; i++) {
        float lux = 0.0f;
        esp_err_t err = bh1750_read_lux(&lux);
        if (err != ESP_OK) return err;

        total += lux;
        vTaskDelay(pdMS_TO_TICKS(150));
    }

    *average_lux = total / SAMPLE_COUNT;
    return ESP_OK;
}

static esp_err_t ds3231_read_time(rtc_time_t *time)
{
    uint8_t start_register = 0x00;
    uint8_t data[7];

    esp_err_t err = i2c_master_transmit_receive(
        ds3231_handle,
        &start_register,
        1,
        data,
        sizeof(data),
        1000
    );
    if (err != ESP_OK) return err;

    time->seconds = bcd_to_decimal(data[0] & 0x7F);
    time->minutes = bcd_to_decimal(data[1] & 0x7F);
    time->hours = bcd_to_decimal(data[2] & 0x3F);
    time->day = bcd_to_decimal(data[3] & 0x07);
    time->date = bcd_to_decimal(data[4] & 0x3F);
    time->month = bcd_to_decimal(data[5] & 0x1F);
    time->year = bcd_to_decimal(data[6]);

    return ESP_OK;
}

static esp_err_t ds3231_set_time(
    uint8_t year,
    uint8_t month,
    uint8_t date,
    uint8_t day,
    uint8_t hours,
    uint8_t minutes,
    uint8_t seconds
)
{
    uint8_t data[8] = {
        0x00,
        decimal_to_bcd(seconds),
        decimal_to_bcd(minutes),
        decimal_to_bcd(hours),
        decimal_to_bcd(day),
        decimal_to_bcd(date),
        decimal_to_bcd(month),
        decimal_to_bcd(year)
    };

    return i2c_master_transmit(
        ds3231_handle,
        data,
        sizeof(data),
        1000
    );
}

static esp_err_t sync_rtc_from_ntp(void)
{
    esp_sntp_config_t config =
        ESP_NETIF_SNTP_DEFAULT_CONFIG("pool.ntp.org");

    esp_err_t err = esp_netif_sntp_init(&config);
    if (err != ESP_OK) return err;

    err = esp_netif_sntp_sync_wait(pdMS_TO_TICKS(15000));
    if (err != ESP_OK) {
        esp_netif_sntp_deinit();
        return err;
    }

    setenv("TZ", "MYT-8", 1);
    tzset();

    time_t now;
    struct tm timeinfo;
    time(&now);
    localtime_r(&now, &timeinfo);

    err = ds3231_set_time(
        (uint8_t)((timeinfo.tm_year + 1900) % 100),
        (uint8_t)(timeinfo.tm_mon + 1),
        (uint8_t)timeinfo.tm_mday,
        (uint8_t)(timeinfo.tm_wday + 1),
        (uint8_t)timeinfo.tm_hour,
        (uint8_t)timeinfo.tm_min,
        (uint8_t)timeinfo.tm_sec
    );

    esp_netif_sntp_deinit();
    return err;
}

static void soil_moisture_init(void)
{
    adc_unit_t unit;

    ESP_ERROR_CHECK(
        adc_oneshot_io_to_channel(
            SOIL_MOISTURE_GPIO,
            &unit,
            &soil_adc_channel
        )
    );

    adc_oneshot_unit_init_cfg_t init = {.unit_id = unit};
    ESP_ERROR_CHECK(adc_oneshot_new_unit(&init, &adc_handle));

    adc_oneshot_chan_cfg_t channel = {
        .atten = ADC_ATTEN_DB_12,
        .bitwidth = ADC_BITWIDTH_DEFAULT
    };

    ESP_ERROR_CHECK(
        adc_oneshot_config_channel(
            adc_handle,
            soil_adc_channel,
            &channel
        )
    );
}

static esp_err_t soil_moisture_read_average(int *average_raw)
{
    int total = 0;

    for (int i = 0; i < SAMPLE_COUNT; i++) {
        int raw = 0;
        esp_err_t err =
            adc_oneshot_read(adc_handle, soil_adc_channel, &raw);

        if (err != ESP_OK) return err;
        total += raw;

        vTaskDelay(pdMS_TO_TICKS(50));
    }

    *average_raw = total / SAMPLE_COUNT;
    return ESP_OK;
}

static int soil_adc_to_percent(int adc_value)
{
    int moisture =
        ((SOIL_DRY_VALUE - adc_value) * 100) /
        (SOIL_DRY_VALUE - SOIL_WET_VALUE);

    if (moisture < 0) moisture = 0;
    if (moisture > 100) moisture = 100;
    return moisture;
}

static const char *soil_get_status(int moisture_percent)
{
    if (moisture_percent < SOIL_DRY_PERCENT) return "DRY";
    if (moisture_percent < SOIL_WET_PERCENT) return "GOOD";
    return "WET";
}

static bool setup_blocks_normal_cloud_traffic(void)
{
    if (!setup_portal_is_active()) {
        return false;
    }

    return setup_portal_state() != SETUP_SUCCESS;
}


static bool floracore_ble_command(
    uint16_t conn_handle,
    const char *command
)
{
    if (command == NULL) {
        return false;
    }

    if (strcmp(command, "ota status") == 0) {
        ble_terminal_printf(
            conn_handle,
            "Firmware version: %s\r\n"
            "OTA candidate pending verification: %s\r\n"
            "OTA update in progress: %s\r\n",
            ota_manager_get_version(),
            ota_manager_is_pending_verify() ? "yes" : "no",
            ota_manager_update_in_progress() ? "yes" : "no"
        );

        return true;
    }

    if (strcmp(command, "ota test") != 0) {
        return false;
    }

#if CONFIG_FLORACORE_OTA_DEV_TEST
    if (ota_manager_is_pending_verify()) {
        ble_terminal_send(
            conn_handle,
            "OTA test refused: this firmware is still pending validation.\r\n"
        );

        return true;
    }

    if (ota_manager_update_in_progress()) {
        ble_terminal_send(
            conn_handle,
            "OTA update is already in progress.\r\n"
        );

        return true;
    }

    if (!wifi_manager_station_ready()) {
        ble_terminal_send(
            conn_handle,
            "OTA test requires Wi-Fi association and DHCP first.\r\n"
        );

        return true;
    }

    if (setup_blocks_normal_cloud_traffic()) {
        ble_terminal_send(
            conn_handle,
            "OTA test is blocked while first-time setup/claim is active.\r\n"
        );

        return true;
    }

    if (system_mode_load() == FLORACORE_MODE_NORMAL) {
        water_pump_off();
        floraos_phase20_force_safe_outputs();
    }

    esp_err_t err =
        ota_manager_start_update(
            CONFIG_FLORACORE_OTA_TEST_URL,
            CONFIG_FLORACORE_OTA_TEST_EXPECTED_VERSION
        );

    if (err == ESP_OK) {
        ble_terminal_printf(
            conn_handle,
            "OTA test started.\r\n"
            "Current: %s\r\n"
            "Expected: %s\r\n"
            "Source: floraos.life firmware origin\r\n"
            "Progress is logged on the serial console. "
            "FloraCore will reboot automatically if installation succeeds.\r\n",
            ota_manager_get_version(),
            CONFIG_FLORACORE_OTA_TEST_EXPECTED_VERSION
        );
    } else {
        ble_terminal_printf(
            conn_handle,
            "Could not start OTA test: %s\r\n",
            esp_err_to_name(err)
        );
    }
#else
    ble_terminal_send(
        conn_handle,
        "Developer OTA test is disabled. Open menuconfig -> FloraCore OTA -> "
        "Enable developer-only BLE OTA test command.\r\n"
    );
#endif

    return true;
}


static bool floraos_cloud_housekeeping(
    floracore_mode_t boot_mode,
    bool *hello_announced
)
{
    /*
     * OTA owns the network/flash update window. Avoid competing hello,
     * heartbeat, telemetry and NTP activity until the update finishes or
     * aborts. The device reboots automatically after a successful install.
     */
    if (ota_manager_update_in_progress()) {
        floraos_phase20_force_safe_outputs();
        if (hello_announced != NULL) {
            *hello_announced = false;
        }
        return false;
    }

    /*
     * First-time onboarding owns the FloraOS cloud channel until ownership
     * is confirmed. During SETUP_IDLE / CONNECTING / WIFI_CONNECTED /
     * CLAIMING / FAILED, setup_portal.c may send only the encrypted claim.
     *
     * This prevents hello/heartbeat/telemetry from competing with the
     * ownership handshake on a factory-new FloraCore.
     */
    if (setup_blocks_normal_cloud_traffic()) {
        floraos_phase20_force_safe_outputs();
        if (hello_announced != NULL) {
            *hello_announced = false;
        }
        return false;
    }

    if (!wifi_manager_station_ready()) {
        if (hello_announced != NULL) {
            *hello_announced = false;
        }
        return false;
    }

    if (!floraos_client_is_ready()) {
        esp_err_t init_err = floraos_client_init();
        if (init_err != ESP_OK) {
            ESP_LOGW(
                TAG,
                "FloraOS secure client init deferred: %s",
                esp_err_to_name(init_err)
            );
            return false;
        }
    }

    if (hello_announced != NULL && !*hello_announced) {
        char payload[160] = {0};

        snprintf(
            payload,
            sizeof(payload),
            "{\"mode\":\"%s\",\"event\":\"online\"}",
            system_mode_name(boot_mode)
        );

        esp_err_t send_err =
            floraos_client_queue_message("hello", payload);

        if (send_err == ESP_OK) {
            *hello_announced = true;
        }
    }

    return floraos_client_is_ready();
}


/*
 * Confirm a newly-installed OTA image only after FloraCore's common software
 * stack is demonstrably alive.
 *
 * What counts as health here:
 *   - OTA metadata can be read
 *   - encrypted NVS / Wi-Fi stack initialized (already reached this point)
 *   - system mode loaded
 *   - BLE terminal initialized
 *   - HMAC_UP-derived FloraOS crypto + HTTPS worker initialized
 *   - if Wi-Fi recovery is required, the setup portal started successfully
 *
 * Deliberately NOT required:
 *   - internet / Cloudflare / floraos.life availability
 *   - BH1750, DS3231 or soil sensor presence
 *
 * Network outages and disconnected plant sensors are environmental conditions,
 * not evidence that the firmware image itself is broken.
 */
static void ota_validate_candidate(
    bool setup_required,
    esp_err_t setup_start_result
)
{
    if (!ota_manager_is_pending_verify()) {
        return;
    }

    ESP_LOGW(
        TAG,
        "Validating newly-installed OTA candidate..."
    );

    /*
     * floraos_client_init() performs the local hardware-derived identity /
     * AES-GCM initialization and starts the existing dedicated HTTPS worker.
     * It does not need an active Wi-Fi connection to initialize.
     */
    esp_err_t crypto_err =
        floraos_client_init();

    if (crypto_err != ESP_OK) {
        ESP_LOGE(
            TAG,
            "OTA candidate failed FloraOS crypto/client self-test: %s",
            esp_err_to_name(crypto_err)
        );

        ESP_ERROR_CHECK(
            ota_manager_rollback_and_reboot(
                "HMAC_UP / FloraOS crypto-client initialization failed"
            )
        );

        return;
    }

    if (
        setup_required &&
        setup_start_result != ESP_OK
    ) {
        ESP_LOGE(
            TAG,
            "OTA candidate cannot provide required recovery setup: %s",
            esp_err_to_name(setup_start_result)
        );

        ESP_ERROR_CHECK(
            ota_manager_rollback_and_reboot(
                "required beginner setup portal could not start"
            )
        );

        return;
    }

    /*
     * Give common background tasks a brief chance to expose an immediate
     * startup fault.  This delay happens only once on the first boot of a
     * newly-installed OTA image.
     */
    vTaskDelay(
        pdMS_TO_TICKS(
            OTA_CANDIDATE_SETTLE_MS
        )
    );

    esp_err_t valid_err =
        ota_manager_mark_valid();

    if (valid_err != ESP_OK) {
        ESP_LOGE(
            TAG,
            "Could not commit OTA candidate as valid: %s",
            esp_err_to_name(valid_err)
        );

        /*
         * Do not continue indefinitely with an unconfirmed candidate.
         */
        ESP_ERROR_CHECK(
            ota_manager_rollback_and_reboot(
                "could not commit OTA validity"
            )
        );
    }
}


void app_main(void)
{
    ESP_LOGI(TAG, "Starting FloraCore...");

    /*
     * Read OTA state before bringing up the rest of FloraCore.  This does not
     * accept a candidate; it merely records whether this is its one
     * PENDING_VERIFY boot.
     */
    ESP_ERROR_CHECK(
        ota_manager_init()
    );

    wifi_manager_init();

    floracore_mode_t boot_mode = system_mode_load();

    bool phase20_ready = false;

    if (boot_mode == FLORACORE_MODE_NORMAL) {
        water_pump_init();

#ifdef CONFIG_FLORACORE_GROW_LIGHT_ENABLE
        grow_light_init();
#endif

        floraos_phase20_ops_t phase20_ops = {
            .setup_blocked = setup_blocks_normal_cloud_traffic,
            .ota_in_progress = ota_manager_update_in_progress,
            .water_set = phase20_water_set,
            .water_get = phase20_water_get,
#ifdef CONFIG_FLORACORE_GROW_LIGHT_ENABLE
            .grow_light_set = phase20_grow_light_set,
            .grow_light_get = phase20_grow_light_get
#else
            .grow_light_set = NULL,
            .grow_light_get = NULL
#endif
        };

        esp_err_t phase20_err = floraos_phase20_init(&phase20_ops);
        if (phase20_err == ESP_OK) {
            phase20_ready = true;
        } else {
            ESP_LOGE(
                TAG,
                "Phase 20 command/runtime init failed; command_protocol will stay disabled: %s",
                esp_err_to_name(phase20_err)
            );
        }
    }

    ESP_ERROR_CHECK(ble_terminal_init());

    ble_terminal_set_command_handl