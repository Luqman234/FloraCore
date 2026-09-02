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
        decim