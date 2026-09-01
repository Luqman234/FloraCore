#ifndef FLORAOS_PHASE20_H
#define FLORAOS_PHASE20_H

#include <stdbool.h>
#include <stdint.h>

#include "esp_err.h"

typedef struct
{
    bool (*setup_blocked)(void);
    bool (*ota_in_progress)(void);

    esp_err_t (*water_set)(bool on);
    bool (*water_get)(void);

    esp_err_t (*grow_light_set)(bool on);
    bool (*grow_light_get)(void);
} floraos_phase20_ops_t;

typedef struct
{
    bool soil_adc_valid;
    int soil_adc;

    bool soil_percent_valid;
    int soil_percent;

    bool light_valid;
    float light_lux;

    bool pump_on;

    bool grow_light_valid;
    bool grow_light_on;

    bool rtc_valid;
    char rtc_text[32];
} floraos_phase20_telemetry_t;

/*
 * Initialize Phase 20 command handling and persistent command-ID dedupe.
 * Call only after the NORMAL-mode actuator outputs have been initialized OFF.
 */
esp_err_t floraos_phase20_init(const floraos_phase20_ops_t *ops);

bool floraos_phase20_is_ready(void);

/*
 * Build compact authenticated payloads. The returned string is heap allocated;
 * release it with floraos_phase20_free_payload().
 */
char *floraos_phase20_build_heartbeat(
    const char *mode,
    bool allow_commands
);

char *floraos_phase20_build_telemetry(
    const char *mode,
    const floraos_phase20_telemetry_t *sample,
    bool allow_commands
);

void floraos_phase20_free_payload(char *payload);

/*
 * Queue a normal FloraOS message. When accept_commands is true and Phase 20
 * initialized successfully, the authenticated/decrypted server response is
 * inspected for command_protocol v1 commands.
 */
esp_err_t floraos_phase20_queue_message(
    const char *type,
    const char *payload_json,
    bool accept_commands
);

/* Local safety integration. */
void floraos_phase20_set_water_lockout(bool locked);
bool floraos_phase20_water_command_active(void);
void floraos_phase20_force_safe_outputs(void);

#endif
