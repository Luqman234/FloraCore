#ifndef SETUP_PORTAL_H
#define SETUP_PORTAL_H

#include <stdbool.h>
#include <stddef.h>
#include "esp_err.h"

typedef enum
{
    SETUP_IDLE = 0,
    SETUP_CONNECTING,
    SETUP_WIFI_CONNECTED,
    SETUP_CLAIMING,
    SETUP_SUCCESS,
    SETUP_FAILED
} setup_portal_state_t;

esp_err_t setup_portal_start(void);
esp_err_t setup_portal_stop(void);

bool setup_portal_is_active(void);
bool setup_portal_should_resume(void);

setup_portal_state_t setup_portal_state(void);
const char *setup_portal_state_name(setup_portal_state_t state);
void setup_portal_reason(char *buffer, size_t capacity);

#endif
