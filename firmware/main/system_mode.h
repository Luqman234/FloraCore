#ifndef SYSTEM_MODE_H
#define SYSTEM_MODE_H

#include "esp_err.h"

typedef enum
{
    FLORACORE_MODE_NORMAL = 0,
    FLORACORE_MODE_COM_DEV = 1

} floracore_mode_t;

/*
 * NVS must already be initialized before using these functions.
 */
floracore_mode_t system_mode_load(void);

esp_err_t system_mode_save(
    floracore_mode_t mode
);

const char *system_mode_name(
    floracore_mode_t mode
);

#endif
