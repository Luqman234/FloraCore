#ifndef OTA_MANAGER_H
#define OTA_MANAGER_H

#include <stdbool.h>

#include "esp_err.h"

/*
 * Initialize OTA boot-state tracking and log the running firmware metadata.
 *
 * This function NEVER marks a candidate firmware valid. A newly-installed
 * OTA image remains ESP_OTA_IMG_PENDING_VERIFY until FloraCore explicitly
 * confirms that its common runtime stack is healthy.
 */
esp_err_t ota_manager_init(void);

/* Version embedded by ESP-IDF (for example, from project version.txt). */
const char *ota_manager_get_version(void);

/* True only while the running OTA image still requires confirmation. */
bool ota_manager_is_pending_verify(void);

/* True while a background HTTPS OTA download/install task is active. */
bool ota_manager_update_in_progress(void);

/*
 * Start a background HTTPS OTA download.
 *
 * Security policy:
 *   - URL must be HTTPS under https://floraos.life/firmware/floracore/
 *   - HTTP redirects are disabled
 *   - TLS uses the ESP-IDF x509 certificate bundle
 *   - candidate project_name must match the running FloraCore app
 *   - candidate version must exactly match expected_version
 *   - candidate semantic version must be newer than the running version
 *
 * On success the inactive OTA slot becomes the next boot partition and the
 * device restarts. The candidate then boots as PENDING_VERIFY and is handled
 * by the existing FloraCore startup health gate.
 *
 * This is intentionally asynchronous so callers such as the BLE command task
 * never perform a blocking TLS/flash operation themselves.
 */
esp_err_t ota_manager_start_update(
    const char *url,
    const char *expected_version
);

/*
 * Mark the currently-running candidate firmware VALID.
 *
 * Safe to call when the image is not pending; in that case it is a no-op.
 */
esp_err_t ota_manager_mark_valid(void);

/*
 * Reject the currently-running candidate and reboot into the previous valid
 * OTA image. On success this function does not return because the ESP restarts.
 */
esp_err_t ota_manager_rollback_and_reboot(const char *reason);

/* Print current version, running partition, configured boot partition and state. */
void ota_manager_log_boot_info(void);

#endif
