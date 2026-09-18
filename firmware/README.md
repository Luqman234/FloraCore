# FloraCore Firmware

This branch contains the ESP-IDF firmware for the FloraCore ESP32-S3 N16R8 smart plant-care platform.

Current source snapshot: **FloraCore 1.0.3**  
Target: **ESP32-S3**  
Development baseline: **ESP-IDF 6.0.2**

## What is included

- ESP32-S3 Wi-Fi and BLE runtime
- beginner-friendly SoftAP setup portal
- HMAC_UP eFuse-backed device identity
- direction-specific AES-256-GCM FloraOS transport
- encrypted device claim flow through `/api/device/v1/message`
- authenticated heartbeat and telemetry
- Phase 20 capability and diagnostics reporting
- command protocol v1 with persistent command-ID dedupe
- water-pump local safety arbitration
- HTTPS OTA with dual slots, PENDING_VERIFY validation, and rollback
- BH1750, DS3231, and soil-moisture integration

Fertilizer control is intentionally **not advertised or enabled** until the required physical dosing and local safety protections exist.

## Security boundary

FloraCore does not store the raw HMAC root key in source code. The physical device identity is rooted in a read-protected HMAC_UP eFuse key. The firmware selects the hardware key slot and asks the ESP32-S3 HMAC peripheral to derive direction-specific network keys; the raw eFuse key is never exported by this repository.

Do not commit generated credentials, production databases, Connection Codes, PATs, private keys, Wi-Fi credentials, or eFuse key material.

## Build

Install and activate ESP-IDF 6.0.2, then configure the ESP32-S3 target and project options:

```bash
idf.py set-target esp32s3
idf.py menuconfig
idf.py build
```

The project uses the custom 16 MB OTA partition table in `partitions.csv`.

Generated `sdkconfig` files are intentionally not committed. Important project-specific options include the 16 MB flash layout, custom partition table, OTA rollback, NimBLE, certificate bundle support, and NVS encryption.

## OTA layout

```text
nvs       64 KiB
otadata    8 KiB
phy_init   4 KiB
ota_0      4 MiB
ota_1      4 MiB
storage    6 MiB
coredump  64 KiB
```

The OTA path has been tested with a deliberately broken candidate: the candidate booted as `PENDING_VERIFY`, crashed before validation, and the ESP-IDF bootloader automatically restored the previous `VALID` image.

## License

FloraCore is released under the GNU Affero General Public License v3.0. See `LICENSE`.
