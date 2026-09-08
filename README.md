# FloraCore

**An open-source ESP32-S3 plant-care platform combining embedded hardware, secure IoT communication, automation, telemetry, OTA updates, and FloraOS.**

[**Live FloraOS**](https://floraos.life) · [**Firmware source**](https://github.com/Luqman234/FloraCore/tree/firmware) · [**Website source**](https://github.com/Luqman234/FloraCore/tree/website) · [**About**](https://about.floraos.life)

---

## What is FloraCore?

FloraCore started with a simple question:

> What if a plant-care system could do more than water a plant when the soil becomes dry?

The result is a connected plant-care platform built around an **ESP32-S3 N16R8** and a companion web platform called **FloraOS**.

FloraCore can monitor the plant environment, automate physical actions, securely communicate with its backend, report telemetry, receive bounded commands, and update its own firmware through rollback-capable OTA.

The goal is not just automatic watering. The goal is to create a platform that can **observe, decide, act, and improve** around a living plant.

---

## Platform at a glance

| Layer | What it does |
| --- | --- |
| **FloraCore hardware** | Sensors, pumps, lighting, reservoirs, and physical plant-care systems |
| **FloraOS firmware** | Device runtime, local safety, Wi-Fi/BLE setup, secure transport, commands, OTA |
| **FloraOS backend** | Device authentication, ownership, telemetry, automation, command queue, OTA services |
| **FloraOS dashboard** | Live monitoring, plant profiles, automation, firmware state, account controls |
| **Developer API** | Owner-scoped programmatic access using revocable Personal Access Tokens |

---

## Core capabilities

- Automatic irrigation
- Grow-light control
- Soil-moisture monitoring
- Light sensing
- Device RTC support
- Water/reservoir-oriented system monitoring
- Wi-Fi + BLE runtime
- Beginner-friendly SoftAP setup
- Secure one-time device claiming
- Authenticated telemetry and heartbeat
- Multi-device ownership
- Automation Studio
- Bounded remote commands
- Public developer API
- Account security and MFA
- HTTPS OTA with dual slots
- Firmware validation and rollback
- Plant profiles and care intelligence
- Open-source firmware and web backend

---

## System architecture

```text
                       FLORACORE

                ┌───────────────────┐
                │   Sensors / RTC   │
                │ Pumps / Lighting  │
                └─────────┬─────────┘
                          │
                          ▼
                ┌───────────────────┐
                │    ESP32-S3       │
                │   FloraOS FW      │
                │                   │
                │ Local safety      │
                │ Wi-Fi / BLE       │
                │ Command runtime   │
                │ OTA + rollback    │
                └─────────┬─────────┘
                          │
                 authenticated +
                 encrypted channel
                          │
                          ▼
            POST /api/device/v1/message
                          │
                          ▼
                ┌───────────────────┐
                │  FloraOS Backend  │
                │                   │
                │ Device ownership  │
                │ Telemetry         │
                │ Automation        │
                │ Commands          │
                │ OTA services      │
                └─────────┬─────────┘
                          │
             ┌────────────┼────────────┐
             ▼            ▼            ▼
         Dashboard    Developer API   Storage
```

---

## Security model

FloraCore does **not** trust a browser simply because it knows a device ID.

Physical-device identity is rooted in an ESP32-S3 **HMAC_UP eFuse key**. The firmware uses the hardware HMAC peripheral to derive direction-specific cryptographic material without exposing the raw root key to the application.

Device communication then uses authenticated encryption through the existing FloraOS device channel:

```text
HMAC_UP eFuse identity
        │
        ▼
direction-specific derived keys
        │
        ▼
AES-256-GCM authenticated transport
        │
        ▼
POST /api/device/v1/message
        │
        ├── replay protection
        ├── heartbeat
        ├── telemetry
        ├── claim
        ├── commands
        └── OTA state
```

Browser authentication, Personal Access Tokens, and device cryptography remain separate trust boundaries.

Production secrets, device key material, databases, OAuth credentials, SMTP credentials, Turnstile secrets, MFA keys, Wi-Fi credentials, and eFuse key material are intentionally excluded from the public repository.

---

## Secure device ownership

FloraCore uses a one-time claim flow instead of trusting a browser-provided device identifier.

```text
User account generates
a short-lived claim token
        │
        ▼
FloraCore receives the token
during setup
        │
        ▼
The authenticated physical device
submits the token through the
encrypted device channel
        │
        ▼
FloraOS verifies the claim
and binds device ownership
```

This means knowledge of a device ID alone is not enough to take ownership of a FloraCore.

---

## Automation

FloraOS can turn sensor conditions into validated physical actions.

Example:

```text
Soil moisture < 30%
        │
        ▼
Cooldown satisfied?
        │
        ▼
Water for 5 seconds
```

Automation actions use the same bounded command validator and encrypted device transport as normal FloraOS commands. They do not bypass the device security model.

---

## OTA firmware updates

FloraCore supports HTTPS OTA using a dual-slot layout.

```text
ota_0  ─────┐
            ├── candidate firmware
ota_1  ─────┘
        │
        ▼
PENDING_VERIFY
        │
   ┌────┴────┐
   ▼         ▼
 VALID     failure
             │
             ▼
          rollback
```

The rollback path has been tested with a deliberately broken candidate firmware. The device booted the candidate as `PENDING_VERIFY`, failed validation, and the ESP-IDF bootloader restored the previous valid image.

Current firmware source snapshot: **FloraCore 1.0.3**  
Development baseline: **ESP-IDF 6.0.2**

---

## Source code

This repository currently separates the two major software components by branch.

### Firmware

[**Open the `firmware` branch →**](https://github.com/Luqman234/FloraCore/tree/firmware)

Contains the ESP-IDF source for the ESP32-S3 device, including:

- secure device transport
- Wi-Fi/BLE runtime
- SoftAP setup
- telemetry and heartbeat
- command protocol
- local safety arbitration
- OTA and rollback
- sensor integration

### FloraOS website and backend

[**Open the `website` branch →**](https://github.com/Luqman234/FloraCore/tree/website)

Contains the Flask-based FloraOS platform, including:

- dashboard
- user accounts
- secure device ownership
- telemetry storage
- Automation Studio
- device command queue
- OTA services
- public API
- plant profiles
- MFA and account security
- Cloudflare Turnstile integration

---

## Live platform

FloraOS is available at:

### **https://floraos.life**

The live deployment is the user-facing control plane for FloraCore.

---

## Project philosophy

FloraCore is built around a few principles:

1. **Physical hardware should prove its own identity.**
2. **Automation must remain bounded by local and server-side safety rules.**
3. **A cloud dashboard should never become a shortcut around device security.**
4. **Firmware updates must be recoverable.**
5. **Plant-care data should become useful decisions, not just numbers on a screen.**
6. **The project should be inspectable, modifiable, and open to further development.**

---

## Repository branches

| Branch | Purpose |
| --- | --- |
| [`main`](https://github.com/Luqman234/FloraCore/tree/main) | Project overview and public entry point |
| [`firmware`](https://github.com/Luqman234/FloraCore/tree/firmware) | ESP32-S3 FloraOS firmware |
| [`website`](https://github.com/Luqman234/FloraCore/tree/website) | FloraOS website and backend |

---

## License

FloraCore is open-source software released under the **GNU Affero General Public License v3.0**.

See [LICENSE](LICENSE) for the full license text.

---

## FloraCore

**One core. Every system.**

Built around something alive.
