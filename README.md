# FloraCore

**An open-source ESP32-S3 plant-care platform combining embedded hardware, secure IoT communication, automation, telemetry, OTA updates, and FloraOS.**

[**Live FloraOS**](https://floraos.life) · [**Firmware source**](firmware/) · [**FloraOS web source**](web/) · [**Self-hosting**](docs/SELF_HOSTING.md) · [**Architecture**](docs/ARCHITECTURE.md) · [**Roadmap**](ROADMAP.md)

---

## What is FloraCore?

FloraCore started with a simple question:

> What if a plant-care system could do more than water a plant when the soil becomes dry?

The result is a connected plant-care platform built around an **ESP32-S3 N16R8** and a companion web platform called **FloraOS**.

FloraCore can monitor the plant environment, automate physical actions, securely communicate with its backend, report telemetry, receive bounded commands, and update its own firmware through rollback-capable OTA.

The goal is not just automatic watering. The goal is to create a platform that can **observe, decide, act, and improve** around a living plant.

---

## Repository layout

FloraCore uses a monorepo so firmware, FloraOS, hardware, documentation, tests, and tooling can evolve together.

```text
FloraCore/
├── firmware/              ESP-IDF firmware for the ESP32-S3
├── web/                   Flask backend + FloraOS dashboard
├── hardware/              hardware notes, schematics, BOMs and mechanical work
├── docs/                  architecture, setup and security documentation
├── tools/                 project-wide development utilities
├── .github/               issue/PR templates and CI
├── CONTRIBUTING.md
├── ROADMAP.md
├── SECURITY.md
└── LICENSE
```

The historical `firmware` and `website` branches remain available as pre-monorepo references while the migration is validated.

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

Device communication then uses authenticated encryption through the FloraOS device channel:

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

See [SECURITY.md](SECURITY.md) before working on security-sensitive components.

---

## Building the components

### Firmware

```bash
cd firmware
idf.py build
```

The current firmware baseline is ESP-IDF 6.0.2. See [firmware/README.md](firmware/README.md) for component-specific notes.

### FloraOS web/backend

```bash
cd web
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Use [web/.env.example](web/.env.example) as the configuration template. Never commit real secrets or production databases.

---

## Self-hosting

FloraOS can be hosted on infrastructure you control. See [docs/SELF_HOSTING.md](docs/SELF_HOSTING.md) for the current deployment workflow, device-key provisioning requirements, and the manual firmware changes required to point a FloraCore at another FloraOS instance.

First-class secure server migration without rebuilding firmware is planned and tracked in [issue #12](https://github.com/Luqman234/FloraCore/issues/12).

---

## Contributing

Start with [CONTRIBUTING.md](CONTRIBUTING.md), then look at the repository Issues for `good first issue` and `help wanted` tasks.

The monorepo allows a single pull request to update both sides of a protocol change when needed:

```text
firmware/  ─┐
            ├── one reviewed change
web/       ─┘
```

For larger work, open or claim an issue before implementation.

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

## License

FloraCore is open-source software released under the **GNU Affero General Public License v3.0**.

See [LICENSE](LICENSE) for the full license text.

---

## FloraCore

**One core. Every system.**

Built around something alive.
