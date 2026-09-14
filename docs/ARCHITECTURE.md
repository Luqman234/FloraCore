# FloraCore Architecture

This document gives contributors a fast mental model of the ecosystem. It intentionally focuses on trust boundaries and component responsibilities rather than every implementation detail.

## Repository layout today

The repository currently separates major software components by branch:

- `main` — project overview, roadmap, contributor and security docs
- `firmware` — ESP-IDF firmware for ESP32-S3
- `website` — Flask-based FloraOS backend and dashboard

A future monorepo migration is planned, but contributors should work with the current branch structure unless an issue says otherwise.

## High-level system

```text
Sensors / pumps / lighting
          │
          ▼
   ESP32-S3 FloraCore
          │
          │ authenticated + encrypted device channel
          ▼
POST /api/device/v1/message
          │
          ▼
      FloraOS backend
      ├─ device authentication
      ├─ ownership
      ├─ telemetry
      ├─ command queue
      ├─ automation
      ├─ OTA metadata
      └─ account/API services
          │
          ├──────────────┐
          ▼              ▼
      Dashboard      Developer API
```

## Firmware responsibilities

The device firmware is responsible for:

- local sensor acquisition
- pump/light actuation
- local safety boundaries
- Wi-Fi and BLE runtime
- setup/provisioning state
- authenticated device messaging
- heartbeat and telemetry
- bounded command execution
- OTA download and rollback validation

The firmware must not assume that a remote command is safe merely because it arrived from the backend. Local safety checks remain important.

## Device identity and transport

Physical-device identity is rooted in an ESP32-S3 HMAC_UP eFuse key. The raw root key is not intended to be exposed to normal application logic.

Direction-specific cryptographic material is derived and used for authenticated encryption between the physical device and FloraOS.

Conceptually:

```text
HMAC_UP eFuse root
       │
       ▼
derived directional keys
       │
       ▼
AES-256-GCM protected messages
       │
       ▼
/api/device/v1/message
```

The backend authenticates and decrypts the device message before applying device-side effects such as claim handling or telemetry storage.

## Ownership model

Knowing a device ID is not ownership.

A user obtains a short-lived claim token through FloraOS. The physical device submits that token through the authenticated device channel. The backend then binds ownership after validating both the device identity and the claim.

Browser input must never be trusted as proof that a user physically controls a device.

## Commands

Remote physical commands are deliberately bounded.

Typical examples include watering and grow-light control. Commands are validated server-side and must also be treated defensively by firmware.

Automation uses the same command path rather than bypassing command validation.

## Automation

Automation Studio evaluates trusted device state and can enqueue bounded actions.

The current design favors simple, auditable automation over arbitrary code execution. Contributors should preserve that principle when proposing new automation features.

## OTA

FloraCore uses ESP-IDF OTA with dual application slots and rollback support.

A new image is installed as a candidate. The device validates health after boot; a failed candidate can be rolled back by the bootloader.

Remote firmware control must remain separated from general user API authority.

## FloraOS backend

FloraOS provides:

- user accounts and sessions
- MFA/account security
- device ownership
- device message processing
- telemetry/state storage
- command queues
- Automation Studio
- OTA metadata/services
- plant profiles
- owner-scoped developer API

The browser/API trust plane is intentionally separate from physical-device authentication.

## Public developer API

Developer access uses user-scoped Personal Access Tokens. PAT authorization does not replace device cryptographic authentication and must not grant raw device-identity authority.

## Online status

Device online state should be based on recent authenticated heartbeat data, not merely ownership, old telemetry, or a browser assertion.

## Security boundaries contributors should preserve

When changing code, ask which side of these boundaries it belongs to:

```text
browser/user session  != physical-device identity
PAT                   != physical-device identity
device ID             != ownership
automation            != safety bypass
OTA metadata access   != arbitrary firmware control
telemetry presence    != live heartbeat
```

## Where to start

For contribution workflow, see [../CONTRIBUTING.md](../CONTRIBUTING.md).

For project priorities, see [../ROADMAP.md](../ROADMAP.md).

For vulnerability reporting, see [../SECURITY.md](../SECURITY.md).
