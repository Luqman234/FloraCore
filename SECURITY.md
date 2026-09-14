# Security Policy

FloraCore includes internet-connected software, embedded firmware, device provisioning, remote physical actions, and OTA updates. Security reports are taken seriously.

## Reporting a vulnerability

Please **do not open a public GitHub issue containing exploit details, credentials, device secrets, or instructions that could be used to compromise deployed FloraCore systems**.

Preferred reporting path:

1. Use GitHub's private vulnerability reporting / Security Advisory feature for this repository when available.
2. Include the affected component (`firmware`, `website`, hardware, setup flow, API, OTA, BLE, etc.).
3. Describe the impact, prerequisites, reproduction steps, and the version or commit tested.
4. Use synthetic credentials and test devices. Never include real production secrets or eFuse material.

If private reporting is unavailable, contact the repository maintainer privately before publishing technical details.

## Scope

Security-relevant components include:

- ESP32-S3 firmware
- BLE administration and provisioning
- SoftAP / captive-portal setup
- device authentication and encrypted transport
- device claiming and ownership
- FloraOS accounts, sessions, MFA, and CSRF protections
- Personal Access Tokens and developer APIs
- command delivery and automation
- telemetry authorization
- OTA download, validation, rollback, and firmware metadata
- input parsing, memory safety, and state-machine transitions

## Important trust boundaries

Contributions and fixes must preserve these boundaries:

- browser/user authentication must not substitute for physical-device authentication
- a device ID alone must never prove ownership
- device claims must travel through the authenticated device channel
- owner-scoped data must remain owner-scoped
- automation must not bypass command validation or physical safety limits
- OTA must remain authenticated and recoverable
- production secrets and device key material must not be exposed

## Safe testing expectations

Security testing should only target systems you own or have explicit permission to test.

For FloraCore development, prefer:

- a recoverable test ESP32
- isolated test Wi-Fi
- staging or local FloraOS
- disposable test accounts
- copied test databases
- bounded request rates

Do not perform denial-of-service testing against public shared infrastructure, attack third-party systems, interfere with radio networks, or destroy eFuse/flash state unless you explicitly own the hardware and have intentionally accepted that risk.

## What to include in a report

Helpful reports include:

- affected commit/version
- component and file/function if known
- attacker prerequisites
- expected behavior
- observed behavior
- minimal reproduction
- impact assessment
- logs or crash traces with secrets removed
- suggested remediation if you have one

## Disclosure

Please allow reasonable time for validation and remediation before public disclosure. Confirmed issues may be documented after a fix is available so the community can learn from them without unnecessarily exposing deployed systems.
