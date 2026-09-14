# FloraCore Roadmap

FloraCore has moved beyond its original competition prototype. The next phase is focused on reliability, security, maintainability, and making the platform usable by people who did not build it.

This roadmap is directional, not a promise of exact dates.

## Phase 1 — Stabilize the foundation

Priority: **highest**

- finish known security hardening work
- improve provisioning and BLE authorization
- strengthen request/response binding
- harden OTA URL/path validation
- add regression tests for previously discovered bugs
- establish reproducible firmware and backend builds
- preserve known-good release snapshots

## Phase 2 — Developer infrastructure

- CI for backend tests and firmware builds
- cleaner deployment workflow
- staging environment
- automated backups and restore testing
- structured logging and service health monitoring
- contributor documentation and issue templates

## Phase 3 — Setup and diagnostics

- beginner-friendly secure onboarding
- clear recovery paths for failed Wi-Fi, expired claims, and interrupted setup
- guided sensor calibration
- device diagnostics
- command lifecycle visibility
- better setup and runtime error messages

## Phase 4 — Telemetry and plant intelligence

- historical telemetry views
- 24-hour, 7-day, and 30-day trends
- watering/event overlays
- meaningful plant profiles based on measurable targets
- explainable care recommendations
- confidence/quality indicators for sensor data

## Phase 5 — Automation Studio v2

- reusable templates
- better execution history
- clearer failure reasons
- richer schedules and conditions
- carefully bounded branching
- notification actions

All physical actions must continue to pass through the same command-validation and safety layers as manual control.

## Phase 6 — Hardware revision 2

- improve enclosure and serviceability
- improve water/electronics separation
- locking/reliable connectors
- easier reservoir access
- replaceable pumps
- calibration access
- cleaner cable management
- capability-gated fertilizer dosing hardware

## Phase 7 — Ecosystem growth

- versioned releases
- migration toward a cleaner repository layout
- expanded documentation
- contributor onboarding
- external testing by users who did not build FloraCore
- community-designed integrations and plant profiles

## Areas where contributors can help now

### Beginner-friendly

- documentation
- setup instructions
- tests
- dashboard copy and error messages
- calibration guides
- accessibility/UI improvements

### Intermediate

- telemetry history
- developer tooling
- diagnostics
- automation history
- API tests
- deployment documentation

### Advanced

- embedded security
- BLE authorization
- secure provisioning design
- OTA hardening
- device/backend protocol validation
- hardware revision design

## Guiding principle

FloraCore should be judged less by how impressive a ten-minute demonstration looks and more by whether another person can install it, understand it, trust it, recover it, and keep using it months later.
