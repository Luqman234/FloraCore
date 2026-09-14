# Contributing to FloraCore

Thank you for considering contributing to FloraCore.

FloraCore is an open-source ESP32-S3 plant-care ecosystem that spans embedded firmware, FloraOS, hardware, automation, telemetry, security, and plant-care logic. You do **not** need to understand the whole system before contributing.

## Where to contribute

The repository currently uses separate branches for the two main software components:

- `main` — project overview, contributor docs, roadmap, and public entry point
- `firmware` — ESP-IDF firmware for FloraCore devices
- `website` — FloraOS Flask backend and web dashboard

## Good ways to start

Look for issues labeled `good first issue` or `help wanted`. Good first contributions include:

- documentation improvements
- test coverage
- clearer error messages
- small dashboard/UI improvements
- developer tooling
- firmware build/documentation fixes
- sensor calibration documentation

Please avoid starting with security-sensitive device authentication, eFuse provisioning, OTA trust, or ownership logic unless you have discussed the change first.

## Development workflow

1. Fork the repository.
2. Create a focused branch from the component branch you want to change.
3. Make one logically scoped change.
4. Test it locally.
5. Commit with a clear message.
6. Open a pull request describing what changed, why, and how it was tested.

Example branch names:

```text
fix/setup-error-message
feature/telemetry-chart
docs/firmware-build-guide
test/ownership-isolation
```

## Pull request expectations

A good pull request should:

- solve one clear problem
- avoid unrelated refactors
- explain user-visible behavior changes
- include tests when practical
- preserve existing security boundaries
- avoid committing secrets, databases, credentials, device keys, Wi-Fi passwords, `.env` files, or eFuse material
- update documentation when behavior changes

For firmware changes, include the ESP-IDF version used and whether `idf.py build` succeeds.

For backend changes, include the tests you ran and any database migration impact.

## Security-sensitive areas

FloraCore has several trust boundaries that contributors must preserve:

- physical-device identity is separate from browser/user authentication
- device traffic uses the authenticated device channel
- ownership must be enforced server-side
- automation must use the same bounded command validation as manual control
- OTA must remain authenticated and rollback-capable
- production secrets and eFuse key material must never be committed

If you believe you found a vulnerability, **do not open a public issue with exploit details**. See [SECURITY.md](SECURITY.md).

## Coding style

Prefer code that is explicit, testable, and easy to audit over clever abstractions. In security- or hardware-critical code, readability is a feature.

Keep comments focused on *why* a constraint exists, especially around bounds checks, state machines, cryptography, ownership, OTA, and physical safety.

## Scope before implementation

For larger changes, open an issue first. This helps avoid duplicate work and lets maintainers confirm that the design fits the project direction.

Good issue proposals include:

- what problem you are solving
- who benefits
- the proposed behavior
- security or hardware implications
- what you plan to test

## Hardware contributions

When proposing hardware changes, include:

- affected components
- voltage/current requirements
- connector assumptions
- safety considerations
- whether existing firmware remains compatible
- photos, diagrams, schematics, or measurements when useful

Never recommend unsafe mains wiring as part of a FloraCore contribution.

## Community expectations

Be respectful, specific, and constructive. Review the idea or code, not the person. Beginners are welcome.

## License

By contributing, you agree that your contribution may be distributed under the repository's GNU Affero General Public License v3.0 terms.

## Need a starting point?

Open the Issues tab and pick a `good first issue`. If an issue is unclear, ask a question on that issue before starting.
