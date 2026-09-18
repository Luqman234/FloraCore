# FloraCore Controlled Security Audit

## Scope

Authorized local firmware/resilience audit of `/home/Luqman/ESP32_Project/FloraCore_git`, ESP32-S3 N16R8, and owner-confirmed local SoftAP only. No requests to floraos.life, Cloudflare, or another network were made during this audit. No hardware was flashed, rebooted, power-cycled, or fuzzed. No eFuse, NVS, partition, credential, or actuator state was changed.

HMAC_UP KEY0, direction-specific AES-256-GCM, `/api/device/v1/message`, request replay protection, and encrypted claim messages remain unchanged. Proposed rules in the test directory are explicitly not production fixes.

## Environment

- Date: 2026-09-08.
- Baseline: `f3db03f` (Fix captive DNS response bounds overflow); initially clean working tree.
- Original requested directory `FloraCore` is not a Git repository. User redirected work to `FloraCore_git`.
- ESP-IDF available: v6.0.2. Host compiler: `cc`, C11, `-Wall -Wextra -Werror`, AddressSanitizer and UndefinedBehaviorSanitizer.
- Host harnesses extract functions/packet block from current source each run. HTTP framework/queue and application descriptor providers are stubs. Thus they exercise production parser code, not the ESP-IDF network stack or FreeRTOS concurrency.
- LeakSanitizer initially failed because this environment uses tracing; `detect_leaks=0` explicitly disables it. ASan bounds checking and UBSan remain enabled, with halt-on-error. No leak-testing claim is made.
- No live target identity, USB recovery, or actuator-isolation confirmation received at report creation. Live tests remain NOT TESTED.
- **Baseline `idf.py build`: PASS**, exit 0. No compiler warning/error entries found. Three SDK Kconfig notes concern boolean defaults in NimBLE/FATFS. Built ESP32-S3 application size 0x145f90; no flash command executed. Build log: `/tmp/flora-audit-build-rm7w0qbz/audit-build.log`.
- Baseline build staged under `/tmp/flora-audit-build-rm7w0qbz`, with tracked source from this checkout, existing local-development `FloraCore/sdkconfig` and cached managed components. That configuration is build input, not evidence of flashed-device configuration. No identity key file was copied.

## Findings

### Critical

None established within the performed tests. This is not a guarantee of absence.

### High

#### H1 — BLE encrypted pairing grants administration without owner authorization
- Severity: High.
- Affected file / line: `main/ble_terminal.c:189`, `:602`, `:817`; startup `main/main.c:1104`.
- Cause: GATT encryption is required, but no-input/no-output pairing has MITM authentication disabled. Dispatch has no owner or physical-presence authorization check.
- Exploitation requirements: Nearby client able to establish an encrypted BLE connection. Firmware's pairing/bond policy does not establish that the client is an administrator.
- Impact: `wifi add`, `wifi erase`, `wifi connect`, `setup start`, `claim`, boot-mode changes and `reboot` are privileged operations. `ota test` is additionally available only when its developer option is built in. Existing bonds are not checked against ownership changes. No physical authorization window is implemented. Backend ownership checks may still block an ownership transfer.
- Verification method: Source analysis only; no BLE commands or pairing attempted.
- Fix: Smallest staged upgrade: gate privileged dispatch on an explicit short physical-presence window plus per-device setup credential or an approved owner/admin bond. Revalidate at execution time, not only enqueue time. Keep general status access separately scoped. Ownership changes should invalidate prior admin authorization. Do not assume Just Works bonding proves ownership.
- Status: OPEN; proposal only. Password/token command logs are redacted; SSIDs and device ID remain exposed to paired clients. Notification sending itself does not recheck link encryption (`:205`). No raw HMAC key export was found in this path.

#### H2 — Open HTTP provisioning exposes credentials and accepts unauthenticated changes
- Severity: High.
- Affected file / line: `main/setup_portal.c:49`, `:408`, `:517`, `:1064`; `main/wifi_manager.c:525`.
- Cause: Open setup AP plus plaintext HTTP, without a client authorization or CSRF token. HTTP is not explicitly restricted to the AP interface; DNS binds INADDR_ANY (`setup_portal.c:575`). Wi-Fi connection/save happens before encrypted claim outcome (`:873`, `:891`).
- Exploitation requirements: Reachable setup service; nearby observer for capture on open Wi-Fi. STA exposure also depends on routing/interface state.
- Impact: Submitted Wi-Fi credentials and Connection Code can be observed; attacker submissions can change networking before a claim is validated. Invalid claiming does not undo local provisioning side effects. This does not forge physical-device authentication or prove backend claim bypass.
- Verification method: Source analysis and stubbed HTTP queue-acceptance tests; no real credentials or device mutation.
- Fix: Unique per-device WPA2 setup credential, short physical setup window, session-bound request token and AP-only service access. Keep actual claim consumption in encrypted device traffic.
- Status: OPEN.

### Medium

#### M1 — Response authentication lacks request binding; expiry and dedupe do not close the gap
- Severity: Medium.
- Affected file / line: `main/floraos_client.c:402`, `:544`, `:559`; `main/floraos_phase20.c:43`, `:223`, `:752`, `:896`.
- Cause: Fresh request message ID is generated, but authenticated response `reply_to` is never compared with it. Command expiry compares against that response's own server_time. Eight-entry persistent dedupe evicts older IDs; queued actions carry no expiry deadline (`:60`).
- Exploitation requirements: Ability to substitute an old valid encrypted application response through the HTTPS delivery path, or an equivalent isolated transport test. Passive Wi-Fi observation alone does not bypass TLS. Reexecuting a historical command also requires dedupe eviction and local safety gates to permit execution.
- Impact: Stale commands may become acceptable again; stale successful responses may incorrectly satisfy claim handling. Ordinary delayed responses can also outlive the intended execution expiry.
- Verification method: Source analysis; isolated AES-GCM test authenticates a stale response but the proposed binding rule rejects it. Matching reply succeeds; tampered authentication tag fails. Current firmware is not claimed fixed or dynamically end-to-end tested.
- Fix: Strict JSON object parsing, reject duplicate relevant keys, require authenticated `reply_to == current_request_id` before callbacks, enforce a bounded request age, and carry a conservative monotonic deadline to actuator execution. Keep server request replay records and command dedupe. Retain command history through the authorized replay/expiry horizon.
- Status: OPEN; isolated proposal in `tests/security_local/proposed_rules.py` passes its tests. This proposal is not a firmware implementation.

#### M2 — Setup callbacks can update a newer setup attempt
- Severity: Medium.
- Affected file / line: `main/setup_portal.c:794`, `:800`, `:832`, `:910`, `:973`.
- Cause: Claim callback ignores user_ctx and updates global state/token. New submissions are not rejected solely because an earlier claim is outstanding; replacing pending state provides no generation identifier to the callback.
- Exploitation requirements: Overlapping setup submissions with a delayed prior claim response; reachable setup service. Exact scheduling was not reproduced on FreeRTOS.
- Impact: A prior success/failure can clear the newer token or mark the wrong local attempt successful, potentially stopping setup prematurely. Does not establish incorrect backend ownership binding.
- Verification method: Source/lifetime tracing, not a runtime race test.
- Fix: Serialize provisioning attempts; use an immutable attempt/generation identifier in callback context; ignore obsolete callbacks. Do not recycle callback context until its response completes.
- Status: OPEN, source-established stale-callback path; timing NOT TESTED.

### Low

#### L1 — Form decoder permits NUL truncation, malformed escapes and duplicate ambiguity
- Severity: Low (compounds H2).
- Affected file / line: `main/setup_portal.c:338`, `:355`, `:397`, `:451`.
- Cause: strtol permits signed two-character input; incomplete percent escapes are copied; decoded NUL is accepted then strlen truncates. Duplicate fields use the first value. Control/non-UTF-8 bytes are not rejected consistently.
- Exploitation requirements: Access to provisioning handler; a syntactically valid synthetic claim token suffices to reach queueing, without backend validation.
- Impact: Unexpected/truncated settings reach provisioning. Host test shows malformed SSIDs can enqueue. No demonstrated memory corruption or claim bypass.
- Verification method: Extracted url_decode/form_value and actual connect_handler with side effects stubbed, under ASan/UBSan. NUL, incomplete/signed escapes, duplicate SSID and control bytes reproduced acceptance.
- Fix: Require exactly two hexadecimal digits; reject decoded NUL/control bytes; reject duplicate required fields; validate decoded lengths explicitly. Define SSID byte/UTF-8 policy without accidentally excluding legitimate networks.
- Status: OPEN.

#### L2 — OTA URL check accepts ambiguous paths
- Severity: Low.
- Affected file / line: `main/ota_manager.c:92`.
- Cause: String-prefix-only check permits traversal, encoded path components, query strings, fragments and double slashes.
- Exploitation requirements: Control over an accepted OTA request URL; same-origin content and normalization behavior needed for a useful bypass. No alternate-origin bypass established.
- Impact: Intended firmware-directory restriction can be undermined by path normalization. TLS, disabled redirects (`:334`) and descriptor checks (`:202`) constrain impact.
- Verification method: Extracted predicate accepts six ambiguous variants; rejects alternate hostname/scheme. Extracted candidate-description validator accepts a normal newer version and rejects wrong project/expected version. Proposed strict path predicate tested separately.
- Fix: Parse and enforce exact origin and canonical path; reject traversal/encoded separators and unneeded query/fragment syntax. Keep redirects disabled. Preserve project/version/partition checks.
- Status: OPEN; proposal only. Redirect HTTP behavior, truncated-image handling and actual OTA/rollback NOT TESTED.

#### L3 — Numeric command timestamps cast before representability validation
- Severity: Low.
- Affected file / line: `main/floraos_phase20.c:752`, `:899`.
- Cause: JSON double is converted to int64_t before finite/range checking. Equality check happens after conversion.
- Exploitation requirements: Authenticated server response containing an out-of-range numeric value; untrusted clients cannot directly forge GCM responses.
- Impact: Undefined conversion behavior can cause unpredictable command acceptance/rejection. No device crash established.
- Verification method: Source analysis; not included in runtime harness.
- Fix: Check isfinite and range (strictly less than 2^63, accounting for double rounding), integer semantics, and reasonable timestamp bounds before casting.
- Status: OPEN.

### Informational

#### I1 — Previous DNS overflow fixed before this audit; protocol strictness remains limited
- Severity: Informational.
- Affected file / line: `main/setup_portal.c:631`, `:665`, `:675`.
- Cause: Prior guard omitted four bytes; current code checks after advancing past QTYPE/QCLASS and rejects labels above 63, truncated labels and pointers.
- Exploitation requirements: Old firmware exposed to a crafted DNS query; not established against current patch.
- Impact: Historical four-byte overwrite is prevented for tested cases. Current parser does not fully validate flags, total DNS-name length or query type/class; malformed-but-bounded questions can still get an answer.
- Verification method: Original-size regression plus 30,000 seeded packets, with exact production packet block and ASan/UBSan. No hardware test.
- Fix: Bounds fix already present in baseline. Optional follow-up: validate request flags, total name length and supported type/class; choose explicit NXDOMAIN/no-answer behavior.
- Status: PRE-EXISTING FIX VERIFIED ON HOST. Not a new fix from this audit.

## Tests Performed

- `python3 tests/security_local/run_host.py`: extracted DNS regressions and 30,000 random packets (seed 20260908); current form/OTA predicates; candidate descriptor validation. Sanitizers passed. Acceptance of insecure inputs is reported as an OPEN finding, not a security pass.
- `python3 tests/security_local/run_http_host.py`: 53 handler cases with queue/HTTP stubs, including empty/oversized/missing body, disconnect mid-body, SSID and password boundaries, malformed escapes, controls, duplicates, malformed token. No actual Wi-Fi/NVS functions called.
- `python3 tests/security_local/proposed_rules.py`: synthetic AES-GCM fixtures; matching reply accepted, authentic stale reply rejected, tampered tag rejected. Separate proposed URL policy rejects ambiguous paths. Neither rule has been integrated into firmware.
- `python3 tests/security_local/softap_probe.py dns`: dry-run corpus 131 cases, maximum 1472 bytes.
- `python3 tests/security_local/softap_probe.py http`: dry-run corpus 22 cases. Bodies contain only synthetic values. Logs use test labels/hashes, not submitted credentials.
- Live runner defaults to 10 test packets/second, caps configuration at 50, checks HTTP health before/after each case, logs case identity before send and stops on health failure/state transition. Health-check latency means a failure is detected at the next check (up to timeout), not instantaneously. No background sender/retries. DNS silence alone is not considered a failure.
- Host stubs cannot establish on-device lack of stack corruption, accidental credential saves, correct ESP-IDF Content-Length handling or race freedom.

## Tests Not Performed

- ALL live DNS/HTTP/BLE/hardware tests: target/recovery/isolation confirmation pending. No private-IP packets were sent.
- Live HTTP specifically also requires approval for possible NVS/Wi-Fi changes, even with intentionally invalid test input. Tool enforces a separate flag; the flag is not itself user approval.
- Hardware stack monitoring, crash log capture, FreeRTOS race testing, bond persistence/ownership transitions, concurrent requests, allocation-failure injection and actual replay injection.
- OTA redirect exchange, truncated firmware download, interruption/resume, normal OTA installation and rollback. No claim that normal OTA works after hardening: no firmware hardening was installed.
- Backend claim/ownership changes and public-service testing. No local Flask backend was used.
- LeakSanitizer and full-system leak/UAF coverage.

### Manual interruption matrix

Every cell below is **NOT TESTED**. For each event, record serial boot/reset reason, boot-loop presence, setup status, saved-network count (not passwords), ability to reopen setup, and eventual encrypted claim outcome. Take one event at a time; no repeated automated power cycling. Use USB-only isolated hardware with actuators disconnected. Obtain approval before persistent-state mutation. Do not erase NVS as routine recovery.

| Setup state | Normal reboot | One manual power cycle | Wi-Fi loss | Source-derived expectation / uncertainty |
|---|---|---|---|---|
| Idle | NOT TESTED | NOT TESTED | NOT TESTED | Boot uses saved credentials/pending marker; RAM state resets. |
| Credential submission | NOT TESTED | NOT TESTED | NOT TESTED | Partial body should not enqueue; queue contents are volatile. |
| Wi-Fi connection | NOT TESTED | NOT TESTED | NOT TESTED | Connection attempt may abort; inspect which credentials remain persisted. |
| Wi-Fi connected | NOT TESTED | NOT TESTED | NOT TESTED | Credential save and setup-pending marker are separate writes; interruption window needs examination. |
| Claim pending | NOT TESTED | NOT TESTED | NOT TESTED | Token is RAM-only; reboot requires a new/resubmitted code. Transport failures retry while running. |
| Claim success | NOT TESTED | NOT TESTED | NOT TESTED | Backend bind may precede local pending-marker clear; confirm recovery after lost response. |
| Setup exit | NOT TESTED | NOT TESTED | NOT TESTED | HTTP/DNS/AP shutdown sequencing and restart races require hardware validation. |

Recovery: stop the test sender, capture serial diagnostics, reconnect USB, perform a single normal reboot. If needed prepare a known-good image and obtain explicit approval before reflashing. Do not change eFuses, partitions or erase flash. Physical USB access alone does not prove recovery until tested.

## Firmware Changes

None. No `main/`, partition table, build configuration or cryptographic source changed. Added report and `tests/security_local/` only. No flash is proposed in this audit. Firmware recommendations remain reviewable follow-up work.

## Remaining Risks

Host coverage does not replace ESP-IDF socket/parser, FreeRTOS, NVS fault-injection, power-loss or hardware validation. BLE/setup authorization remains the highest immediate exposure. Response binding and attempt-generation isolation remain unimplemented. SDK configuration is not committed; a successful staged build cannot prove presentation hardware is running the audited commit/settings.

## Presentation-Day Recommendation

Keep the known-good firmware; do not apply an unbuilt/unflashed experimental patch for presentation. Prefer physical isolation and minimizing time with setup/BLE administration exposed. Resolve the OPEN findings in a separate focused patch with baseline build and USB recovery validation. Do not enable destructive OTA test commands. No eFuse or flash-erasure changes are needed for these recommendations.

PASS: Isolated sanitizer/parser and proposed-rule tests listed above; dry-run corpus generation; staged ESP-IDF baseline build.
FIXED: No new firmware fixes. Existing DNS bounds patch verified on host.
OPEN: BLE/setup authorization, response freshness, setup callback generation, form validation, OTA paths, numeric casts.
NOT TESTED: Live hardware/network resilience, interruption matrix, installed OTA/rollback, runtime races and persistent-state behavior.
