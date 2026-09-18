# Local security harnesses

These files do not change firmware. Run from the repository root:

```sh
python3 tests/security_local/run_host.py
python3 tests/security_local/run_http_host.py
python3 tests/security_local/proposed_rules.py
python3 tests/security_local/softap_probe.py dns
python3 tests/security_local/softap_probe.py http
```

The first two compile temporary C executables from current source with host `cc`, ASan and UBSan. LeakSanitizer is disabled because the audit environment uses tracing. The HTTP handler's queue, HTTP framework and state transitions are stubbed; no Wi-Fi or NVS side effects occur. Assertions encode observed current behavior, including known undesirable acceptance, rather than claiming those inputs are securely rejected.

`proposed_rules.py` needs Python cryptography. It tests a proposed request binding gate after real AES-GCM authentication with synthetic keys, and a conservative proposed OTA URL policy. These are NOT deployed firmware changes.

`softap_probe.py` only generates a corpus unless `--live` is set. Target is fixed to 192.168.4.1, DNS port 53 or HTTP port 80. Default rate is 10 cases/second with additional health checks and delays; maximum configured rate 50. Seed defaults to 20260908. Random DNS count is configurable. Dry-run opens no sockets and writes no log.

Before any live run, obtain confirmation that the target is the owner's FloraCore, USB recovery is possible, and actuators are isolated. Do not infer identity from the IP address alone. Live HTTP requires separate explicit user approval for possible persistent setup/NVS changes. Its command-line approval flag records a prior approval; it does not replace one. No live run was performed by this audit.

Logs contain synthetic case name, index, seed, hash, length and health state; reconstruct packet bytes with the same source/seed/index. A before-send entry is flushed first so the final entry identifies the candidate on a timeout. Test sender stops at the first failed health probe or unexpected setup state, with no retries. DNS no-response is normal for malformed queries. Temporary network loss cannot by itself distinguish a crash, reboot, parser timeout, or expected setup transition; use serial diagnostics. Do not put real credentials/tokens in this corpus.

See `../../SECURITY_AUDIT_LOCAL.md` for findings, remaining limitations and the manual interruption matrix.
