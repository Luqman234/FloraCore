# FloraOS Website Security Assessment

Date: 2026-09-08. Target: https://floraos.life only.

## Scope and limitations

Owner-authorized initial production assessment: 15 successful GET/HEAD requests, no redirects followed, no account login, credential guessing, account creation, ownership changes, hardware commands, uploads, fuzzing or availability tests. Requests can create routine server access logs; two login GETs issued anonymous session cookies. No authenticated session or production data was modified. No source fixes were made.

Reviewed source is this repository's stored `origin/website` commit `4a47aa1`. Deployment equivalence is unverified. Source findings must not be represented as reproduced production exploits. Browser/web tool could not open the site and sandbox DNS failed; approved HTTPS curl requests succeeded with normal certificate verification. Testing did not bypass TLS or Cloudflare or contact an origin IP.

## Findings

### Low — Unvalidated JSON envelope type causes an exception before authentication

- File/line: `origin/website:floraos_device_api.py:151` and `:153` at commit `4a47aa1`.
- Root cause: `request.get_json(silent=True) or {}` may yield a truthy list, string, integer or boolean. The handler immediately calls `.get()` without checking that it is a dictionary.
- Preconditions: A client can POST a non-object JSON value to the device route. No valid device identity is required to reach this operation.
- Impact: Unhandled AttributeError; normally a 500 response and error logging. No demonstrated data disclosure, authentication bypass, process crash or service-wide denial of service. Actual deployment error handling is unverified.
- Verification: `python3 tests/security_web/test_envelope_shape.py` executes the actual extracted function with request/jsonify stubs. Four truthy non-object types raise AttributeError; empty object/array/null are rejected with 400. Flask is not installed in the host interpreter; the harness tests Python handler logic, not Flask middleware. No malformed POST was sent to production.
- Minimal fix: Validate `isinstance(envelope, dict)` before accessing fields; return JSON 400 otherwise. Preserve AES-GCM authentication and all replay/claim behavior. Audit similar JSON handlers for this pattern.
- Status: Confirmed in source/local reproduction; production NOT TESTED. OPEN.

### Informational — Public readiness endpoint discloses component status

- Endpoint: GET https://floraos.life/health/ready.
- File/line: `origin/website:floraos_web_phase20.py:260`.
- Live response: HTTP 200, `{"check":"ready","details":{"database":true,"device_tables":true,"phase20":true},"ok":true,"service":"FloraCore"}`.
- Preconditions: Unauthenticated public access.
- Impact: Limited architecture/status reconnaissance. No customer data or credentials exposed in the observed response. Source also returns exception class name on errors; that failure behavior was not induced.
- Minimal fix: If detailed readiness is intended only for operators, protect that route and expose a minimal public liveness boolean. It is also reasonable to accept this small disclosure intentionally.
- Status: Confirmed live; optional hardening.

No Critical/High/Medium issue established by this limited assessment. This does not establish that none exist.

## Live test results

| Request | Observed result | Interpretation |
|---|---|---|
| GET `/` | 200 | Public home page reachable over verified HTTPS. |
| GET `/login` | 200, no-store | Session cookie has Secure, HttpOnly, SameSite=Lax. Cookie values omitted. |
| GET `/dashboard` | 302 to `/login?next=/dashboard` | Unauthenticated browser access redirected. |
| GET `/api/v1/me` | 401 | Requires bearer token. |
| GET `/api/v1/devices` | 401 | Requires bearer token. |
| GET `/api/developer/tokens` | 401 | Token management not anonymously readable. |
| GET `/api/device/latest/floracore-000000000000` | 401 | Synthetic device telemetry request denied. |
| GET `/api/device/claim/audit-nonexistent` | 401 | Synthetic claim-status request denied. |
| GET `/health/ready` | 200 | Limited status disclosure above. |
| HEAD `/.env` | 404 | Not exposed by this tested method/path. |
| HEAD `/.git/config` | 404 | Not exposed by this tested method/path. |
| HEAD `/device_keys.json` | 404 | Not exposed by this tested method/path. |
| HEAD `/users.db` | 404 | Not exposed by this tested method/path. |
| GET `/api/v1/devices`, Origin `https://audit.invalid` | 401; no Access-Control-Allow-Origin | No permissive CORS observed on this unauthenticated response. |
| GET `/login?next=https%3A%2F%2Faudit.invalid%2F` | 200; hidden nextUrl `/dashboard` | This external redirect value sanitized before login. No external target contacted. |

Observed security headers include HSTS (one year, includeSubDomains), CSP (including object-src none, base-uri self, frame-ancestors none), X-Content-Type-Options nosniff, X-Frame-Options DENY, Referrer-Policy and Permissions-Policy. CSP permits inline styles, not general inline scripts. API denials and login use no-store. Header presence is not proof against XSS or other application vulnerabilities.

HEAD 404 results are not an exhaustive secret-exposure scan. One rejected Origin does not establish CORS correctness on all endpoints. Anonymous denials do not establish cross-account isolation.

## Source observations

- AES-GCM verification precedes device processing: `floraos_device_api.py:181`.
- Request replay insertion precedes side effects in the transaction: `floraos_device_api.py:243`.
- Claim creation requires login and CSRF: `device_enrollment.py:453`.
- Claim status query scopes claim ID to session user: `device_enrollment.py:530`.
- Public API device lookup filters both user ID and device ID: `floraos_public_api.py:503`.
- Command creation checks ownership in a transaction: `floraos_public_api.py:1352`.
- API tokens use stored digests, expiry/revocation checks and scope authorization: `floraos_public_api.py:366` onward.
- Login checks CSRF and rate guards: `app.py:1194` onward. Their effectiveness was not tested through repeated login attempts.
- Firmware file serving checks resolved containment before send_file: `app.py:690`.

These observations support the design review; they do not replace authenticated penetration testing or prove every endpoint uses the same controls.

## Not tested

- Two-account IDOR and role/scope escalation; no disposable accounts supplied.
- Real login/logout, session revocation/expiry, password reset, MFA, OAuth completion, CSRF enforcement against an authenticated session.
- Live device message authentication or claim consumption during this assessment. Earlier conversation checks are not counted as current results.
- SQL injection, stored/reflected/DOM XSS, SSRF, uploads, comprehensive traversal testing, exhaustive endpoint discovery.
- Rate-limit/load/DoS testing, public credential guessing, hardware commands or OTA.
- Dependency CVE review and origin/infrastructure access.

## Next phase

Use two disposable accounts with distinct disposable records and no real actuators attached, preferably on staging or an explicitly authorized isolated local backend. Validate owner/non-owner access across telemetry, claims, tokens, commands and automation APIs. Production command/claim writes remain excluded until separately approved. Do not share real passwords in the report or test source.

PASS: Listed live anonymous-access/header checks and local handler test execution.
FINDINGS: One Low source-reproduced input-validation issue; one Informational live status disclosure.
FIXED: None; recommendations only.
NOT TESTED: Authenticated and state-changing penetration tests and other items listed above.
