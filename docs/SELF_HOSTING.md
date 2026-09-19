# Self-hosting FloraOS

FloraOS can be run from the monorepo on infrastructure you control. This guide covers:

- running the Flask/Gunicorn application yourself
- exposing it over HTTPS
- provisioning the self-hosted backend with the device's derived network keys
- manually pointing current FloraCore firmware at the self-hosted server
- claiming the device to an account on that self-hosted instance

> Current limitation: FloraCore firmware still hard-codes the official FloraOS host and OTA origin. A first-class secure server-migration flow is planned. Until that work lands, switching a physical device to another FloraOS instance requires a firmware rebuild and reflash.

## 1. Clone the repository

```bash
git clone https://github.com/Luqman234/FloraCore.git
cd FloraCore
```

## 2. Create the FloraOS Python environment

```bash
cd web
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Copy the environment template:

```bash
cp .env.example .env
```

At minimum, generate and set your own `SECRET_KEY`. For an HTTPS deployment behind a reverse proxy, set values appropriate for your host, for example:

```text
SECRET_KEY=<your-long-random-secret>
FLORACORE_PUBLIC_URL=https://flora.example.com
FLORACORE_TRUST_PROXY=1
FLORACORE_SECURE_COOKIES=1
```

OAuth, SMTP, Turnstile, and other integrations are optional unless you choose to enable those features.

Never commit your populated `.env`, production database, or device-key registry.

## 3. Validate the backend

From `web/`:

```bash
PYTHONPATH=. python scripts/floracore_preflight.py
```

For development, the application can be started with:

```bash
python app.py
```

The development server listens on `127.0.0.1:5000`.

For a real self-hosted deployment, use Gunicorn behind an HTTPS reverse proxy or tunnel rather than exposing Flask's development server directly. A simple Gunicorn invocation is:

```bash
gunicorn -b 127.0.0.1:8000 app:app
```

Terminate TLS at your reverse proxy and forward requests to Gunicorn. The physical FloraCore device expects HTTPS.

## 4. Provision the self-hosted backend with the device's network keys

A FloraCore device authenticates with keys derived from its HMAC_UP eFuse root key. A fresh self-host does not automatically know those keys.

If you possess the original 32-byte raw HMAC provisioning key used for that device, derive only the directional network keys on a trusted machine:

```bash
python provision_device_key.py \
  --device-id floracore-aabbccddeeff \
  --hmac-key-file /secure/path/device-hmac-key.bin \
  --registry /secure/path/device_keys.json
```

Then configure FloraOS to read that registry:

```text
FLORAOS_DEVICE_KEYS_FILE=/secure/path/device_keys.json
```

The generated registry contains the derived `d2s_key` and `s2d_key`; it does not contain the raw HMAC root key.

Do not copy the raw eFuse/HMAC key onto the web server.

## 5. Manually point current firmware to the self-hosted FloraOS instance

Current firmware uses a compile-time endpoint in:

```text
firmware/main/floraos_client.c
```

Change:

```c
#define FLORAOS_ENDPOINT "https://floraos.life/api/device/v1/message"
```

to your server, for example:

```c
#define FLORAOS_ENDPOINT "https://flora.example.com/api/device/v1/message"
```

Keep the path as:

```text
/api/device/v1/message
```

because it is part of the authenticated protocol context.

### OTA origin

Current OTA policy also restricts firmware URLs to the official FloraOS origin in:

```text
firmware/main/ota_manager.c
```

The current allowed prefix is:

```text
https://floraos.life/firmware/floracore/
```

If you want the self-hosted instance to distribute OTA firmware, change the allowed prefix to your HTTPS origin, for example:

```text
https://flora.example.com/firmware/floracore/
```

Review the OTA validation code and preserve its HTTPS, project-name, version, and rollback checks. Do not broaden the allowed origin to arbitrary URLs.

The setup portal also contains user-facing links and text referring to `floraos.life`; these may be changed for a fully branded self-hosted build, but they are not the device authentication mechanism.

## 6. Build and flash the modified firmware

Activate ESP-IDF 6.0.2, then:

```bash
cd firmware
idf.py set-target esp32s3
idf.py build
idf.py -p /dev/ttyACM0 flash monitor
```

Use the serial port appropriate for your system.

## 7. Claim the device on the self-hosted instance

Ownership is local to each FloraOS database.

Create an account on the self-hosted FloraOS instance, open its Connect flow, and generate a one-time Connection Code.

The physical device must submit that token through the existing authenticated and encrypted device channel. The existing claim message remains:

```json
{
  "type": "claim",
  "payload": {
    "token": "<ONE-TIME-TOKEN>"
  }
}
```

The self-hosted backend then records its own `device_ownership` relationship.

A device can still have an old ownership row in the official `floraos.life` database. Once the firmware is pointed elsewhere, the official service will simply stop receiving its heartbeats and will eventually show it as offline. The two databases are independent.

## 8. Security model

Self-hosting must not weaken the existing device-authentication boundary.

Preserve these invariants:

- the browser does not prove device ownership merely by knowing a device ID
- claims travel through the encrypted `/api/device/v1/message` channel
- the raw HMAC eFuse root key is not stored on the web server
- device and server messages remain AES-256-GCM authenticated
- replay protection remains enabled
- OTA remains HTTPS-only and origin-restricted
- local firmware safety checks continue to apply to remote commands

## Future: first-class server migration

The manual firmware-editing workflow above is transitional.

A future server-migration feature should let the physical owner authorize a new FloraOS server without rebuilding firmware. The design should include:

- a configurable server profile stored securely on-device
- explicit owner/physical authorization before changing servers
- HTTPS-only endpoint validation
- server-specific cryptographic derivation or another mechanism that prevents one FloraOS instance from automatically inheriting another instance's authority
- a clean re-claim flow on the destination instance
- safe handling of OTA origin changes
- recovery/reset behavior if the destination server is unavailable

See the project roadmap and [issue #12](https://github.com/Luqman234/FloraCore/issues/12) for progress.
