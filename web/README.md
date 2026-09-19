# FloraCore — FloraOS Website / Backend

This branch contains the open-source FloraOS web application and backend for FloraCore.

FloraOS provides the browser UI, authenticated device backend, telemetry storage,
plant-care intelligence, automation, notifications, OTA distribution, account
security, and public developer API used by FloraCore.

## Security boundary

Physical devices continue to use the authenticated encrypted device transport:

`POST /api/device/v1/message`

The public website source does **not** include production secrets, per-device key
material, eFuse/HMAC keys, derived AES keys, user databases, OAuth secrets,
SMTP credentials, Turnstile secrets, or MFA encryption keys.

Create a local `.env` from `.env.example` and provide your own deployment values.

## Self-hosting

See [../docs/SELF_HOSTING.md](../docs/SELF_HOSTING.md) for running FloraOS on your own infrastructure, provisioning the local device-key registry, and manually pointing current FloraCore firmware at the self-hosted instance.

Current firmware still requires a rebuild/reflash to change FloraOS servers. First-class secure server migration is tracked in [issue #12](https://github.com/Luqman234/FloraCore/issues/12).

## License

Software in this branch is released under the GNU Affero General Public License
v3.0, as provided by the repository `LICENSE`.
