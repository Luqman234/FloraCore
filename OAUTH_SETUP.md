# FloraCore Google + GitHub sign-in setup

The code is already wired for OAuth. The provider buttons become active only when the corresponding client ID and client secret are present in the server environment.

## Callback URLs for floraos.life

Configure these **exact** HTTPS callback URLs at the providers:

```text
Google: https://floraos.life/auth/google/callback
GitHub: https://floraos.life/auth/github/callback
```

FloraCore does not store Google or GitHub access tokens. The token is used during the callback only to retrieve a verified identity, then discarded. The local database stores the stable provider user ID and the linked FloraCore user ID.

## 1. Google

1. Open Google Cloud Console and select/create a project for FloraCore.
2. Configure the OAuth consent screen / branding for the project.
3. Create an OAuth client with application type **Web application**.
4. Add this Authorized redirect URI exactly:

   ```text
   https://floraos.life/auth/google/callback
   ```

5. Copy the generated **Client ID** and **Client secret**.
6. Set them on the FloraCore server as `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET`.

FloraCore requests only:

```text
openid email profile
```

The backend accepts the Google identity only when Google returns a verified email address.

If the Google OAuth app is still in testing mode, only accounts allowed by your Google project configuration may be able to sign in.

## 2. GitHub

For this lightweight identity-only integration, create a GitHub **OAuth App**:

1. GitHub → Settings → Developer settings → OAuth apps.
2. Choose **New OAuth App** / **Register a new application**.
3. Application name: `FloraCore`.
4. Homepage URL:

   ```text
   https://floraos.life
   ```

5. Authorization callback URL:

   ```text
   https://floraos.life/auth/github/callback
   ```

6. Keep callback matching exact; do not enable wildcard callback matching unless you have a specific reason to need it.
7. Register the app and generate/copy the **Client ID** and **Client secret**.
8. Set them on the FloraCore server as `GITHUB_CLIENT_ID` and `GITHUB_CLIENT_SECRET`.

FloraCore requests read-only identity scopes:

```text
read:user user:email
```

The backend calls GitHub's email endpoint and only accepts a **verified** email. It prefers the primary verified address. GitHub PKCE (`S256`) is enabled in addition to OAuth state validation.

## 3. Production environment

Recommended environment for your current Cloudflare Tunnel deployment:

```text
SECRET_KEY=<long-random-secret>
FLORACORE_PUBLIC_URL=https://floraos.life
FLORACORE_TRUST_PROXY=1
FLORACORE_SECURE_COOKIES=1
GOOGLE_CLIENT_ID=<google-client-id>
GOOGLE_CLIENT_SECRET=<google-client-secret>
GITHUB_CLIENT_ID=<github-client-id>
GITHUB_CLIENT_SECRET=<github-client-secret>
```

Generate the Flask secret once:

```bash
python -c 'import secrets; print(secrets.token_hex(32))'
```

Never put the OAuth client secrets in HTML, JavaScript, a public Git repository, or the browser. They belong on the backend only.

### systemd example

Create a private environment file:

```bash
sudo nano /etc/floracore.env
```

Put the variables above in it, then protect it:

```bash
sudo chmod 600 /etc/floracore.env
```

In your FloraCore systemd service, add:

```ini
EnvironmentFile=/etc/floracore.env
```

Then reload and restart:

```bash
sudo systemctl daemon-reload
sudo systemctl restart floraos
```

Use the actual service name if yours is not `floraos`.

## 4. Install the new dependency

The updated project uses Authlib for the OAuth/OIDC client flow:

```bash
source .venv/bin/activate
pip install -r requirements.txt
```

Then restart Gunicorn/Flask.

## 5. What happens when someone clicks a provider

```text
FloraCore /login
       ↓
Google or GitHub authorization page
       ↓
Provider sends an authorization code back to FloraCore
       ↓
FloraCore validates OAuth state (and GitHub PKCE)
       ↓
FloraCore exchanges the code server-side
       ↓
Verified provider identity/email is read
       ↓
Existing matching account is linked, or a new FloraCore ID is created
       ↓
Provider token is discarded
       ↓
FloraCore session → /dashboard
```

An OAuth identity is linked by the provider's stable user ID, not by repeatedly trusting the email on every future login.

## Local testing

The production credentials should use the public HTTPS callback URLs above. For local OAuth testing, create separate development OAuth credentials/callbacks rather than weakening the production callback rules.
