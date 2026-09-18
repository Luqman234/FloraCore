#!/usr/bin/env python3
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import os
import re
import shutil
import subprocess
import sys
import tempfile


REPO = "https://github.com/Luqman234/FloraCore.git"
BRANCH = "website"
SOURCE = Path("/home/Luqman/website")

# Never publish these.
EXCLUDED_NAMES = {
    ".env",
    "users.db",
    "users.db-wal",
    "users.db-shm",
    "device_keys.json",
    ".floracore_secret",
    ".floracore_mfa_key",
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "node_modules",
    "build",
    "dist",
    ".source_parts",
    ".source_xz",
}

EXCLUDED_SUFFIXES = {
    ".pyc", ".pyo", ".bin", ".elf", ".map", ".o", ".a",
    ".so", ".dll", ".dylib", ".zip", ".tar", ".gz", ".xz", ".7z",
}

# Keep the public branch focused on actual website/backend source.
SKIP_PREFIXES = (
    "backup-before-",
    "backup_",
    "backup-",
)

SKIP_FILE_PREFIXES = (
    "patch_",
    "fix_",
    "restore_",
    "collect_",
    "diagnose_",
)

# Obvious secret patterns. This is intentionally conservative.
SECRET_PATTERNS = [
    re.compile(r"(?i)(password|secret|api[_-]?key|client[_-]?secret|private[_-]?key)\s*=\s*['\"][^'\"]{8,}['\"]"),
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]{20,}"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
]

TEXT_SUFFIXES = {
    ".py", ".html", ".css", ".js", ".txt", ".md", ".json",
    ".toml", ".ini", ".cfg", ".yaml", ".yml", ".sql", ".csv",
}

SPECIAL_TEXT_NAMES = {
    "requirements.txt",
    "requirements-dev.txt",
    "pyproject.toml",
    "Pipfile",
    "Pipfile.lock",
    "poetry.lock",
    "Procfile",
    "Dockerfile",
    ".gitignore",
}


def run(cmd: list[str], cwd: Path | None = None, check: bool = True) -> subprocess.CompletedProcess[str]:
    print("+", " ".join(cmd))
    return subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=check,
    )


def should_copy(path: Path) -> bool:
    rel = path.relative_to(SOURCE)

    if any(part in EXCLUDED_NAMES for part in rel.parts):
        return False
    if any(part.startswith(SKIP_PREFIXES) for part in rel.parts):
        return False
    if path.name.startswith(SKIP_FILE_PREFIXES):
        return False
    if path.suffix.lower() in EXCLUDED_SUFFIXES:
        return False

    # Only publish text/source files and known source directories.
    if path.name in SPECIAL_TEXT_NAMES:
        return True
    return path.suffix.lower() in TEXT_SUFFIXES


def copy_source(destination: Path) -> int:
    count = 0
    for path in sorted(SOURCE.rglob("*")):
        if not path.is_file() or not should_copy(path):
            continue
        rel = path.relative_to(SOURCE)
        target = destination / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)
        count += 1
    return count


def env_example() -> str:
    env_path = SOURCE / ".env"
    if not env_path.exists():
        return (
            "# FloraOS environment template\n"
            "# Copy to .env and fill values locally. Never commit real secrets.\n"
        )

    keys: list[str] = []
    for raw in env_path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key = line.split("=", 1)[0].strip()
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
            keys.append(key)

    lines = [
        "# FloraOS environment template",
        "# Copy to .env and fill values locally. Never commit real secrets.",
        "",
    ]
    for key in sorted(set(keys)):
        lines.append(f"{key}=")
    return "\n".join(lines) + "\n"


def scan_secrets(root: Path) -> list[str]:
    """
    Conservative source scan with placeholder awareness.

    Safe documentation examples such as:
      Bearer flora_pat_YOUR_TOKEN
      CLIENT_SECRET="YOUR_CLIENT_SECRET"
      API_KEY="REPLACE_ME"

    are not treated as real credentials.

    Real-looking matches are reported only as file:line + rule. The suspected
    value itself is never printed.
    """
    placeholder_markers = {
        "YOUR_TOKEN",
        "YOUR_API_KEY",
        "YOUR_CLIENT_SECRET",
        "YOUR_SECRET",
        "REPLACE_ME",
        "REPLACEME",
        "CHANGE_ME",
        "CHANGEME",
        "EXAMPLE",
        "PLACEHOLDER",
        "REDACTED",
        "DUMMY",
        "TEST_TOKEN",
        "TEST_SECRET",
    }

    rules = [
        (
            "credential assignment",
            re.compile(
                r"(?i)(password|secret|api[_-]?key|client[_-]?secret|private[_-]?key)"
                r"\s*=\s*['\"]([^'\"]{8,})['\"]"
            ),
        ),
        (
            "bearer token",
            re.compile(r"(?i)bearer\s+([A-Za-z0-9._~+/=-]{20,})"),
        ),
        (
            "private key",
            re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        ),
    ]

    def looks_like_placeholder(value: str) -> bool:
        upper = value.upper()
        if any(marker in upper for marker in placeholder_markers):
            return True

        obvious_words = (
            "TOKEN",
            "SECRET",
            "PASSWORD",
            "EXAMPLE",
            "PLACEHOLDER",
            "REPLACE",
            "CHANGEME",
            "REDACTED",
        )
        if any(word in upper for word in obvious_words):
            letters = sum(ch.isalpha() for ch in value)
            digits = sum(ch.isdigit() for ch in value)
            symbols = sum(not ch.isalnum() for ch in value)
            if digits <= 4 and symbols <= 8 and letters >= 4:
                return True

        return False

    hits: list[str] = []

    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if path.name == "LICENSE":
            continue
        if path.suffix.lower() not in TEXT_SUFFIXES and path.name not in SPECIAL_TEXT_NAMES:
            continue

        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        for line_no, line in enumerate(source.splitlines(), start=1):
            for rule_name, rule in rules:
                match = rule.search(line)
                if not match:
                    continue

                if rule_name == "private key":
                    hits.append(f"{path.relative_to(root)}:{line_no} [{rule_name}]")
                    continue

                value = match.group(match.lastindex or 0)
                if looks_like_placeholder(value):
                    continue

                hits.append(f"{path.relative_to(root)}:{line_no} [{rule_name}]")

    return sorted(set(hits))

def ensure_gitignore(root: Path) -> None:
    gitignore = root / ".gitignore"
    existing = gitignore.read_text(encoding="utf-8", errors="replace") if gitignore.exists() else ""
    required = """
# FloraOS local/private state
.env
.env.*
!.env.example
users.db
users.db-*
device_keys.json
.floracore_secret
.floracore_mfa_key
.venv/
venv/
__pycache__/
*.py[cod]
.pytest_cache/
.mypy_cache/
.ruff_cache/
backup-before-*/
backup_*/
backup-*/
firmware/**/*.bin
*.elf
*.map
"""
    if "# FloraOS local/private state" not in existing:
        gitignore.write_text(existing.rstrip() + "\n\n" + required.lstrip(), encoding="utf-8")


def website_readme() -> str:
    return """# FloraCore — FloraOS Website / Backend

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

## License

Software in this branch is released under the GNU Affero General Public License
v3.0, as provided by the repository `LICENSE`.
"""


def main() -> int:
    if not SOURCE.is_dir() or not (SOURCE / "app.py").exists():
        print(f"ERROR: FloraOS website source not found at {SOURCE}", file=sys.stderr)
        return 2

    # Confirm current source imports before publishing.
    if (SOURCE / ".venv" / "bin" / "python").exists():
        py = SOURCE / ".venv" / "bin" / "python"
        result = run(
            [str(py), "-m", "py_compile", str(SOURCE / "app.py")],
            cwd=SOURCE,
            check=False,
        )
        print(result.stdout, end="")
        if result.returncode:
            print("ERROR: app.py does not compile; refusing to publish.", file=sys.stderr)
            return 3

    with tempfile.TemporaryDirectory(prefix="floracore-website-publish-") as tmp:
        work = Path(tmp) / "FloraCore"

        result = run(["git", "clone", REPO, str(work)], check=False)
        print(result.stdout, end="")
        if result.returncode:
            print("ERROR: git clone failed.", file=sys.stderr)
            return result.returncode

        run(["git", "fetch", "origin"], cwd=work)

        # The website branch already exists in the repository.
        result = run(
            ["git", "checkout", "-B", BRANCH, f"origin/{BRANCH}"],
            cwd=work,
            check=False,
        )
        print(result.stdout, end="")
        if result.returncode:
            print(f"ERROR: could not check out origin/{BRANCH}.", file=sys.stderr)
            return result.returncode

        # Preserve Git metadata and the root AGPL license, replace everything else.
        for child in list(work.iterdir()):
            if child.name in {".git", "LICENSE"}:
                continue
            if child.is_dir():
                shutil.rmtree(child)
            else:
                child.unlink()

        count = copy_source(work)

        # Public-release support files.
        (work / ".env.example").write_text(env_example(), encoding="utf-8")
        (work / "README.md").write_text(website_readme(), encoding="utf-8")
        ensure_gitignore(work)

        # Ensure old archive-staging directories are gone.
        shutil.rmtree(work / ".source_parts", ignore_errors=True)
        shutil.rmtree(work / ".source_xz", ignore_errors=True)

        hits = scan_secrets(work)
        if hits:
            print("\nSECURITY STOP: possible real embedded secrets detected:")
            for item in hits:
                print("  ", item)
            print("\nKnown documentation placeholders are ignored. Nothing was committed or pushed.")
            return 4

        # Basic source sanity.
        pyfiles = [str(p) for p in work.rglob("*.py")]
        if pyfiles:
            result = run(
                [sys.executable, "-m", "py_compile", *pyfiles],
                cwd=work,
                check=False,
            )
            print(result.stdout, end="")
            if result.returncode:
                print("ERROR: copied Python source failed syntax validation.", file=sys.stderr)
                return 5

        run(["git", "add", "-A"], cwd=work)
        status = run(["git", "status", "--short"], cwd=work)
        print(status.stdout, end="")

        if not status.stdout.strip():
            print("\nWebsite branch is already up to date.")
            return 0

        stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        commit = run(
            ["git", "commit", "-m", f"Publish FloraOS website source ({stamp})"],
            cwd=work,
            check=False,
        )
        print(commit.stdout, end="")
        if commit.returncode:
            print("ERROR: git commit failed. Check git user.name/user.email.", file=sys.stderr)
            return commit.returncode

        push = run(["git", "push", "origin", BRANCH], cwd=work, check=False)
        print(push.stdout, end="")
        if push.returncode:
            print(
                "\nERROR: push failed. GitHub authentication may need to be refreshed.",
                file=sys.stderr,
            )
            return push.returncode

        print()
        print("FloraOS WEBSITE SOURCE: PUBLISHED")
        print(f"Repository: Luqman234/FloraCore")
        print(f"Branch:     {BRANCH}")
        print(f"Files:      {count}")
        print("Secrets:    sanitized / scan passed")
        print("Old .source_parts/.source_xz staging: removed")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
