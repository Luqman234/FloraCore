#!/usr/bin/env bash

set -uo pipefail

LOG="$HOME/floracore-premerge-audit.log"

PASS_COUNT=0
WARN_COUNT=0
FAIL_COUNT=0

pass() {
    printf 'PASS  %s\n' "$*"
    PASS_COUNT=$((PASS_COUNT + 1))
}

warn() {
    printf 'WARN  %s\n' "$*"
    WARN_COUNT=$((WARN_COUNT + 1))
}

fail() {
    printf 'FAIL  %s\n' "$*"
    FAIL_COUNT=$((FAIL_COUNT + 1))
}

section() {
    echo
    echo "============================================================"
    echo "$*"
    echo "============================================================"
}

run_check() {
    local name="$1"
    shift

    echo
    echo "--- $name ---"

    if "$@"; then
        pass "$name"
    else
        local rc=$?
        fail "$name (exit $rc)"
    fi
}


# ============================================================
# FIND REPOSITORY
# ============================================================

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || true)"

if [[ -z "$ROOT" ]]; then
    echo "ERROR: Run this script from inside the FloraCore Git repository."
    read -rp "Press Enter to exit audit..."
    exit 1
fi

cd "$ROOT"

exec > >(tee "$LOG") 2>&1

TMP="$(mktemp -d -t floracore-premerge-XXXXXX)"

cleanup() {
    rm -rf "$TMP"
}

trap cleanup EXIT


# ============================================================
# KNOWN MIGRATION BASELINES
# ============================================================

FW_BASE="f3db03f7d145982d8f1ff0a39105b1097faa0781"
WEB_BASE="4a47aa1dc648fc36486886c9fec596b15b5fb8f6"
MAIN_BASE="0d1ad169f0fe24addaa086b33db5b77c871e4bc6"

if [[ -x "$ROOT/.venv-web/bin/python" ]]; then
    PY="$ROOT/.venv-web/bin/python"
elif command -v python >/dev/null 2>&1; then
    PY="$(command -v python)"
elif command -v python3 >/dev/null 2>&1; then
    PY="$(command -v python3)"
else
    echo "ERROR: Python was not found."
    read -rp "Press Enter to exit audit..."
    exit 1
fi


section "FLORACORE PRE-MERGE AUDIT"

echo "Repository: $ROOT"
echo "Branch:     $(git branch --show-current)"
echo "Commit:     $(git rev-parse --short HEAD)"
echo "Python:     $PY"
echo "Log:        $LOG"


# ============================================================
# 1. GIT STATE
# ============================================================

section "1. Git state and migration history"

run_check \
    "Fetch latest remote state" \
    git fetch origin --prune

CURRENT_BRANCH="$(git branch --show-current)"

if [[ "$CURRENT_BRANCH" == "monorepo-migration" ]]; then
    pass "Currently on monorepo-migration"
else
    warn "Current branch is '$CURRENT_BRANCH', not monorepo-migration"
fi

if [[ -z "$(git status --porcelain --untracked-files=no)" ]]; then
    pass "Tracked working tree is clean"
else
    fail "Tracked working tree contains uncommitted changes"
    git status --short
fi

run_check \
    "No whitespace/errors in PR diff" \
    git diff --check origin/main...HEAD

if git grep -n -E '^(<<<<<<< |>>>>>>> )' -- . >/dev/null 2>&1; then
    fail "Merge-conflict markers found"
    git grep -n -E '^(<<<<<<< |>>>>>>> )' -- .
else
    pass "No merge-conflict markers"
fi


# ============================================================
# 2. HISTORICAL GIT GRAPH
# ============================================================

section "2. Historical Git graph"

for commit in "$FW_BASE" "$WEB_BASE" "$MAIN_BASE"; do
    if git cat-file -e "${commit}^{commit}" 2>/dev/null; then
        pass "Historical commit exists: ${commit:0:12}"
    else
        fail "Historical commit missing: $commit"
    fi
done

if git merge-base --is-ancestor "$FW_BASE" HEAD; then
    pass "Firmware history remains reachable"
else
    fail "Firmware historical commit is not reachable"
fi

if git merge-base --is-ancestor "$WEB_BASE" HEAD; then
    pass "Website history remains reachable"
else
    fail "Website historical commit is not reachable"
fi

if git merge-base --is-ancestor "$MAIN_BASE" HEAD; then
    pass "Original main history remains reachable"
else
    fail "Original main historical commit is not reachable"
fi

if git show-ref --verify --quiet refs/remotes/origin/firmware; then
    pass "Historical origin/firmware branch retained"
else
    fail "Historical origin/firmware branch missing"
fi

if git show-ref --verify --quiet refs/remotes/origin/website; then
    pass "Historical origin/website branch retained"
else
    fail "Historical origin/website branch missing"
fi


# ============================================================
# 3. SOURCE PARITY
# ============================================================

section "3. Historical source parity"

mkdir -p "$TMP/fw-old" "$TMP/web-old"

if git archive "$FW_BASE" | tar -x -C "$TMP/fw-old"; then
    pass "Extracted historical firmware snapshot"
else
    fail "Could not extract historical firmware snapshot"
fi

if git archive "$WEB_BASE" | tar -x -C "$TMP/web-old"; then
    pass "Extracted historical website snapshot"
else
    fail "Could not extract historical website snapshot"
fi

compare_tree() {
    "$PY" - "$1" "$2" "$3" <<'PY'
from pathlib import Path
import hashlib
import sys

old = Path(sys.argv[1])
new = Path(sys.argv[2])
kind = sys.argv[3]

SKIP_PARTS = {
    ".git",
    "build",
    "managed_components",
    "__pycache__",
    ".venv",
    ".venv-web",
    ".venv-clean",
    "venv",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "node_modules",
    "dist",
}

SKIP_NAMES = {
    "sdkconfig",
    ".env",
    "users.db",
    "users.db-wal",
    "users.db-shm",
    "device_keys.json",
    ".floracore_secret",
    ".floracore_mfa_key",
}

SKIP_SUFFIXES = {
    ".pyc",
    ".pyo",
    ".bin",
    ".elf",
    ".map",
    ".o",
    ".a",
    ".so",
    ".dll",
    ".dylib",
}

# Files intentionally removed during migration.
ALLOWED_MISSING = set()

if kind == "web":
    ALLOWED_MISSING.add("publish_floraos_website_branch_v2.py")


def ignored(rel: Path) -> bool:
    if any(part in SKIP_PARTS for part in rel.parts):
        return True

    if rel.name in SKIP_NAMES:
        return True

    if rel.suffix.lower() in SKIP_SUFFIXES:
        return True

    return False


def collect(root: Path):
    result = {}

    for p in root.rglob("*"):
        if not p.is_file():
            continue

        rel = p.relative_to(root)

        if ignored(rel):
            continue

        result[str(rel)] = p

    return result


def digest(path: Path) -> str:
    h = hashlib.sha256()

    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)

    return h.hexdigest()


old_files = collect(old)
new_files = collect(new)

missing = sorted(set(old_files) - set(new_files))
extra = sorted(set(new_files) - set(old_files))

approved_missing = [
    item for item in missing
    if item in ALLOWED_MISSING
]

unexpected_missing = [
    item for item in missing
    if item not in ALLOWED_MISSING
]

modified = []

for rel in sorted(set(old_files) & set(new_files)):
    if digest(old_files[rel]) != digest(new_files[rel]):
        modified.append(rel)

print(f"Historical files: {len(old_files)}")
print(f"Current files:    {len(new_files)}")
print(f"Modified:         {len(modified)}")
print(f"Extra/new:        {len(extra)}")
print(f"Missing:          {len(missing)}")

if modified:
    print("\nModified since historical snapshot:")
    for item in modified[:60]:
        print("  M", item)

    if len(modified) > 60:
        print(f"  ... {len(modified) - 60} more")

if extra:
    print("\nNew monorepo files:")
    for item in extra[:60]:
        print("  +", item)

    if len(extra) > 60:
        print(f"  ... {len(extra) - 60} more")

if approved_missing:
    print("\nIntentional removals:")
    for item in approved_missing:
        print("  -", item)

if unexpected_missing:
    print("\nUNEXPECTED MISSING FILES:")

    for item in unexpected_missing:
        print("  !", item)

    raise SystemExit(1)

print("\nNo unexpected historical files are missing.")
PY
}

if compare_tree "$TMP/fw-old" "$ROOT/firmware" firmware; then
    pass "Firmware historical source coverage"
else
    fail "Firmware historical source coverage"
fi

if compare_tree "$TMP/web-old" "$ROOT/web" web; then
    pass "Website historical source coverage"
else
    fail "Website historical source coverage"
fi


# ============================================================
# 4. SECRET / RUNTIME STATE
# ============================================================

section "4. Secret and runtime-state audit"

if "$PY" - <<'PY'
from pathlib import Path
import subprocess
import sys

tracked = subprocess.check_output(
    ["git", "ls-files", "-z"]
).decode().split("\0")

BAD_NAMES = {
    ".env",
    "users.db",
    "users.db-wal",
    "users.db-shm",
    "device_keys.json",
    ".floracore_secret",
    ".floracore_mfa_key",
}

BAD_SUFFIXES = {
    ".pem",
    ".p12",
    ".pfx",
}

hits = []

for raw in tracked:
    if not raw:
        continue

    p = Path(raw)

    if p.name in BAD_NAMES:
        hits.append(raw)
        continue

    if p.suffix.lower() in BAD_SUFFIXES:
        hits.append(raw)

if hits:
    print("Forbidden tracked runtime/secret files:")

    for item in hits:
        print("  ", item)

    sys.exit(1)

print("No forbidden runtime/secret filenames are tracked.")
PY
then
    pass "No forbidden runtime/secret files tracked"
else
    fail "Forbidden runtime/secret file detected"
fi


# ============================================================
# 5. SECURITY / PROTOCOL INVARIANTS
# ============================================================

section "5. FloraOS security and protocol invariants"

check_pattern() {
    local description="$1"
    local pattern="$2"
    shift 2

    if grep -Eq "$pattern" "$@"; then
        pass "$description"
    else
        fail "$description"
    fi
}

check_pattern \
    "Device API remains /api/device/v1/message" \
    'DEVICE_PATH[[:space:]]*=[[:space:]]*"/api/device/v1/message"' \
    web/floraos_device_api.py

check_pattern \
    "Firmware target remains ESP32-S3" \
    'CONFIG_IDF_TARGET="esp32s3"' \
    firmware/sdkconfig.defaults

check_pattern \
    "NVS encryption remains enabled" \
    '^CONFIG_NVS_ENCRYPTION=y' \
    firmware/sdkconfig.defaults

check_pattern \
    "HMAC eFuse KEY0 configuration retained" \
    '^CONFIG_NVS_SEC_HMAC_EFUSE_KEY_ID=0' \
    firmware/sdkconfig.defaults

check_pattern \
    "OTA rollback remains enabled" \
    '^CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE=y' \
    firmware/sdkconfig.defaults

check_pattern \
    "NimBLE remains enabled" \
    '^CONFIG_BT_NIMBLE_ENABLED=y' \
    firmware/sdkconfig.defaults

check_pattern \
    "Hardware HMAC implementation remains present" \
    'esp_hmac|HMAC_UP|hmac' \
    firmware/main/floraos_crypto.c

check_pattern \
    "AES-GCM implementation remains present" \
    'gcm|GCM' \
    firmware/main/floraos_crypto.c

check_pattern \
    "Encrypted claim implementation remains present" \
    'claim' \
    firmware/main/floraos_claim.c

check_pattern \
    "Message/replay identity handling remains server-side" \
    'message_id|replay' \
    web/floraos_device_api.py


# ============================================================
# 6. PARTITION TABLE
# ============================================================

section "6. Firmware partition table"

if "$PY" - <<'PY'
from pathlib import Path
import csv
import sys

path = Path("firmware/partitions.csv")

rows = []

for raw in path.read_text().splitlines():
    raw = raw.strip()

    if not raw or raw.startswith("#"):
        continue

    row = next(csv.reader([raw]))

    row = [x.strip() for x in row]

    if len(row) < 5:
        print("Malformed partition row:", row)
        sys.exit(1)

    rows.append(row)

by_name = {row[0]: row for row in rows}

required_names = {
    "nvs",
    "otadata",
    "ota_0",
    "ota_1",
    "coredump",
}

missing = required_names - set(by_name)

if missing:
    print("Missing required partitions:")
    for name in sorted(missing):
        print("  ", name)
    sys.exit(1)

# IMPORTANT:
# SPIFFS is a subtype, not necessarily the partition NAME.
spiffs = [
    row for row in rows
    if len(row) >= 3
    and row[1] == "data"
    and row[2] == "spiffs"
]

if not spiffs:
    print("No data/spiffs partition found.")
    sys.exit(1)

print("Required named partitions are present.")

for name in sorted(required_names):
    print(" ", name, "->", by_name[name])

print("SPIFFS partition:")
for row in spiffs:
    print(" ", row)

print("Partition-table validation passed.")
PY
then
    pass "Partition table contains OTA, NVS, SPIFFS, and coredump layout"
else
    fail "Partition table validation"
fi


# ============================================================
# 7. FLORAOS WEB
# ============================================================

section "7. FloraOS Web validation"

run_check \
    "Python dependency consistency" \
    "$PY" -m pip check

run_check \
    "Compile FloraOS Web source" \
    "$PY" -m compileall -q web

run_check \
    "FloraOS Web regression suite" \
    env PYTHONPATH=web "$PY" -m unittest discover \
        -s web/tests \
        -p 'test_*.py' \
        -v

run_check \
    "FloraCore preflight" \
    env PYTHONPATH=web "$PY" \
        web/scripts/floracore_preflight.py

run_check \
    "Website publisher dry-run" \
    env PYTHONPATH=web "$PY" \
        web/publish_floraos_website_branch.py \
        --dry-run


# ============================================================
# 8. SECURITY HARNESS
# ============================================================

section "8. Local security audit harnesses"

run_check \
    "Firmware host security harness" \
    "$PY" tests/security_local/run_host.py

run_check \
    "Firmware HTTP parser security harness" \
    "$PY" tests/security_local/run_http_host.py

run_check \
    "Proposed security rules" \
    "$PY" tests/security_local/proposed_rules.py

run_check \
    "SoftAP DNS corpus dry-run" \
    "$PY" tests/security_local/softap_probe.py dns

run_check \
    "SoftAP HTTP corpus dry-run" \
    "$PY" tests/security_local/softap_probe.py http

echo
echo "NOTE:"
echo "  CONFIRMED OPEN and NOTE messages are known audit findings."
echo "  They are not treated as migration-test failures."


# ============================================================
# 9. DOCUMENTATION
# ============================================================

section "9. Documentation and repository consistency"

if "$PY" - <<'PY'
from pathlib import Path
from urllib.parse import unquote
import re
import subprocess
import sys

root = Path.cwd()

tracked = subprocess.check_output(
    ["git", "ls-files", "*.md"]
).decode().splitlines()

pattern = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")

broken = []

for raw in tracked:
    p = root / raw

    try:
        text = p.read_text(encoding="utf-8")
    except OSError:
        continue

    for lineno, line in enumerate(text.splitlines(), 1):
        for match in pattern.finditer(line):
            target = match.group(1).strip()

            if not target:
                continue

            if target.startswith(
                ("http://", "https://", "mailto:", "#")
            ):
                continue

            target = target.split("#", 1)[0]
            target = target.split("?", 1)[0]

            if not target:
                continue

            target = unquote(target)

            candidate = (p.parent / target).resolve()

            if not candidate.exists():
                broken.append(
                    f"{raw}:{lineno} -> {target}"
                )

if broken:
    print("Broken local Markdown links:")

    for item in broken:
        print("  ", item)

    sys.exit(1)

print("All checked local Markdown links resolve.")
PY
then
    pass "Documentation relative links"
else
    fail "Broken documentation links"
fi

UNCHECKED="$(
    grep -nE '^- \[ \]' MONOREPO_MIGRATION.md \
    2>/dev/null || true
)"

if [[ -n "$UNCHECKED" ]]; then
    fail "MONOREPO_MIGRATION.md still contains unchecked pre-merge items"
    echo "$UNCHECKED"
else
    pass "Monorepo migration checklist completed"
fi

if grep -q \
    "FloraCore is migrating to a monorepo" \
    README.md
then
    warn "README still describes the monorepo migration as ongoing"
else
    pass "README describes monorepo as current architecture"
fi


# ============================================================
# 10. MACHINE-SPECIFIC PATHS
# ============================================================

section "10. Portability audit"

LEGACY_PATTERN='/home/Luqman/website|/home/Luqman/ESP32_Project/FloraCore(_git)?'

if grep -RInE "$LEGACY_PATTERN" \
    web \
    tools \
    docs \
    firmware \
    --exclude=premerge_audit.sh \
    --exclude-dir=build \
    --exclude-dir=managed_components \
    --exclude-dir=__pycache__ \
    2>/dev/null
then
    fail "Active project files contain legacy machine-specific paths"
else
    pass "No legacy machine-specific paths in active project areas"
fi


# ============================================================
# 11. FIRMWARE REPRODUCIBILITY
# ============================================================

section "11. FloraOS firmware reproducibility"

if git ls-files --error-unmatch \
    firmware/sdkconfig \
    >/dev/null 2>&1
then
    fail "Generated firmware/sdkconfig is tracked"
else
    pass "Generated firmware/sdkconfig is not tracked"
fi

if git ls-files --error-unmatch \
    firmware/sdkconfig.defaults \
    >/dev/null 2>&1
then
    pass "firmware/sdkconfig.defaults is tracked"
else
    fail "firmware/sdkconfig.defaults is missing from Git"
fi

if git ls-files \
    firmware/build \
    firmware/managed_components \
    | grep -q .
then
    fail "Generated firmware build/component files are tracked"
else
    pass "Firmware build/cache directories are not tracked"
fi


# ============================================================
# 12. ESP-IDF
# ============================================================

section "12. FloraOS firmware build"

if ! command -v idf.py >/dev/null 2>&1; then

    IDF_EXPORT=""

    for candidate in \
        "$HOME/.espressif/v6.0.2/esp-idf/export.sh" \
        "$HOME/esp/v6.0.2/esp-idf/export.sh" \
        "$HOME/esp/esp-idf/export.sh"
    do
        if [[ -f "$candidate" ]]; then
            IDF_EXPORT="$candidate"
            break
        fi
    done

    if [[ -n "$IDF_EXPORT" ]]; then
        echo "Loading ESP-IDF:"
        echo "  $IDF_EXPORT"

        # shellcheck disable=SC1090
        source "$IDF_EXPORT"
    fi
fi

if command -v idf.py >/dev/null 2>&1; then

    run_check \
        "ESP-IDF environment available" \
        idf.py --version

    run_check \
        "Full FloraOS firmware build" \
        bash -c 'cd firmware && idf.py build'

else

    fail "ESP-IDF unavailable; firmware build could not be repeated"

fi


# ============================================================
# 13. GITHUB PR / CI
# ============================================================

section "13. GitHub PR / CI / protection"

if command -v gh >/dev/null 2>&1; then

    echo
    echo "--- PR #11 ---"

    gh pr view 11 \
        --repo Luqman234/FloraCore \
        --json \
        number,title,state,isDraft,mergeable,headRefName,baseRefName,url \
        || warn "Unable to query PR #11"

    PR_OK="$(
        gh pr view 11 \
            --repo Luqman234/FloraCore \
            --json state,isDraft,mergeable,baseRefName \
            --jq '
                .state == "OPEN"
                and .isDraft == false
                and .mergeable == "MERGEABLE"
                and .baseRefName == "main"
            ' \
            2>/dev/null \
            || true
    )"

    if [[ "$PR_OK" == "true" ]]; then
        pass "PR #11 is open, ready, mergeable, and targets main"
    else
        fail "PR #11 is not currently merge-ready"
    fi

    echo
    echo "--- PR checks ---"

    if gh pr checks 11 \
        --repo Luqman234/FloraCore
    then
        pass "GitHub PR checks"
    else
        fail "One or more GitHub PR checks are not successful"
    fi

    echo
    echo "--- main protection ---"

    if gh api \
        repos/Luqman234/FloraCore/branches/main/protection \
        >/tmp/floracore-protection.$$ \
        2>/dev/null
    then
        pass "main branch protection is enabled"
        cat /tmp/floracore-protection.$$
    else
        warn "main branch protection is disabled or could not be read"
    fi

    rm -f /tmp/floracore-protection.$$ 2>/dev/null || true

    echo
    echo "--- GitHub language report ---"

    if gh api \
        repos/Luqman234/FloraCore/languages
    then
        pass "GitHub language report readable"
    else
        warn "Unable to retrieve GitHub language report"
    fi

else

    warn "GitHub CLI (gh) unavailable; remote PR/protection checks skipped"

fi


# ============================================================
# 14. FINAL REPOSITORY INTEGRITY
# ============================================================

section "14. Final repository integrity"

if [[ -z "$(git status --porcelain --untracked-files=no)" ]]; then
    pass "Audit did not modify tracked source"
else
    fail "Tracked source changed during audit"
    git status --short
fi

echo
echo "--- PR diff summary ---"
git diff --stat origin/main...HEAD

echo
echo "--- Changed top-level areas ---"

git diff --name-only origin/main...HEAD \
    | cut -d/ -f1 \
    | sort \
    | uniq -c \
    | sort -nr


# ============================================================
# RESULT
# ============================================================

section "PRE-MERGE AUDIT RESULT"

echo "PASS: $PASS_COUNT"
echo "WARN: $WARN_COUNT"
echo "FAIL: $FAIL_COUNT"
echo

echo "Full log:"
echo "  $LOG"
echo

if (( FAIL_COUNT == 0 )); then

    echo "============================================"
    echo "FLORACORE PRE-MERGE AUDIT: PASS"
    echo "============================================"
    echo
    echo "No blocking failure was detected."

    if (( WARN_COUNT > 0 )); then
        echo "Review the WARN item(s) manually before merging."
    fi

else

    echo "============================================"
    echo "FLORACORE PRE-MERGE AUDIT: NOT READY"
    echo "============================================"
    echo
    echo "$FAIL_COUNT blocking check(s) need attention."

fi

echo
read -rp "Press Enter to exit audit..."

exit "$FAIL_COUNT"
