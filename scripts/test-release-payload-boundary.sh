#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/ryk-release-payload-boundary.XXXXXX")"
trap 'rm -rf "$TMP_ROOT"' EXIT INT TERM

# Write NAME=value at runtime so this script is itself releasable.
write_assignment() {
  printf '%s=%s\n' "$2" "$3" > "$1"
}

SOURCE="$TMP_ROOT/source"
STAGED="$TMP_ROOT/staged"
mkdir -p "$SOURCE/docs" "$SOURCE/scripts"
cp "$ROOT/scripts/stage-release-payload.sh" "$SOURCE/scripts/"
printf '%s\n' 'tracked documentation' > "$SOURCE/docs/guide.md"
write_assignment "$SOURCE/docs/.env" OPENAI_API_KEY 'sk-Live''LookingIgnoredSecret1234567890'

git -C "$SOURCE" init -q
git -C "$SOURCE" add docs/guide.md scripts/stage-release-payload.sh
git -C "$SOURCE" -c user.name=ryk-test -c user.email=ryk-test@example.invalid commit -qm fixture

bash "$SOURCE/scripts/stage-release-payload.sh" "$SOURCE" "$STAGED"
test -f "$STAGED/docs/guide.md"
test ! -e "$STAGED/docs/.env"

write_assignment "$STAGED/docs/leak.txt" GITHUB_TOKEN 'ghp_AbCdEf''0123456789AbCdEf0123456789'
if bash "$ROOT/scripts/check-release-payload-secrets.sh" "$STAGED" >/dev/null 2>&1; then
  printf '%s\n' 'release-payload-boundary: secret scanner accepted credential-shaped content' >&2
  exit 1
fi
rm "$STAGED/docs/leak.txt"

write_assignment "$STAGED/docs/leak.txt" PASSWORD generated-at-runtime-but-real
if bash "$ROOT/scripts/check-release-payload-secrets.sh" "$STAGED" >/dev/null 2>&1; then
  printf '%s\n' 'release-payload-boundary: scanner accepted placeholder-suffixed credential' >&2
  exit 1
fi
rm "$STAGED/docs/leak.txt"

# The real tracked repository payload must remain releasable in directory and
# archive form; content-specific synthetic placeholders must not false-positive.
REAL_STAGED="$TMP_ROOT/real-staged"
bash "$ROOT/scripts/stage-release-payload.sh" "$ROOT" "$REAL_STAGED"
bash "$ROOT/scripts/check-release-payload-secrets.sh" "$REAL_STAGED"
tar -czf "$TMP_ROOT/real-payload.tar.gz" -C "$REAL_STAGED" .
bash "$ROOT/scripts/check-release-payload-secrets.sh" "$TMP_ROOT/real-payload.tar.gz"
cp "$REAL_STAGED/docs/credentials.md" "$TMP_ROOT/credentials.md.clean"
printf '%s=%s\n' PASSWORD actual-low-entropy-release-secret >> "$REAL_STAGED/docs/credentials.md"
if bash "$ROOT/scripts/check-release-payload-secrets.sh" "$REAL_STAGED" >/dev/null 2>&1; then
  printf '%s\n' 'release-payload-boundary: scanner accepted injection into reviewed synthetic file' >&2
  exit 1
fi
cp "$TMP_ROOT/credentials.md.clean" "$REAL_STAGED/docs/credentials.md"
write_assignment "$STAGED/docs/leak.txt" AWS_ACCESS_KEY_ID 'ASIA''0123456789ABCDEF'
if bash "$ROOT/scripts/check-release-payload-secrets.sh" "$STAGED" >/dev/null 2>&1; then
  printf '%s\n' 'release-payload-boundary: scanner accepted temporary AWS credentials' >&2
  exit 1
fi
printf '%s\n' 'synthetic fixture note' '-----BEGIN PRIV''ATE KEY-----' 'AbCdEf0123456789AbCdEf0123456789' '-----END PRIV''ATE KEY-----' > "$STAGED/docs/leak.txt"
if bash "$ROOT/scripts/check-release-payload-secrets.sh" "$STAGED" >/dev/null 2>&1; then
  printf '%s\n' 'release-payload-boundary: synthetic text bypassed private-key rejection' >&2
  exit 1
fi
rm "$STAGED/docs/leak.txt"
bash "$ROOT/scripts/check-release-payload-secrets.sh" "$STAGED" >/dev/null

write_assignment "$STAGED/docs/leak.txt" PASSWORD hunter2
if bash "$ROOT/scripts/check-release-payload-secrets.sh" "$STAGED" >/dev/null 2>&1; then
  printf '%s\n' 'release-payload-boundary: scanner accepted a low-entropy password assignment' >&2
  exit 1
fi

write_assignment "$STAGED/docs/leak.txt" PGPASSWORD hunter2
if bash "$ROOT/scripts/check-release-payload-secrets.sh" "$STAGED" >/dev/null 2>&1; then
  printf '%s\n' 'release-payload-boundary: scanner accepted PGPASSWORD assignment' >&2
  exit 1
fi
write_assignment "$STAGED/docs/leak.txt" SECRET_KEY django-insecure-xxx
if bash "$ROOT/scripts/check-release-payload-secrets.sh" "$STAGED" >/dev/null 2>&1; then
  printf '%s\n' 'release-payload-boundary: scanner accepted SECRET_KEY assignment' >&2
  exit 1
fi
rm "$STAGED/docs/leak.txt"

mkdir -p "$STAGED/fixtures/adversarial"
write_assignment "$STAGED/fixtures/adversarial/real-secret.txt" PASSWORD correct-horse-battery-staple
if bash "$ROOT/scripts/check-release-payload-secrets.sh" "$STAGED" >/dev/null 2>&1; then
  printf '%s\n' 'release-payload-boundary: scanner exempted a fixture credential' >&2
  exit 1
fi
rm "$STAGED/fixtures/adversarial/real-secret.txt"

write_assignment "$STAGED/docs/leak.txt" PASSWORD 'p@$$w0rd'
if bash "$ROOT/scripts/check-release-payload-secrets.sh" "$STAGED" >/dev/null 2>&1; then
  printf '%s\n' 'release-payload-boundary: scanner treated dollar signs as placeholders' >&2
  exit 1
fi
write_assignment "$STAGED/docs/leak.txt" database_password hunter2
if bash "$ROOT/scripts/check-release-payload-secrets.sh" "$STAGED" >/dev/null 2>&1; then
  printf '%s\n' 'release-payload-boundary: scanner missed a lowercase credential name' >&2
  exit 1
fi
rm "$STAGED/docs/leak.txt"
write_assignment "$STAGED/docs/leak.txt" DATABASE_URL "postgres:"'//admin:S3cr3t@db.internal/app'
if bash "$ROOT/scripts/check-release-payload-secrets.sh" "$STAGED" >/dev/null 2>&1; then
  printf '%s\n' 'release-payload-boundary: scanner accepted URI userinfo credentials' >&2
  exit 1
fi
rm "$STAGED/docs/leak.txt"

write_assignment "$TMP_ROOT/outside-secret" PASSWORD outside-release-boundary
ln -s "$TMP_ROOT/outside-secret" "$STAGED/docs/linked-secret"
if bash "$ROOT/scripts/check-release-payload-secrets.sh" "$STAGED" >/dev/null 2>&1; then
  printf '%s\n' 'release-payload-boundary: scanner accepted a symlink payload' >&2
  exit 1
fi
rm "$STAGED/docs/linked-secret"

ln -s .env "$SOURCE/docs/tracked-link"
git -C "$SOURCE" add docs/tracked-link
if bash "$SOURCE/scripts/stage-release-payload.sh" "$SOURCE" "$TMP_ROOT/symlink-staged" >/dev/null 2>&1; then
  printf '%s\n' 'release-payload-boundary: staging accepted a tracked symlink' >&2
  exit 1
fi

ARCHIVE_FIXTURE="$TMP_ROOT/archive-fixture"
mkdir -p "$ARCHIVE_FIXTURE/root/sub"
printf '%s\n' 'safe' > "$ARCHIVE_FIXTURE/root/file.txt"
# BSD tar -s / GNU --transform are not portable. Write the ../escape member
# with Python so this fixture works on Linux GNU tar and macOS.
command -v python3 >/dev/null 2>&1 || {
  printf '%s\n' 'release-payload-boundary: python3 is required to build a portable traversal archive' >&2
  exit 1
}
python3 - "$TMP_ROOT/traversal.tar.gz" <<'PY'
import io
import sys
import tarfile

out = sys.argv[1]
payload = b"safe\n"
info = tarfile.TarInfo(name="../escape")
info.size = len(payload)
with tarfile.open(out, "w:gz") as archive:
    archive.addfile(info, io.BytesIO(payload))
PY
if bash "$ROOT/scripts/check-release-payload-secrets.sh" "$TMP_ROOT/traversal.tar.gz" >/dev/null 2>&1; then
  printf '%s\n' 'release-payload-boundary: scanner accepted a traversal archive entry' >&2
  exit 1
fi

ln -s file.txt "$ARCHIVE_FIXTURE/root/linked-file"
tar -czf "$TMP_ROOT/symlink.tar.gz" -C "$ARCHIVE_FIXTURE" root
if bash "$ROOT/scripts/check-release-payload-secrets.sh" "$TMP_ROOT/symlink.tar.gz" >/dev/null 2>&1; then
  printf '%s\n' 'release-payload-boundary: scanner accepted an archive symlink' >&2
  exit 1
fi

if command -v zip >/dev/null 2>&1; then
  (cd "$ARCHIVE_FIXTURE/root/sub" && zip -q "$TMP_ROOT/traversal.zip" ../file.txt)
  if bash "$ROOT/scripts/check-release-payload-secrets.sh" "$TMP_ROOT/traversal.zip" >/dev/null 2>&1; then
    printf '%s\n' 'release-payload-boundary: scanner accepted a zip traversal entry' >&2
    exit 1
  fi
fi

printf '%s\n' 'release-payload-boundary: passed'
