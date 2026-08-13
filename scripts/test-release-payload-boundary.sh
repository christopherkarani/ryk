#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/ryk-release-payload-boundary.XXXXXX")"
trap 'rm -rf "$TMP_ROOT"' EXIT INT TERM

SOURCE="$TMP_ROOT/source"
STAGED="$TMP_ROOT/staged"
mkdir -p "$SOURCE/docs" "$SOURCE/scripts"
cp "$ROOT/scripts/stage-release-payload.sh" "$SOURCE/scripts/"
printf '%s\n' 'tracked documentation' > "$SOURCE/docs/guide.md"
printf '%s\n' 'OPENAI_API_KEY=sk-LiveLookingIgnoredSecret1234567890' > "$SOURCE/docs/.env"

git -C "$SOURCE" init -q
git -C "$SOURCE" add docs/guide.md scripts/stage-release-payload.sh
git -C "$SOURCE" -c user.name=ryk-test -c user.email=ryk-test@example.invalid commit -qm fixture

bash "$SOURCE/scripts/stage-release-payload.sh" "$SOURCE" "$STAGED"
test -f "$STAGED/docs/guide.md"
test ! -e "$STAGED/docs/.env"

printf '%s\n' 'GITHUB_TOKEN=ghp_AbCdEf0123456789AbCdEf0123456789' > "$STAGED/docs/leak.txt"
if bash "$ROOT/scripts/check-release-payload-secrets.sh" "$STAGED" >/dev/null 2>&1; then
  printf '%s\n' 'release-payload-boundary: secret scanner accepted credential-shaped content' >&2
  exit 1
fi
rm "$STAGED/docs/leak.txt"

printf '%s\n' 'PASSWORD=generated-at-runtime-but-real' > "$STAGED/docs/leak.txt"
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
printf '%s\n' 'PASSWORD=actual-low-entropy-release-secret' >> "$REAL_STAGED/docs/credentials.md"
if bash "$ROOT/scripts/check-release-payload-secrets.sh" "$REAL_STAGED" >/dev/null 2>&1; then
  printf '%s\n' 'release-payload-boundary: scanner accepted injection into reviewed synthetic file' >&2
  exit 1
fi
cp "$TMP_ROOT/credentials.md.clean" "$REAL_STAGED/docs/credentials.md"
printf '%s\n' 'AWS_ACCESS_KEY_ID=ASIA0123456789ABCDEF' > "$STAGED/docs/leak.txt"
if bash "$ROOT/scripts/check-release-payload-secrets.sh" "$STAGED" >/dev/null 2>&1; then
  printf '%s\n' 'release-payload-boundary: scanner accepted temporary AWS credentials' >&2
  exit 1
fi
printf '%s\n' 'synthetic fixture note' '-----BEGIN PRIVATE KEY-----' 'AbCdEf0123456789AbCdEf0123456789' '-----END PRIVATE KEY-----' > "$STAGED/docs/leak.txt"
if bash "$ROOT/scripts/check-release-payload-secrets.sh" "$STAGED" >/dev/null 2>&1; then
  printf '%s\n' 'release-payload-boundary: synthetic text bypassed private-key rejection' >&2
  exit 1
fi
rm "$STAGED/docs/leak.txt"
bash "$ROOT/scripts/check-release-payload-secrets.sh" "$STAGED" >/dev/null

printf '%s\n' 'PASSWORD=hunter2' > "$STAGED/docs/leak.txt"
if bash "$ROOT/scripts/check-release-payload-secrets.sh" "$STAGED" >/dev/null 2>&1; then
  printf '%s\n' 'release-payload-boundary: scanner accepted a low-entropy password assignment' >&2
  exit 1
fi

mkdir -p "$STAGED/fixtures/adversarial"
printf '%s\n' 'PASSWORD=correct-horse-battery-staple' > "$STAGED/fixtures/adversarial/real-secret.txt"
if bash "$ROOT/scripts/check-release-payload-secrets.sh" "$STAGED" >/dev/null 2>&1; then
  printf '%s\n' 'release-payload-boundary: scanner exempted a fixture credential' >&2
  exit 1
fi
rm "$STAGED/fixtures/adversarial/real-secret.txt"

printf '%s\n' 'PASSWORD=p@$$w0rd' > "$STAGED/docs/leak.txt"
if bash "$ROOT/scripts/check-release-payload-secrets.sh" "$STAGED" >/dev/null 2>&1; then
  printf '%s\n' 'release-payload-boundary: scanner treated dollar signs as placeholders' >&2
  exit 1
fi
printf '%s\n' 'database_password=hunter2' > "$STAGED/docs/leak.txt"
if bash "$ROOT/scripts/check-release-payload-secrets.sh" "$STAGED" >/dev/null 2>&1; then
  printf '%s\n' 'release-payload-boundary: scanner missed a lowercase credential name' >&2
  exit 1
fi
rm "$STAGED/docs/leak.txt"
printf '%s\n' 'DATABASE_URL=postgres://admin:S3cr3t@db.internal/app' > "$STAGED/docs/leak.txt"
if bash "$ROOT/scripts/check-release-payload-secrets.sh" "$STAGED" >/dev/null 2>&1; then
  printf '%s\n' 'release-payload-boundary: scanner accepted URI userinfo credentials' >&2
  exit 1
fi
rm "$STAGED/docs/leak.txt"

printf '%s\n' 'PASSWORD=outside-release-boundary' > "$TMP_ROOT/outside-secret"
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
tar -cf "$TMP_ROOT/traversal.tar" -C "$ARCHIVE_FIXTURE/root" -s '|^file.txt$|../escape|' file.txt
gzip "$TMP_ROOT/traversal.tar"
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
