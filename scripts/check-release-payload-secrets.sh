#!/usr/bin/env bash
set -euo pipefail

TARGET="${1:?release payload directory or archive is required}"
TMP_ROOT=""
cleanup() {
  [[ -z "$TMP_ROOT" ]] || rm -rf "$TMP_ROOT"
}
trap cleanup EXIT INT TERM

if [[ -d "$TARGET" ]]; then
  SCAN_ROOT="$TARGET"
else
  TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/ryk-release-secret-scan.XXXXXX")"
  case "$TARGET" in
    *.tar.gz)
      while IFS= read -r path; do
        case "$path" in
          /*|../*|*/../*|*/..|..) printf 'release payload scan: unsafe archive path: %s\n' "$path" >&2; exit 1 ;;
        esac
      done < <(tar -tzf "$TARGET")
      if tar -tvzf "$TARGET" | LC_ALL=C grep -Eq '^[lh]'; then
        printf 'release payload scan: archive links are forbidden\n' >&2
        exit 1
      fi
      tar -xzf "$TARGET" -C "$TMP_ROOT"
      ;;
    *.zip)
      command -v unzip >/dev/null 2>&1 || {
        printf 'release payload scan: unzip is required for %s\n' "$TARGET" >&2
        exit 1
      }
      while IFS= read -r path; do
        case "$path" in
          /*|../*|*/../*|*/..|..) printf 'release payload scan: unsafe archive path: %s\n' "$path" >&2; exit 1 ;;
        esac
      done < <(unzip -Z1 "$TARGET")
      if unzip -Z -l "$TARGET" | LC_ALL=C grep -Eq '^l'; then
        printf 'release payload scan: archive symlinks are forbidden\n' >&2
        exit 1
      fi
      unzip -qq "$TARGET" -d "$TMP_ROOT"
      ;;
    *) printf 'release payload scan: unsupported input: %s\n' "$TARGET" >&2; exit 1 ;;
  esac
  SCAN_ROOT="$TMP_ROOT"
fi

# Release archives conventionally contain one top-level product directory.
# Normalize it so reviewed synthetic-file paths are identical for directory
# and archive scans.
top_count="$(find "$SCAN_ROOT" -mindepth 1 -maxdepth 1 | wc -l | tr -d ' ')"
if [[ "$top_count" == "1" ]]; then
  top_entry="$(find "$SCAN_ROOT" -mindepth 1 -maxdepth 1 -print -quit)"
  if [[ -d "$top_entry" ]]; then
    SCAN_ROOT="$top_entry"
  fi
fi

if find "$SCAN_ROOT" -type l -print -quit | grep -q .; then
  printf 'release payload scan: symlink payload entries are forbidden\n' >&2
  exit 1
fi

violations=0
patterns=(
  'sk-[A-Za-z0-9]{20,}'
  'sk-ant-[A-Za-z0-9]{20,}'
  'gh[pousr]_[A-Za-z0-9]{20,}'
  'github_pat_[A-Za-z0-9_]{20,}'
  'xox[baprs]-[A-Za-z0-9-]{10,}'
  'AKIA[0-9A-Z]{16}'
  'ASIA[0-9A-Z]{16}'
)

# Secret identifiers make even short, low-entropy values sensitive. Keep this
# intentionally structural rather than entropy-based so a low-entropy PASSWORD
# value and URI credentials cannot pass merely because they look ordinary.
# PGPASSWORD has no underscore; SECRET_KEY / ENCRYPTION_KEY do not end in a
# listed term (SECRET_KEY is SECRET + _KEY, not *_SECRET). Name them first.
credential_name='PGPASSWORD|SECRET_KEY|ENCRYPTION_KEY|PASSWORD|PASSWD|PASSPHRASE|PWD|TOKEN|SECRET|API_KEY|APIKEY|ACCESS_KEY|PRIVATE_KEY|CLIENT_SECRET|CREDENTIALS?|AUTHORIZATION|COOKIE'
env_assignment_pattern="(^|[^A-Za-z0-9_])(([A-Z][A-Z0-9_]*)_)?(${credential_name})[[:space:]]*=[[:space:]]*[^[:space:],;}{]+"
lowercase_credential_assignment_pattern="(^|[^A-Za-z0-9_])[a-z][a-z0-9_]+_(password|passwd|passphrase|pwd|token|secret|api_?key|access_?key|private_?key|client_?secret|credential(s)?|authorization|cookie)[[:space:]]*=[[:space:]]*[^[:space:],;}{]+"
structured_assignment_pattern="^[[:space:]]*[\"']?(password|passwd|passphrase|pwd|token|secret|api[_-]?key|apikey|access[_-]?key|private[_-]?key|client[_-]?secret|credential(s)?|authorization|proxy-authorization|cookie|set-cookie)[\"']?[[:space:]]*:[[:space:]]*[^[:space:],;}{]+"
uri_userinfo_pattern='[A-Za-z][A-Za-z0-9+.-]*://[^/@[:space:]]+:[^/@[:space:]]+@'

printable_strings() {
  # Prefer `strings` so binary padding cannot join a URL to a later `@`.
  if command -v strings >/dev/null 2>&1; then
    strings -a -n 8 "$1" 2>/dev/null || true
  else
    python3 -c '
import sys
data = open(sys.argv[1], "rb").read().split(b"\x00")
for part in data:
    if len(part) >= 8 and all(32 <= b <= 126 for b in part):
        sys.stdout.buffer.write(part + b"\n")
' "$1" 2>/dev/null || true
  fi
}

is_placeholder_assignment() {
  local match="$1"
  local value="${match#*=}"
  value="${value#*:}"
  value="$(printf '%s' "$value" | sed -E 's/^[[:space:]"'"'"']+//; s/[[:space:]"'"'"'`)]+$//')"
  if [[ "$match" == *'="${'* || "$match" == *'="$'* || "$match" == *"='$"* || "$match" == *'=$'* || "$match" == *'=$('* || "$match" == *'=%s'* ]]; then
    return 0
  fi
  case "$value" in
    '<release-project-token>'|'fake_secret_value'*|'fake-secret-value'*|'sk-fakeSynthetic'*|'ghp_fakeSynthetic'*|'sk-ant-fakeSynthetic'*|'sk-fakeProviderCanary99'|'sk-...'|'ghp_...'|'[REDACTED]'|'<generated-at-runtime>'|'phc_test_public_token'|'abc123'|'xxxxx'|'') return 0 ;;
    '\$'[A-Za-z_]*|'${'*'}'|'$('*')'|'%s'*) return 0 ;;
    *) return 1 ;;
  esac
}

is_reviewed_synthetic_file() {
  local relative="${1#./}"
  local file="$2"
  local expected=""
  case "$relative" in
    ryk-pi/test/secret_capture.test.ts) expected='d1a3ad088d51656841c69ab7fdff637d82069a9769f9c878308e8eaf7190655d' ;;
    examples/leaky-agent-demo/run-demo.ps1) expected='c100efa79dedcc7f75a96ad49f440982de282e516a64bfe24025a48e5f640a19' ;;
    examples/leaky-agent-demo/run-demo.sh) expected='e91cb78655865e4b246d4682fb4e829259942766763673a78677773402755ce8' ;;
    scripts/adversarial/secret-boundary-canary.sh) expected='8eaa78a0559ab606859448f2d4ad68219f537ec21224725ea1377059fa307247' ;;
    scripts/test-telemetry-release-contract.sh) expected='feecda8d4d7089f244b7eefe5f8f7b0d51577abe810aa77cd9b7ad01aec0dba3' ;;
    packages/core/tests/contract.zig) expected='a687e982724f5e023b1c2df6182f5c5c81abe6562e804c7cbc459a507e699fbb' ;;
    fixtures/network-exfil/http-query-exfil/fixture.yaml) expected='9a72613bd364dec2d991921230acd2990483202b6ee663ef0c37d5d6aa1bc07e' ;;
    docs/credentials.md) expected='8f7f3885110df3906393e72ea6aadcf39bfd5e6c3368401cb003e5db20e3cb84' ;;
    *) return 1 ;;
  esac
  [[ "$(shasum -a 256 "$file" | awk '{print $1}')" == "$expected" ]]
}

has_live_credential_assignment() {
  local file="$1"
  local match
  while IFS= read -r match; do
    [[ -n "$match" ]] || continue
    if ! is_placeholder_assignment "$match"; then
      return 0
    fi
  done < <({ LC_ALL=C grep -aEo -- "$env_assignment_pattern" "$file" || true; LC_ALL=C grep -aEio -- "$lowercase_credential_assignment_pattern" "$file" || true; LC_ALL=C grep -aEio -- "$structured_assignment_pattern" "$file" || true; })
  return 1
}

is_synthetic() {
  case "$1" in
    ghp_fakeSyntheticTokenValue1234567890|sk-fakeSyntheticOpenAIKey1234567890|sk-fakeSyntheticOpenAIKeyUPDATED0001|sk-ant-fakeSyntheticAnthropicKey1234567890|sk-fakeProviderCanary99|sk-legacyWorkspaceSyntheticSecret|sk-legacyWorkspaceSyntheticSecret123456789|AKIASYNTHETICONLY123|AKIAIOSFODNN7EXAMPLE|sk-xxxxxxxxxxxxxxxxxxxx|ghp_xxxxxxxxxxxxxxxxxxxx) return 0 ;;
    *) return 1 ;;
  esac
}

while IFS= read -r -d '' file; do
  relative="${file#"$SCAN_ROOT"/}"
  if has_live_credential_assignment "$file"; then
    if ! is_reviewed_synthetic_file "$relative" "$file"; then
      printf 'release-secret-violation: %s contains a credential assignment\n' "$relative" >&2
      violations=$((violations + 1))
    fi
  fi
  # Scan NUL-terminated printable strings only. Raw `grep -a` on PE/ELF
  # binaries false-positives on `http://127.0.0.1:` plus padding then `@`.
  if printable_strings "$file" | LC_ALL=C grep -Eq -- "$uri_userinfo_pattern"; then
    if ! is_reviewed_synthetic_file "$relative" "$file"; then
      printf 'release-secret-violation: %s contains URI userinfo credentials\n' "$relative" >&2
      violations=$((violations + 1))
    fi
  fi
  if ! is_reviewed_synthetic_file "$relative" "$file"; then
    for pattern in "${patterns[@]}"; do
      while IFS= read -r token; do
        [[ -n "$token" ]] || continue
        if ! is_synthetic "$token"; then
          printf 'release-secret-violation: %s matches a credential pattern\n' "${file#"$SCAN_ROOT"/}" >&2
          violations=$((violations + 1))
          break
        fi
      done < <(LC_ALL=C grep -aEo -- "$pattern" "$file" || true)
    done
  fi
done < <(find "$SCAN_ROOT" -type f -print0)

while IFS= read -r -d '' file; do
  relative="${file#"$SCAN_ROOT"/}"
  case "$relative" in
    */fixtures/secret-exfil/ssh-key-read-basic/input/fake-home/.ssh/id_ed25519|*/fixtures/prompt-injection/issue-ssh-key-read/input/fake-home/.ssh/id_ed25519|fixtures/secret-exfil/ssh-key-read-basic/input/fake-home/.ssh/id_ed25519|fixtures/prompt-injection/issue-ssh-key-read/input/fake-home/.ssh/id_ed25519)
      continue
      ;;
  esac
  if grep -Eq -- '-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----' "$file" &&
      grep -Eq -- '-----END (RSA |EC |OPENSSH )?PRIVATE KEY-----' "$file"; then
    printf 'release-secret-violation: %s contains private key material\n' "$relative" >&2
    violations=$((violations + 1))
  fi
done < <(find "$SCAN_ROOT" -type f -print0)

if [[ "$violations" -ne 0 ]]; then
  printf 'release payload scan: %d violation(s)\n' "$violations" >&2
  exit 1
fi
printf 'release payload scan: passed\n'
