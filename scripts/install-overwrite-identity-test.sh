#!/usr/bin/env bash
# Fast no-network identity test: a real ryk product binary is overwrite-safe;
# a non-ryk file at the destination still refuses. Does not download releases.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
INSTALL_SH="${REPO_ROOT}/scripts/install.sh"

fail() {
  printf 'install-overwrite-identity: %s\n' "$1" >&2
  exit 1
}

[[ -f "${INSTALL_SH}" ]] || fail "missing ${INSTALL_SH}"

# Load is_ryk_product_binary from install.sh without running the installer.
eval "$(awk '
  $0 == "is_ryk_product_binary() {" { printing = 1 }
  printing { print }
  printing && $0 == "}" { exit }
' "${INSTALL_SH}")"

type is_ryk_product_binary >/dev/null 2>&1 ||
  fail "is_ryk_product_binary is missing from install.sh"

grep -q 'is_ryk_product_binary' "${INSTALL_SH}" ||
  fail "validate_binary_destination must consult is_ryk_product_binary"
grep -F -q 'ryk update --force' "${INSTALL_SH}" ||
  fail "refuse path must name ryk update --force as the one next step"
grep -F -q 'ryk update --force' "${REPO_ROOT}/scripts/install.ps1" ||
  fail "install.ps1 refuse path must name ryk update --force"

TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/ryk-install-overwrite-id.XXXXXX")"
identity_cleanup() {
  rm -rf "${TMP_ROOT}"
}
trap identity_cleanup EXIT INT TERM

# Stub product binary: basename ryk, prints version --json (issue #209 contract).
STUB_DIR="${TMP_ROOT}/stub"
mkdir -p "${STUB_DIR}"
cat > "${STUB_DIR}/ryk" <<'EOF'
#!/usr/bin/env sh
case "${1:-}" in
  version|--version)
    if [ "${2:-}" = "--json" ]; then
      printf '{"product":"ryk","version":"0.2.18"}\n'
    else
      printf 'ryk 0.2.18\n'
    fi
    exit 0
    ;;
esac
exit 1
EOF
chmod 0755 "${STUB_DIR}/ryk"

# Non-ryk files that must still refuse (do not weaken this).
NON_RYK_DIR="${TMP_ROOT}/non-ryk"
mkdir -p "${NON_RYK_DIR}"
printf '#!/usr/bin/env python3\nprint("hello")\n' > "${NON_RYK_DIR}/ryk"
chmod 0755 "${NON_RYK_DIR}/ryk"

EMPTY_DIR="${TMP_ROOT}/empty"
mkdir -p "${EMPTY_DIR}"
: > "${EMPTY_DIR}/ryk"
chmod 0755 "${EMPTY_DIR}/ryk"

SCRIPT_DIR_DEST="${TMP_ROOT}/script"
mkdir -p "${SCRIPT_DIR_DEST}"
printf '#!/bin/sh\necho not-ryk\n' > "${SCRIPT_DIR_DEST}/ryk"
chmod 0755 "${SCRIPT_DIR_DEST}/ryk"

# ELF / real executable that is not ryk — must not treat every binary as ryk.
ELF_DIR="${TMP_ROOT}/elf"
mkdir -p "${ELF_DIR}"
if [[ -x /bin/true ]]; then
  cp /bin/true "${ELF_DIR}/ryk"
  chmod 0755 "${ELF_DIR}/ryk"
fi

# Marker in a file not named ryk — basename gate.
OTHER_NAME="${TMP_ROOT}/other"
mkdir -p "${OTHER_NAME}"
printf '{"product":"ryk","version":"0.2.18"}\n' > "${OTHER_NAME}/not-ryk"
chmod 0755 "${OTHER_NAME}/not-ryk"

# Probe-only stub: prints version --json but does not embed the marker in-file.
PROBE_DIR="${TMP_ROOT}/probe"
mkdir -p "${PROBE_DIR}"
cat > "${PROBE_DIR}/ryk" <<'EOF'
#!/usr/bin/env sh
key=$(printf '%s%s' pro duct)
if [ "${1:-}" = "version" ] && [ "${2:-}" = "--json" ]; then
  printf '{"%s":"ryk","version":"0.2.18"}\n' "$key"
  exit 0
fi
exit 1
EOF
chmod 0755 "${PROBE_DIR}/ryk"

is_ryk_product_binary "${STUB_DIR}/ryk" ||
  fail "stub ryk that prints version --json must be a product binary"

is_ryk_product_binary "${PROBE_DIR}/ryk" ||
  fail "ryk stub that only prints version --json (no in-file marker) must pass"

is_ryk_product_binary "${NON_RYK_DIR}/ryk" &&
  fail "python file named ryk must not be a product binary"

is_ryk_product_binary "${EMPTY_DIR}/ryk" &&
  fail "empty file named ryk must not be a product binary"

is_ryk_product_binary "${SCRIPT_DIR_DEST}/ryk" &&
  fail "random script named ryk must not be a product binary"

if [[ -x "${ELF_DIR}/ryk" ]]; then
  is_ryk_product_binary "${ELF_DIR}/ryk" &&
    fail "non-ryk ELF named ryk must not be a product binary"
fi

is_ryk_product_binary "${OTHER_NAME}/not-ryk" &&
  fail "product JSON in a file not named ryk must not pass"

# Live validate_binary_destination when install.sh can be sourced as a library.
if grep -q 'RYK_INSTALL_SOURCE_ONLY' "${INSTALL_SH}"; then
  HOME="${TMP_ROOT}/home"
  mkdir -p "${HOME}"
  SHARE_DIR="${TMP_ROOT}/share"
  mkdir -p "${SHARE_DIR}"
  # shellcheck disable=SC1090
  RYK_INSTALL_SOURCE_ONLY=1 \
    RYK_VERSION=0.0.0 \
    RYK_INSTALL_DIR="${TMP_ROOT}/bin" \
    RYK_SHARE_DIR="${SHARE_DIR}" \
    HOME="${HOME}" \
    . "${INSTALL_SH}"

  type validate_binary_destination >/dev/null 2>&1 ||
    fail "SOURCE_ONLY did not expose validate_binary_destination"

  validate_binary_destination "${STUB_DIR}/ryk" ||
    fail "validate_binary_destination must allow a ryk product binary without FORCE"

  validate_binary_destination "${PROBE_DIR}/ryk" ||
    fail "validate_binary_destination must allow a probe-only ryk stub without FORCE"

  RYK_INSTALL_FORCE=1 validate_binary_destination "${NON_RYK_DIR}/ryk" ||
    fail "RYK_INSTALL_FORCE=1 must still overwrite a non-ryk file"

  refuse_out="${TMP_ROOT}/refuse.out"
  if (validate_binary_destination "${NON_RYK_DIR}/ryk") >"${refuse_out}" 2>&1; then
    fail "validate_binary_destination must refuse a non-ryk file"
  fi
  grep -F -q "refusing to overwrite non-ryk file" "${refuse_out}" ||
    fail "refuse reason must say non-ryk file"
  grep -F -q "ryk update --force" "${refuse_out}" ||
    fail "refuse next step must be ryk update --force"
  if grep -E -q 'choose another|or set |or RYK_' "${refuse_out}"; then
    fail "refuse must be one reason + one next (no extra nexts)"
  fi

  dir_dest="${TMP_ROOT}/dir-dest"
  mkdir -p "${dir_dest}"
  if (validate_binary_destination "${dir_dest}") >"${TMP_ROOT}/dir.out" 2>&1; then
    fail "validate_binary_destination must refuse a directory destination"
  fi
  grep -F -q "refusing directory binary destination" "${TMP_ROOT}/dir.out" ||
    fail "directory refuse reason missing"

  link_dest="${TMP_ROOT}/link-dest/ryk"
  mkdir -p "$(dirname "${link_dest}")"
  ln -s "${NON_RYK_DIR}/ryk" "${link_dest}"
  validate_binary_destination "${link_dest}" ||
    fail "validate_binary_destination must still allow a final symlink destination"
fi

printf '[install-overwrite-identity] passed\n'
