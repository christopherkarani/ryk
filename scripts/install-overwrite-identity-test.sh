#!/usr/bin/env bash
# Fast no-network identity test: a real ryk product binary is overwrite-safe;
# a non-ryk file at the destination still refuses and is never executed.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
INSTALL_SH="${REPO_ROOT}/scripts/install.sh"
INSTALL_PS1="${REPO_ROOT}/scripts/install.ps1"

test_fail() {
  printf 'install-overwrite-identity: %s\n' "$1" >&2
  exit 1
}
fail() { test_fail "$1"; }

[[ -f "${INSTALL_SH}" ]] || fail "missing ${INSTALL_SH}"
[[ -f "${INSTALL_PS1}" ]] || fail "missing ${INSTALL_PS1}"

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

TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/ryk-install-overwrite-id.XXXXXX")"
identity_cleanup() {
  rm -rf "${TMP_ROOT}"
}
trap identity_cleanup EXIT INT TERM

SIDE_EFFECT="${TMP_ROOT}/EXECUTED"
assert_not_executed() {
  if [[ -e "${SIDE_EFFECT}" ]]; then
    test_fail "$1 executed the destination (wrote ${SIDE_EFFECT})"
  fi
}

# Real 0.2.18 in-binary marker on a native image (ELF). Never a shebang stub.
STUB_DIR="${TMP_ROOT}/stub"
mkdir -p "${STUB_DIR}"
printf '\177ELF\0\0\0\0safety_boundary_version\0' > "${STUB_DIR}/ryk"
chmod 0755 "${STUB_DIR}/ryk"

# PE named ryk.exe with the same marker (Windows feel-pass fixture).
PE_DIR="${TMP_ROOT}/pe"
mkdir -p "${PE_DIR}"
printf 'MZ\0\0safety_boundary_version\0' > "${PE_DIR}/ryk.exe"
chmod 0755 "${PE_DIR}/ryk.exe"

# Mach-O 64-bit (little-endian magic) with the marker.
MACHO_DIR="${TMP_ROOT}/macho"
mkdir -p "${MACHO_DIR}"
printf '\317\372\355\376safety_boundary_version\0' > "${MACHO_DIR}/ryk"
chmod 0755 "${MACHO_DIR}/ryk"

# Hostile regular files named ryk: must refuse and must not be executed.
NON_RYK_DIR="${TMP_ROOT}/non-ryk"
mkdir -p "${NON_RYK_DIR}"
cat > "${NON_RYK_DIR}/ryk" <<EOF
#!/usr/bin/env python3
open(r'''${SIDE_EFFECT}''', "w").write("EXECUTED\n")
print("hello")
EOF
chmod 0755 "${NON_RYK_DIR}/ryk"

EMPTY_DIR="${TMP_ROOT}/empty"
mkdir -p "${EMPTY_DIR}"
: > "${EMPTY_DIR}/ryk"
chmod 0755 "${EMPTY_DIR}/ryk"

SCRIPT_DIR_DEST="${TMP_ROOT}/script"
mkdir -p "${SCRIPT_DIR_DEST}"
cat > "${SCRIPT_DIR_DEST}/ryk" <<EOF
#!/bin/sh
printf 'EXECUTED\n' > '${SIDE_EFFECT}'
echo not-ryk
EOF
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
printf '\177ELF\0\0\0\0safety_boundary_version\0' > "${OTHER_NAME}/not-ryk"
chmod 0755 "${OTHER_NAME}/not-ryk"

# Probe-only / wrapper: would pass an exec probe or a JSON-substring grep, but
# is not a native image with safety_boundary_version. Must refuse, never exec.
PROBE_DIR="${TMP_ROOT}/probe"
mkdir -p "${PROBE_DIR}"
cat > "${PROBE_DIR}/ryk" <<EOF
#!/usr/bin/env sh
printf 'EXECUTED\n' > '${SIDE_EFFECT}'
printf '{"product":"ryk","version":"0.2.18"}\n'
exit 0
EOF
chmod 0755 "${PROBE_DIR}/ryk"

# Corp wrapper that only mentions product JSON (P4). Must still refuse.
WRAPPER_JSON_DIR="${TMP_ROOT}/wrapper-json"
mkdir -p "${WRAPPER_JSON_DIR}"
cat > "${WRAPPER_JSON_DIR}/ryk" <<EOF
#!/bin/sh
printf 'EXECUTED\n' > '${SIDE_EFFECT}'
# {"product":"ryk","version":"0.2.18"}
exit 0
EOF
chmod 0755 "${WRAPPER_JSON_DIR}/ryk"

# Shebang file that mentions the in-binary marker — not a native image.
WRAPPER_MARKER_DIR="${TMP_ROOT}/wrapper-marker"
mkdir -p "${WRAPPER_MARKER_DIR}"
cat > "${WRAPPER_MARKER_DIR}/ryk" <<EOF
#!/bin/sh
printf 'EXECUTED\n' > '${SIDE_EFFECT}'
# safety_boundary_version
exit 0
EOF
chmod 0755 "${WRAPPER_MARKER_DIR}/ryk"

is_ryk_product_binary "${STUB_DIR}/ryk" ||
  fail "ELF named ryk with safety_boundary_version must be a product binary"

is_ryk_product_binary "${PE_DIR}/ryk.exe" ||
  fail "PE named ryk.exe with safety_boundary_version must be a product binary"

is_ryk_product_binary "${MACHO_DIR}/ryk" ||
  fail "Mach-O named ryk with safety_boundary_version must be a product binary"

is_ryk_product_binary "${PROBE_DIR}/ryk" &&
  fail "probe-only / version --json stub must not be a product binary (no exec)"
assert_not_executed "probe-only stub"

is_ryk_product_binary "${WRAPPER_JSON_DIR}/ryk" &&
  fail "wrapper that mentions product JSON must not be a product binary"
assert_not_executed "product-JSON wrapper"

is_ryk_product_binary "${WRAPPER_MARKER_DIR}/ryk" &&
  fail "shebang file that mentions safety_boundary_version must not be a product binary"
assert_not_executed "marker wrapper"

is_ryk_product_binary "${NON_RYK_DIR}/ryk" &&
  fail "python file named ryk must not be a product binary"
assert_not_executed "python dest"

is_ryk_product_binary "${EMPTY_DIR}/ryk" &&
  fail "empty file named ryk must not be a product binary"

is_ryk_product_binary "${SCRIPT_DIR_DEST}/ryk" &&
  fail "random script named ryk must not be a product binary"
assert_not_executed "random script dest"

if [[ -x "${ELF_DIR}/ryk" ]]; then
  is_ryk_product_binary "${ELF_DIR}/ryk" &&
    fail "non-ryk ELF named ryk must not be a product binary"
fi

is_ryk_product_binary "${OTHER_NAME}/not-ryk" &&
  fail "product marker in a file not named ryk must not pass"

# Identity must never exec dest (timeout/perl/version --json are the old hole).
if grep -E -q 'timeout[[:space:]]+[0-9]|perl -e .alarm' "${INSTALL_SH}"; then
  fail "install.sh must not exec dest via timeout/perl"
fi
if grep -n 'version --json' "${INSTALL_SH}" | grep -v '^[^:]*:[[:space:]]*#'; then
  fail "install.sh must not probe dest with version --json"
fi
if grep -q 'RYK_INSTALL_SOURCE_ONLY' "${INSTALL_SH}"; then
  fail "install.sh must not implement RYK_INSTALL_SOURCE_ONLY (production kill-switch)"
fi
grep -F -q 'RYK_INSTALL_FORCE=1' "${INSTALL_SH}" ||
  fail "curl-door refuse path must name RYK_INSTALL_FORCE=1"
grep -F -q 'RYK_INSTALL_FORCE=1' "${INSTALL_PS1}" ||
  fail "install.ps1 refuse path must name RYK_INSTALL_FORCE=1"

# Windows: markers only, skip reparse, never exec, do not Copy-Item through a link.
if grep -q 'function Get-ExistingProductInfo' "${INSTALL_PS1}"; then
  fail "install.ps1 must not exec dest via Get-ExistingProductInfo"
fi
if grep -E -q '& \$Path version|ReadToEnd' "${INSTALL_PS1}"; then
  fail "install.ps1 must not exec dest or ReadToEnd a dest stream"
fi
grep -q 'ReparsePoint' "${INSTALL_PS1}" ||
  fail "install.ps1 must skip reparse/symlink dest (allow, never exec)"
grep -F -q '[System.IO.File]::Delete' "${INSTALL_PS1}" ||
  fail "install.ps1 must replace a reparse dest instead of Copy-Item through it"
grep -F -q 'safety_boundary_version' "${INSTALL_PS1}" ||
  fail "install.ps1 identity must use the safety_boundary_version marker"

# Live validate_binary_destination via extracted snippet (no install.sh kill-switch).
fail() {
  printf '%s\n' "$1" >&2
  if [[ -n "${2:-}" ]]; then
    printf '%s\n' "$2" >&2
  fi
  exit 1
}
reject_symlink_parents() { :; }
managed_runtime_version() { return 1; }
eval "$(awk '
  $0 == "validate_binary_destination() {" { printing = 1 }
  printing { print }
  printing && $0 == "}" { exit }
' "${INSTALL_SH}")"

type validate_binary_destination >/dev/null 2>&1 ||
  test_fail "validate_binary_destination is missing from install.sh"

validate_binary_destination "${STUB_DIR}/ryk" ||
  test_fail "validate_binary_destination must allow a ryk product binary without FORCE"

if (validate_binary_destination "${PROBE_DIR}/ryk") >"${TMP_ROOT}/probe-validate.out" 2>&1; then
  test_fail "validate_binary_destination must refuse a probe-only stub without FORCE"
fi
assert_not_executed "validate probe-only stub"

RYK_INSTALL_FORCE=1 validate_binary_destination "${NON_RYK_DIR}/ryk" ||
  test_fail "RYK_INSTALL_FORCE=1 must still overwrite a non-ryk file"
assert_not_executed "FORCE overwrite of python dest"

refuse_out="${TMP_ROOT}/refuse.out"
if (validate_binary_destination "${NON_RYK_DIR}/ryk") >"${refuse_out}" 2>&1; then
  test_fail "validate_binary_destination must refuse a non-ryk file"
fi
assert_not_executed "validate python dest"
grep -F -q "refusing to overwrite non-ryk file" "${refuse_out}" ||
  test_fail "refuse reason must say non-ryk file"
grep -F -q "RYK_INSTALL_FORCE=1" "${refuse_out}" ||
  test_fail "curl-door refuse next step must be RYK_INSTALL_FORCE=1"
if grep -E -q 'choose another| or |ryk update --force' "${refuse_out}"; then
  test_fail "refuse must be one reason + one next (RYK_INSTALL_FORCE=1)"
fi

dir_dest="${TMP_ROOT}/dir-dest"
mkdir -p "${dir_dest}"
if (validate_binary_destination "${dir_dest}") >"${TMP_ROOT}/dir.out" 2>&1; then
  test_fail "validate_binary_destination must refuse a directory destination"
fi
grep -F -q "refusing directory binary destination" "${TMP_ROOT}/dir.out" ||
  test_fail "directory refuse reason missing"

link_dest="${TMP_ROOT}/link-dest/ryk"
mkdir -p "$(dirname "${link_dest}")"
ln -s "${NON_RYK_DIR}/ryk" "${link_dest}"
validate_binary_destination "${link_dest}" ||
  test_fail "validate_binary_destination must still allow a final symlink destination"
assert_not_executed "final symlink dest"

printf '[install-overwrite-identity] passed\n'
