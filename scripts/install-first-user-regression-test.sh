#!/usr/bin/env bash
set -euo pipefail

# First-user / curl-door regression (D86) for w1-install-handoff.
# Executes scripts/install.sh against a mock product binary. After co-migration
# the primary post-binary door is `"$DESTINATION" doctor --fix --from-install`.
# When the mock advertises doctor --fix, start --auto is poison (must not green).

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
VERSION="$(tr -d '[:space:]' < "${REPO_ROOT}/VERSION")"
INSTALL_SH="${REPO_ROOT}/scripts/install.sh"

fail() {
  printf 'install-first-user-regression: %s\n' "$1" >&2
  exit 1
}

# D06 full-protection forbid-list (case-insensitive). Soft / partial success
# receipts and install step copy must never claim these.
assert_no_d06_full_protection() {
  local text="$1"
  local label="${2:-output}"
  if printf '%s\n' "${text}" | grep -Eiq \
    'fully protected|all hosts wired|protection complete|full protection'; then
    fail "${label} claimed a D06 full-protection phrase"
  fi
}

case "$(uname -s)" in
  Darwin) os=darwin ;;
  Linux) os=linux ;;
  *) fail "unsupported host OS" ;;
esac

case "$(uname -m)" in
  x86_64|amd64) arch=amd64 ;;
  arm64|aarch64) arch=arm64 ;;
  *) fail "unsupported host architecture" ;;
esac

tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/ryk-first-user.XXXXXX")"
# macOS commonly exposes /var as a system symlink to /private/var. Exercise the
# installer with the physical test path so only test-created symlinks are in
# scope for the rejection cases.
tmp_root="$(cd "${tmp_root}" && pwd -P)"
cleanup() {
  rm -rf "${tmp_root}"
}
trap cleanup EXIT INT TERM

home="${tmp_root}/home"
escaped="${tmp_root}/escaped"
install_dir="${home}/bin \$(touch PATH_INJECTION)"
share_dir="${home}/share \$(touch RESOURCE_INJECTION)"
artifact_dir="${tmp_root}/artifacts"
release_root="${tmp_root}/ryk-v${VERSION}-${os}-${arch}"
artifact="ryk-v${VERSION}-${os}-${arch}.tar.gz"
mkdir -p "${home}" "${artifact_dir}" "${release_root}/bin"

for dir in integrations fixtures schemas policies ryk-pi; do
  mkdir -p "${release_root}/${dir}"
  printf 'fixture\n' > "${release_root}/${dir}/fixture.txt"
done

# Mock product binary installed as ryk. Implements doctor for
# the W1 ensure door; start is poison so restoring start --auto cannot green
# when doctor --fix is advertised. doctor --help must list --fix so the
# installer's capability probe selects the W1 door (not legacy start --auto).
cat > "${release_root}/bin/ryk" <<'EOF'
#!/usr/bin/env sh
# Log door line + trust-scope env for the first-user harness.
# Door line for doctor is "doctor <first-flag>" so count gate can use
# grep -c '^doctor --fix$'. Help probes must not count as the ensure door.
log_scope() {
  door_line="$1"
  shift
  printf '%s\n' "${door_line}" >> "${RYK_TEST_ONBOARD_LOG:?}"
  printf 'cwd=%s\n' "$PWD" >> "${RYK_TEST_ONBOARD_LOG}"
  printf 'ryk_resource=%s\n' "${RYK_RESOURCE_ROOT:-}" >> "${RYK_TEST_ONBOARD_LOG}"
  printf 'resource=%s\n' "${RYK_RESOURCE_ROOT:-}" >> "${RYK_TEST_ONBOARD_LOG}"
  printf 'path=%s\n' "${PATH:-}" >> "${RYK_TEST_ONBOARD_LOG}"
  printf 'argv=' >> "${RYK_TEST_ONBOARD_LOG}"
  first=1
  for a in "$@"; do
    if [ "$first" -eq 1 ]; then
      printf '%s' "$a" >> "${RYK_TEST_ONBOARD_LOG}"
      first=0
    else
      printf ' %s' "$a" >> "${RYK_TEST_ONBOARD_LOG}"
    fi
  done
  printf '\n' >> "${RYK_TEST_ONBOARD_LOG}"
}

case "${1:-}" in
  doctor)
    # Capability probe (install.sh cli_supports_doctor_fix): do not log help.
    if [ "${2:-}" = "--help" ] || [ "${2:-}" = "-h" ]; then
      printf 'Usage:\n  ryk doctor [-v|--verbose] [--check] [--json] [--fix] [--from-install]\n'
      printf 'Examples:\n  ryk doctor --fix\n'
      exit 0
    fi
    # Anchored door line uses $2 (expected --fix). Optional further flags
    # (--from-install, --preset) are recorded on the argv= line only.
    log_scope "doctor${2:+ $2}" "$@"
    if [ "${RYK_TEST_DOCTOR_EXIT:-0}" -ne 0 ]; then
      printf 'mock doctor: forced failure (exit %s)\n' "${RYK_TEST_DOCTOR_EXIT}" >&2
      exit "${RYK_TEST_DOCTOR_EXIT}"
    fi
    if [ "${RYK_TEST_DOCTOR_PARTIAL:-0}" = "1" ]; then
      # Soft host-fail honesty: exit 0, partial label, teach doctor --fix.
      # Must not emit D06 full-protection phrases.
      printf 'ryk ensure: protection partial — some hosts incomplete or none detected.\n'
      printf 'host mock-host: incomplete — ryk doctor --fix\n'
      exit 0
    fi
    printf 'ryk ensure: core ready (mock)\n'
    ;;
  start)
    # Poison path: log and fail so install.sh cannot green via start --auto
    # when the W1 doctor --fix door is available.
    log_scope "start${2:+ $2}" "$@"
    if [ "${RYK_TEST_START_EXIT:-99}" -ne 0 ]; then
      printf 'mock start: forbidden install door (exit %s)\n' "${RYK_TEST_START_EXIT:-99}" >&2
      exit "${RYK_TEST_START_EXIT:-99}"
    fi
    printf "You're now protected by ryk\n"
    ;;
  env|--print-install-env)
    printf 'export RYK_FIRST_USER_ACTIVATED=1\n'
    ;;
  version|--version)
    if [ "${2:-}" = "--json" ]; then
      printf '{"product":"ryk","version":"0.0.0"}\n'
    else
      printf 'ryk 0.0.0\n'
    fi
    ;;
esac
EOF
chmod +x "${release_root}/bin/ryk"
tar -czf "${artifact_dir}/${artifact}" -C "${tmp_root}" "$(basename "${release_root}")"
if command -v sha256sum >/dev/null 2>&1; then
  checksum="$(sha256sum "${artifact_dir}/${artifact}" | awk '{print $1}')"
else
  checksum="$(shasum -a 256 "${artifact_dir}/${artifact}" | awk '{print $1}')"
fi
printf '%s  %s\n' "${checksum}" "${artifact}" > "${artifact_dir}/checksums.txt"

onboard_log="${tmp_root}/onboard.log"
# Real upgrades may still have the Phase 5a markers. The new installer must
# migrate them rather than append a second managed block.
cat > "${home}/.profile" <<EOF
# Added by ryk installer
export PATH='/legacy/ryk/bin':"\$PATH"

# ryk runtime assets
export RYK_RESOURCE_ROOT='/legacy/ryk/share'
EOF

# ── Non-TTY install: doctor --fix once under HOME + resource roots (D86) ──
output="$(
  cat "${INSTALL_SH}" | \
    HOME="${home}" \
    SHELL=/bin/sh \
    RYK_VERSION="${VERSION}" \
    RYK_ARTIFACT_DIR="${artifact_dir}" \
    RYK_INSTALL_DIR="${install_dir}" \
    RYK_SHARE_DIR="${share_dir}" \
    RYK_RESOURCE_ROOT="${escaped}" \
    RYK_TEST_ONBOARD_LOG="${onboard_log}" \
    sh
)"

# Captured stdout is intentionally non-TTY. Setup must still be automatic via
# doctor --fix (ensure door). start --auto must not appear.
[[ "$(grep -c '^doctor --fix$' "${onboard_log}")" == 1 ]] ||
  fail "non-TTY install did not run doctor --fix exactly once (got: $(grep -c '^doctor --fix$' "${onboard_log}" 2>/dev/null || echo 0); log=$(cat "${onboard_log}" 2>/dev/null || true))"
[[ "$(grep -c '^start --auto$' "${onboard_log}")" == 0 ]] ||
  fail "install still invoked start --auto (forbidden; restore is not a green path)"
[[ "$(grep -c '^start' "${onboard_log}")" == 0 ]] ||
  fail "install invoked start door (forbidden after w1-install-handoff)"
# Install-scope flag must ride with the doctor --fix door (D32).
grep -qE '^argv=doctor --fix --from-install' "${onboard_log}" ||
  fail "onboarding argv missing --from-install (got: $(grep '^argv=' "${onboard_log}" 2>/dev/null || true))"

actual_onboard_cwd="$(sed -n 's/^cwd=//p' "${onboard_log}" | head -n 1)"
[[ -n "${actual_onboard_cwd}" && "${actual_onboard_cwd}" -ef "${home}" ]] ||
  fail "onboarding did not run from the global HOME scope (cwd=${actual_onboard_cwd})"
grep -qF "resource=${share_dir}/current" "${onboard_log}" ||
  fail "onboarding did not receive RYK_RESOURCE_ROOT at installed resource root"
grep -qF "ryk_resource=${share_dir}/current" "${onboard_log}" ||
  fail "onboarding did not receive RYK_RESOURCE_ROOT at installed resource root"
grep -qF "${install_dir}" "${onboard_log}" ||
  fail "onboarding PATH did not contain the installed binary directory"

# Reinstalling must update the managed blocks instead of appending duplicates.
HOME="${home}" \
SHELL=/bin/sh \
RYK_VERSION="${VERSION}" \
RYK_ARTIFACT_DIR="${artifact_dir}" \
RYK_INSTALL_DIR="${install_dir}" \
RYK_SHARE_DIR="${share_dir}" \
RYK_TEST_ONBOARD_LOG="${onboard_log}" \
sh "${INSTALL_SH}" >/dev/null
[[ "$(grep -c '^# Added by ryk installer$' "${home}/.profile")" == 1 ]] || fail "reinstall duplicated the PATH block"
[[ "$(grep -c '^# ryk runtime assets$' "${home}/.profile")" == 1 ]] || fail "reinstall duplicated the runtime block"
[[ "$(grep -ci 'ryk installer\\|ryk runtime assets' "${home}/.profile")" == 0 ]] || fail "legacy profile markers were not migrated"

[[ ! -e "${escaped}" ]] || fail "RYK_RESOURCE_ROOT escaped the install destination"
resource_root="${share_dir}/${VERSION}"
[[ -f "${resource_root}/fixtures/fixture.txt" ]] || fail "runtime assets were not installed under HOME"
[[ "$(readlink "${share_dir}/current")" == "${resource_root}" ]] || fail "current link targets the wrong runtime root"

# macOS/BSD mv-into-symlink-dir regression: an existing current→version selector
# must be replaced, not followed (which plants current/current and fails install).
old_runtime="${share_dir}/0.0.0-old"
mkdir -p "${old_runtime}"
printf 'ryk-runtime-v1\nversion=0.0.0\n' > "${old_runtime}/.ryk-installation"
# Plant the failure mode from buggy installs: nested selector inside the target.
ln -sfn "${resource_root}" "${old_runtime}/current"
ln -sfn "${old_runtime}" "${share_dir}/current"
[[ -L "${share_dir}/current/current" ]] || fail "test setup missing nested current/current pollution"
: > "${onboard_log}"
HOME="${home}" \
SHELL=/bin/sh \
RYK_VERSION="${VERSION}" \
RYK_ARTIFACT_DIR="${artifact_dir}" \
RYK_INSTALL_DIR="${install_dir}" \
RYK_SHARE_DIR="${share_dir}" \
RYK_TEST_ONBOARD_LOG="${onboard_log}" \
sh "${INSTALL_SH}" >/dev/null ||
  fail "install failed when replacing an existing current→version symlink (mv-into-dir skew)"
[[ "$(readlink "${share_dir}/current")" == "${resource_root}" ]] ||
  fail "current selector not replaced after reinstall (got: $(readlink "${share_dir}/current" 2>/dev/null || true))"
[[ ! -e "${share_dir}/current/current" ]] ||
  fail "nested current/current pollution still present after reinstall"
[[ "$(readlink "${old_runtime}/current")" == "${resource_root}" ]] ||
  fail "reinstall modified a previous runtime's nested selector"

activation="$(printf '%s\n' "${output}" | awk '/^    eval / { sub(/^    /, ""); print; exit }')"
[[ -n "${activation}" ]] || fail "installer did not print an activation command"
[[ "${activation}" == *"${install_dir}/ryk"* ]] || fail "activation command does not use the absolute installed binary"
# UX receipt: brand + success + hierarchy (presentation may use ANSI; strip for asserts).
plain_output="$(printf '%s\n' "${output}" | sed $'s/\x1b\\[[0-9;]*m//g')"
printf '%s\n' "${plain_output}" | grep -Eq 'Rykan V|ryk' || fail "installer did not print brand header"
printf '%s\n' "${plain_output}" | grep -Eqi 'Rykan V' || fail "installer did not print Rykan V brand"
printf '%s\n' "${plain_output}" | grep -Eq 'installed|reinstalled' || fail "installer did not print success receipt"
# Ensure is summarized into the step list — no streamed start/doctor TUI.
printf '%s\n' "${plain_output}" | grep -Eqi 'Set up protection' ||
  fail "installer missing Set up protection step"
printf '%s\n' "${plain_output}" | grep -Eqi 'policy ready' ||
  fail "installer missing short ensure receipt (policy ready)"
if printf '%s\n' "${plain_output}" | grep -Eiq 'Try next|Re-run safely|Verification skipped|Setup complete'; then
  fail "installer streamed ensure TUI into the install receipt"
fi
if printf '%s\n' "${plain_output}" | grep -Fqi 'ryk start'; then
  fail "installer still teaches ryk start as user-facing door"
fi
if printf '%s\n' "${plain_output}" | grep -Fqi 'start --auto'; then
  fail "installer still surfaces start --auto in user-facing copy"
fi
assert_no_d06_full_protection "${plain_output}" "success receipt"
printf '%s\n' "${plain_output}" | grep -Eq '^[[:space:]]*eval ' || fail "installer did not print activation eval line"
if printf '%s\n' "${plain_output}" | grep -Eq 'Activate this terminal|Activate this session|Profile exports|INSTALL_DIR is not on PATH'; then
  fail "installer still prints removed success chrome (Activate/profile noise)"
fi
if printf '%s\n' "${plain_output}" | grep -Eq '^[[:space:]]*Details[[:space:]]*$|binary[[:space:]]+.*/ryk|assets[[:space:]]+.*current'; then
  fail "installer still prints Details block on success"
fi
# Dashboard soft-warn belongs on the receipt stdout when assets are missing.
printf '%s\n' "${plain_output}" | grep -Eqi 'dashboard' || fail "installer did not surface missing dashboard on the receipt"
if printf '%s\n' "${plain_output}" | grep -Eiq '(^|[^[:alnum:]_])orca([^[:alnum:]_]|$)'; then
  fail "installer exposed retired ryk branding"
fi
unset RYK_FIRST_USER_ACTIVATED
eval "${activation}"
[[ "${RYK_FIRST_USER_ACTIVATED:-}" == 1 ]] || fail "printed activation command did not activate the current shell"

# Quiet mode: only the activation line on stdout (no banner / steps / details).
# Quiet call site must still invoke doctor --fix under HOME + resource roots.
: > "${onboard_log}"
quiet_output="$(
  HOME="${home}" \
  SHELL=/bin/sh \
  RYK_VERSION="${VERSION}" \
  RYK_ARTIFACT_DIR="${artifact_dir}" \
  RYK_INSTALL_DIR="${install_dir}" \
  RYK_SHARE_DIR="${share_dir}" \
  RYK_INSTALL_QUIET=1 \
  RYK_TEST_ONBOARD_LOG="${onboard_log}" \
  sh "${INSTALL_SH}" 2>/dev/null
)"
[[ "$(grep -c '^doctor --fix$' "${onboard_log}")" == 1 ]] ||
  fail "quiet install did not run doctor --fix exactly once"
[[ "$(grep -c '^start --auto$' "${onboard_log}")" == 0 ]] ||
  fail "quiet install invoked start --auto"
actual_quiet_cwd="$(sed -n 's/^cwd=//p' "${onboard_log}" | head -n 1)"
[[ -n "${actual_quiet_cwd}" && "${actual_quiet_cwd}" -ef "${home}" ]] ||
  fail "quiet onboarding did not run from HOME (cwd=${actual_quiet_cwd})"
grep -qF "resource=${share_dir}/current" "${onboard_log}" ||
  fail "quiet onboarding missing RYK_RESOURCE_ROOT"
grep -qF "ryk_resource=${share_dir}/current" "${onboard_log}" ||
  fail "quiet onboarding missing RYK_RESOURCE_ROOT"
quiet_activation="$(printf '%s\n' "${quiet_output}" | awk '/^    eval / { sub(/^    /, ""); print; exit }')"
[[ -n "${quiet_activation}" ]] || fail "quiet mode did not print an activation command"
if printf '%s\n' "${quiet_output}" | grep -Eq 'Platform|Details|Resolve release|Activate this terminal|Rykan V'; then
  fail "quiet mode leaked non-activation UI"
fi
# Only the activation line should be non-empty content (allow blank lines).
nonempty_quiet="$(printf '%s\n' "${quiet_output}" | sed '/^[[:space:]]*$/d')"
[[ "$(printf '%s\n' "${nonempty_quiet}" | wc -l | tr -d ' ')" == "1" ]] || fail "quiet mode printed more than the activation line"

# Core / hard onboarding failure must fail the install receipt instead of claiming
# success and requiring the user to notice a dim warning.
: > "${onboard_log}"
failed_output="${tmp_root}/failed.out"
if HOME="${home}" \
  SHELL=/bin/sh \
  RYK_VERSION="${VERSION}" \
  RYK_ARTIFACT_DIR="${artifact_dir}" \
  RYK_INSTALL_DIR="${install_dir}" \
  RYK_SHARE_DIR="${share_dir}" \
  RYK_TEST_ONBOARD_LOG="${onboard_log}" \
  RYK_TEST_DOCTOR_EXIT=17 \
  sh "${INSTALL_SH}" >"${failed_output}" 2>&1; then
  fail "installer succeeded after doctor --fix failed"
fi
failed_plain="$(sed $'s/\x1b\\[[0-9;]*m//g' "${failed_output}")"
if printf '%s\n' "${failed_plain}" | grep -Fq "You're now protected by ryk"; then
  fail "installer claimed protection after doctor --fix failed"
fi
assert_no_d06_full_protection "${failed_plain}" "failed install"
# Hard-fail remediation must re-teach install trust scope (HOME + --from-install),
# not a bare `ryk doctor --fix` that drops the install-time scope flags.
printf '%s\n' "${failed_plain}" | grep -Fq 'doctor --fix --from-install' ||
  fail "hard-fail remediation missing doctor --fix --from-install (got remediation from failed install output)"
if ! printf '%s\n' "${failed_plain}" | grep -Eiq 'home directory|cd ["'\'']?\$?HOME'; then
  fail "hard-fail remediation missing HOME guidance (home directory / cd HOME)"
fi

# Soft host-fail honesty: doctor --fix exits 0 with partial receipt.
# Install must not step_done / claim D06 full-protection phrases.
: > "${onboard_log}"
partial_output="${tmp_root}/partial.out"
HOME="${home}" \
SHELL=/bin/sh \
RYK_VERSION="${VERSION}" \
RYK_ARTIFACT_DIR="${artifact_dir}" \
RYK_INSTALL_DIR="${install_dir}" \
RYK_SHARE_DIR="${share_dir}" \
RYK_TEST_ONBOARD_LOG="${onboard_log}" \
RYK_TEST_DOCTOR_PARTIAL=1 \
sh "${INSTALL_SH}" >"${partial_output}" 2>&1 ||
  fail "installer failed on soft host-fail (doctor --fix exit 0 / partial)"
[[ "$(grep -c '^doctor --fix$' "${onboard_log}")" == 1 ]] ||
  fail "partial-path install did not run doctor --fix once"
partial_plain="$(sed $'s/\x1b\\[[0-9;]*m//g' "${partial_output}")"
assert_no_d06_full_protection "${partial_plain}" "soft host-fail install"
if printf '%s\n' "${partial_plain}" | grep -Fqi 'ryk start'; then
  fail "soft host-fail path still teaches ryk start"
fi
# Soft path must not claim the old start full-protection completion string.
if printf '%s\n' "${partial_plain}" | grep -Fq "You're now protected by ryk"; then
  fail "soft host-fail path claimed full protection completion"
fi

# SKIP_ONBOARD must suppress the ensure door entirely (both RYK_ and RYK_ names).
: > "${onboard_log}"
HOME="${home}" \
SHELL=/bin/sh \
RYK_VERSION="${VERSION}" \
RYK_ARTIFACT_DIR="${artifact_dir}" \
RYK_INSTALL_DIR="${install_dir}" \
RYK_SHARE_DIR="${share_dir}" \
RYK_INSTALL_SKIP_ONBOARD=1 \
RYK_TEST_ONBOARD_LOG="${onboard_log}" \
sh "${INSTALL_SH}" >/dev/null
[[ ! -s "${onboard_log}" ]] ||
  fail "RYK_INSTALL_SKIP_ONBOARD=1 still invoked doctor/start (log not empty)"

: > "${onboard_log}"
HOME="${home}" \
SHELL=/bin/sh \
RYK_VERSION="${VERSION}" \
RYK_ARTIFACT_DIR="${artifact_dir}" \
RYK_INSTALL_DIR="${install_dir}" \
RYK_SHARE_DIR="${share_dir}" \
RYK_INSTALL_SKIP_ONBOARD=1 \
RYK_TEST_ONBOARD_LOG="${onboard_log}" \
sh "${INSTALL_SH}" >/dev/null
[[ ! -s "${onboard_log}" ]] ||
  fail "RYK_INSTALL_SKIP_ONBOARD=1 still invoked doctor/start (log not empty)"

# Destination hardening: even force mode must not write through symlinked
# install/share parents or final binary/runtime targets.
assert_rejected_without_touching() {
  case_name="$1"
  case_install_dir="$2"
  case_share_dir="$3"
  victim="$4"
  output_path="${tmp_root}/${case_name}.out"

  if HOME="${home}" \
    SHELL=/bin/sh \
    RYK_VERSION="${VERSION}" \
    RYK_ARTIFACT_DIR="${artifact_dir}" \
    RYK_INSTALL_DIR="${case_install_dir}" \
    RYK_SHARE_DIR="${case_share_dir}" \
    RYK_INSTALL_FORCE=1 \
    RYK_INSTALL_SKIP_ONBOARD=1 \
    sh "${INSTALL_SH}" >"${output_path}" 2>&1; then
    fail "${case_name}: installer accepted an unsafe destination"
  fi
  [[ "$(cat "${victim}")" == "untouched" ]] || fail "${case_name}: installer modified the victim"
}

assert_rejected_without_staged_binary() {
  case_name="$1"
  case_install_dir="$2"
  case_share_dir="$3"
  watched_dir="$4"
  output_path="${tmp_root}/${case_name}.out"

  if HOME="${home}" \
    SHELL=/bin/sh \
    RYK_VERSION="${VERSION}" \
    RYK_ARTIFACT_DIR="${artifact_dir}" \
    RYK_INSTALL_DIR="${case_install_dir}" \
    RYK_SHARE_DIR="${case_share_dir}" \
    RYK_INSTALL_FORCE=1 \
    RYK_INSTALL_SKIP_ONBOARD=1 \
    sh "${INSTALL_SH}" >"${output_path}" 2>&1; then
    fail "${case_name}: installer accepted a directory binary destination"
  fi
  for staged_parent in "${case_install_dir}" "${watched_dir}"; do
    if [ -d "${staged_parent}" ] &&
      find "${staged_parent}" -maxdepth 1 -name '.ryk-install.*' -print -quit | grep -q .; then
      fail "${case_name}: installer left a staged binary in the destination area"
    fi
  done
}

victim_file="${tmp_root}/victim-file"
printf 'untouched\n' > "${victim_file}"
binary_final_dir="${tmp_root}/binary-final"
mkdir -p "${binary_final_dir}"
ln -s "${victim_file}" "${binary_final_dir}/ryk"
assert_rejected_without_touching \
  "binary-final-symlink" "${binary_final_dir}" "${tmp_root}/binary-final-share" "${victim_file}"

binary_product_dir="${tmp_root}/binary-product-final"
mkdir -p "${binary_product_dir}"
ln -s "${release_root}/bin/ryk" "${binary_product_dir}/ryk"
binary_product_share="${tmp_root}/binary-product-share"
binary_product_runtime="${binary_product_share}/1.2.9"
mkdir -p "${binary_product_runtime}"
{
  printf 'ryk-runtime-v1\n'
  printf 'version=1.2.9\n'
} > "${binary_product_runtime}/.ryk-installation"
ln -s "${binary_product_runtime}" "${binary_product_share}/current"
product_target_before="$(cat "${release_root}/bin/ryk")"
if ! HOME="${home}" \
  SHELL=/bin/sh \
  RYK_VERSION="${VERSION}" \
  RYK_ARTIFACT_DIR="${artifact_dir}" \
  RYK_INSTALL_DIR="${binary_product_dir}" \
  RYK_SHARE_DIR="${binary_product_share}" \
  RYK_INSTALL_SKIP_ONBOARD=1 \
  sh "${INSTALL_SH}" >/dev/null 2>&1; then
  fail "binary-product-final-symlink: installer rejected an existing ryk symlink"
fi
[[ ! -L "${binary_product_dir}/ryk" ]] ||
  fail "binary-product-final-symlink: installer left the destination symlink in place"
[[ -f "${binary_product_dir}/ryk" ]] ||
  fail "binary-product-final-symlink: installer did not install a regular binary"
[[ "$(cat "${release_root}/bin/ryk")" == "${product_target_before}" ]] ||
  fail "binary-product-final-symlink: installer modified the symlink target"

malicious_target="${tmp_root}/malicious-target"
malicious_marker="${tmp_root}/malicious-executed"
cat > "${malicious_target}" <<'EOF'
#!/usr/bin/env sh
printf 'executed\n' > "${RYK_MALICIOUS_MARKER:?}"
exit 0
EOF
chmod 0755 "${malicious_target}"
malicious_dir="${tmp_root}/malicious-final"
mkdir -p "${malicious_dir}"
ln -s "${malicious_target}" "${malicious_dir}/ryk"
if HOME="${home}" \
  SHELL=/bin/sh \
  RYK_VERSION="${VERSION}" \
  RYK_ARTIFACT_DIR="${artifact_dir}" \
  RYK_INSTALL_DIR="${malicious_dir}" \
  RYK_SHARE_DIR="${tmp_root}/malicious-share" \
  RYK_MALICIOUS_MARKER="${malicious_marker}" \
  RYK_INSTALL_FORCE=1 \
  RYK_INSTALL_SKIP_ONBOARD=1 \
  sh "${INSTALL_SH}" >"${tmp_root}/malicious.out" 2>&1; then
  fail "malicious-final-symlink: installer accepted an executable non-ryk link"
fi
[[ ! -e "${malicious_marker}" ]] ||
  fail "malicious-final-symlink: installer executed the existing destination"

binary_parent_target="${tmp_root}/binary-parent-target"
mkdir -p "${binary_parent_target}"
binary_parent_victim="${binary_parent_target}/ryk"
printf 'untouched\n' > "${binary_parent_victim}"
ln -s "${binary_parent_target}" "${tmp_root}/binary-parent-link"
assert_rejected_without_touching \
  "binary-parent-symlink" "${tmp_root}/binary-parent-link" "${tmp_root}/binary-parent-share" "${binary_parent_victim}"

binary_parent_dotdot_target="${tmp_root}/binary-parent-dotdot-target"
mkdir -p "${binary_parent_dotdot_target}"
ln -s "${binary_parent_dotdot_target}" "${tmp_root}/binary-parent-dotdot-link"
binary_parent_dotdot_safe="${tmp_root}/binary-parent-dotdot-safe"
mkdir -p "${binary_parent_dotdot_safe}"
binary_parent_dotdot_victim="${binary_parent_dotdot_safe}/ryk"
printf 'untouched\n' > "${binary_parent_dotdot_victim}"
assert_rejected_without_touching \
  "binary-parent-dotdot-symlink" \
  "${tmp_root}/binary-parent-dotdot-link/../binary-parent-dotdot-safe" \
  "${tmp_root}/binary-parent-dotdot-share" \
  "${binary_parent_dotdot_victim}"

binary_plain_dotdot_parent="${tmp_root}/binary-plain-dotdot-parent"
mkdir -p "${binary_plain_dotdot_parent}"
binary_plain_dotdot_safe="${tmp_root}/binary-plain-dotdot-safe"
mkdir -p "${binary_plain_dotdot_safe}"
binary_plain_dotdot_victim="${binary_plain_dotdot_safe}/ryk"
printf 'untouched\n' > "${binary_plain_dotdot_victim}"
assert_rejected_without_touching \
  "binary-plain-dotdot" \
  "${binary_plain_dotdot_parent}/../binary-plain-dotdot-safe" \
  "${tmp_root}/binary-plain-dotdot-share" \
  "${binary_plain_dotdot_victim}"

binary_directory_parent="${tmp_root}/binary-directory-parent"
mkdir -p "${binary_directory_parent}/ryk"
assert_rejected_without_staged_binary \
  "binary-final-directory" "${binary_directory_parent}" "${tmp_root}/binary-directory-share" "${binary_directory_parent}/ryk"

binary_directory_target="${tmp_root}/binary-directory-target"
mkdir -p "${binary_directory_target}"
binary_directory_link_parent="${tmp_root}/binary-directory-link-parent"
mkdir -p "${binary_directory_link_parent}"
ln -s "${binary_directory_target}" "${binary_directory_link_parent}/ryk"
assert_rejected_without_staged_binary \
  "binary-final-directory-symlink" "${binary_directory_link_parent}" "${tmp_root}/binary-directory-link-share" "${binary_directory_target}"

runtime_victim_dir="${tmp_root}/runtime-victim"
mkdir -p "${runtime_victim_dir}"
runtime_victim="${runtime_victim_dir}/sentinel"
printf 'untouched\n' > "${runtime_victim}"
runtime_final_share="${tmp_root}/runtime-final-share"
mkdir -p "${runtime_final_share}"
ln -s "${runtime_victim_dir}" "${runtime_final_share}/${VERSION}"
assert_rejected_without_touching \
  "runtime-final-symlink" "${tmp_root}/runtime-final-bin" "${runtime_final_share}" "${runtime_victim}"

runtime_parent_target="${tmp_root}/runtime-parent-target"
mkdir -p "${runtime_parent_target}"
runtime_parent_victim="${runtime_parent_target}/sentinel"
printf 'untouched\n' > "${runtime_parent_victim}"
ln -s "${runtime_parent_target}" "${tmp_root}/runtime-parent-link"
assert_rejected_without_touching \
  "runtime-parent-symlink" "${tmp_root}/runtime-parent-bin" "${tmp_root}/runtime-parent-link" "${runtime_parent_victim}"

runtime_current_target="${tmp_root}/runtime-current-target"
mkdir -p "${runtime_current_target}"
runtime_current_victim="${runtime_current_target}/current"
printf 'untouched\n' > "${runtime_current_victim}"
runtime_current_share="${tmp_root}/runtime-current-share"
mkdir -p "${runtime_current_share}"
ln -s "${runtime_current_target}" "${runtime_current_share}/current"
if ! HOME="${home}" \
  SHELL=/bin/sh \
  RYK_VERSION="${VERSION}" \
  RYK_ARTIFACT_DIR="${artifact_dir}" \
  RYK_INSTALL_DIR="${tmp_root}/runtime-current-bin" \
  RYK_SHARE_DIR="${runtime_current_share}" \
  RYK_INSTALL_FORCE=1 \
  RYK_INSTALL_SKIP_ONBOARD=1 \
  sh "${INSTALL_SH}" >/dev/null 2>&1; then
  fail "runtime-current-symlink: installer failed while replacing an external selector"
fi
[[ "$(cat "${runtime_current_victim}")" == "untouched" ]] ||
  fail "runtime-current-symlink: installer deleted the selector target's current file"

# A failure after runtime staging begins must clean every installer-owned
# staging path. An unmanaged destination forces that late validation failure.
late_cleanup_share="${tmp_root}/late-cleanup-share"
mkdir -p "${late_cleanup_share}/${VERSION}"
printf 'unmanaged\n' > "${late_cleanup_share}/${VERSION}/sentinel"
late_cleanup_install="${tmp_root}/late-cleanup-bin"
if HOME="${home}" \
  SHELL=/bin/sh \
  RYK_VERSION="${VERSION}" \
  RYK_ARTIFACT_DIR="${artifact_dir}" \
  RYK_INSTALL_DIR="${late_cleanup_install}" \
  RYK_SHARE_DIR="${late_cleanup_share}" \
  RYK_INSTALL_FORCE=1 \
  RYK_INSTALL_SKIP_ONBOARD=1 \
  sh "${INSTALL_SH}" >"${tmp_root}/late-cleanup.out" 2>&1; then
  fail "late-cleanup: installer accepted an unmanaged runtime destination"
fi
for staging_parent in "${late_cleanup_install}" "${late_cleanup_share}"; do
  if [ -d "${staging_parent}" ] && find "${staging_parent}" -maxdepth 1 \
    \( -name '.ryk-install.*' -o -name '.ryk-runtime.*' -o -name '.ryk-old.*' -o -name '.ryk-current.*' \) \
    -print -quit | grep -q .; then
    fail "late-cleanup: installer left an atomic-install staging path behind"
  fi
done

if find "${share_dir}" "${install_dir}" -maxdepth 1 \
  \( -name '.ryk-install.*' -o -name '.ryk-runtime.*' -o -name '.ryk-old.*' -o -name '.ryk-current.*' \) \
  -print -quit | grep -q .; then
  fail "installer left atomic-install staging paths behind"
fi

# Package-manager templates are legacy inputs; the supported release channel
# exercised by this test is the checksum-verified curl installer.
grep -qF 'raw.githubusercontent.com/christopherkarani/ryk/main/scripts/install.sh' "${INSTALL_SH}" ||
  fail "curl installer guidance does not use the canonical rykan repository"
if git -C "${REPO_ROOT}" grep -nE \
  'github\.com/(christopherkarani|chriskarani)/(orca|aegis|ryk-rs)([^A-Za-z0-9_-]|$)|raw\.githubusercontent\.com/(christopherkarani|chriskarani)/(orca|aegis|ryk-rs)/' \
  -- README.md AGENTS.md scripts packaging integrations schemas macos docs; then
  fail "public metadata still contains a stale main-repository URL"
fi

# ── Static machine gates on install.sh (D84 adjunct; D86 runtime is above) ──
# The hard-cut ensure door is doctor --fix --from-install; there is no
# pre-hard-cut fallback.
if ! grep -nF 'cli_supports_doctor_fix' "${INSTALL_SH}" >/dev/null 2>&1; then
  fail 'scripts/install.sh missing cli_supports_doctor_fix capability probe'
fi
if ! grep -nF '"$DESTINATION" doctor --fix' "${INSTALL_SH}" >/dev/null 2>&1; then
  fail 'scripts/install.sh missing invocation-anchored "$DESTINATION" doctor --fix'
fi
if ! grep -nF '"$DESTINATION" doctor --fix --from-install' "${INSTALL_SH}" >/dev/null 2>&1; then
  fail 'scripts/install.sh missing "$DESTINATION" doctor --fix --from-install (install-scope flag)'
fi
if grep -nE 'start --auto|start_auto_fallback|pre-W1|legacy fallback' "${INSTALL_SH}" >/dev/null 2>&1; then
  fail 'scripts/install.sh still contains a removed start --auto compatibility fallback'
fi
# Hard-fail operator remediation must re-teach install trust scope (not bare doctor --fix).
# Match re-teach copy (ryk doctor --fix --from-install), not only the binary invocation.
if ! grep -nE 'ryk doctor --fix --from-install' "${INSTALL_SH}" >/dev/null 2>&1; then
  fail 'scripts/install.sh hard-fail remediation missing re-teach of ryk doctor --fix --from-install'
fi
if ! grep -nF 'Re-run from your home directory:' "${INSTALL_SH}" >/dev/null 2>&1; then
  fail 'scripts/install.sh hard-fail remediation missing HOME guidance (Re-run from your home directory)'
fi
if ! grep -nF 'cd "$HOME"' "${INSTALL_SH}" >/dev/null 2>&1; then
  fail 'scripts/install.sh missing cd "$HOME" around ensure invocation'
fi
if ! grep -n 'RYK_RESOURCE_ROOT' "${INSTALL_SH}" >/dev/null 2>&1; then
  fail "scripts/install.sh missing RYK_RESOURCE_ROOT export around ensure"
fi
if grep -niE 'fully protected|all hosts wired|protection complete|full protection' "${INSTALL_SH}" >/dev/null 2>&1; then
  fail "scripts/install.sh contains D06 full-protection forbid phrases"
fi
# Interactive guided start must not be the taught hard-cut install door.
if grep -nE '(^|[^$])ryk start' "${INSTALL_SH}" >/dev/null 2>&1; then
  fail "scripts/install.sh still teaches bare ryk start (use doctor --fix --from-install)"
fi
# Harness self-check (D84): the capable-binary path must require doctor --fix.
if ! grep -nF "grep -c '^doctor --fix$'" "${BASH_SOURCE[0]}" >/dev/null 2>&1; then
  fail "harness must count doctor --fix (D86)"
fi
if grep -nE "grep -c '\\^start --auto\\\$'[[:space:]].*==[[:space:]]*1" "${BASH_SOURCE[0]}" >/dev/null 2>&1; then
  fail "harness must not treat start --auto count==1 as the green path for capable binaries"
fi

(
  cd "${home}"
  # shellcheck disable=SC1090
  . "${home}/.profile"
)
[[ ! -e "${home}/PATH_INJECTION" ]] || fail "install path executed shell syntax from the profile"
[[ ! -e "${home}/RESOURCE_INJECTION" ]] || fail "resource path executed shell syntax from the profile"

printf '[install-first-user-regression] passed\n'
