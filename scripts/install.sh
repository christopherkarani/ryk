#!/usr/bin/env sh
set -eu

# ryk installer (macOS / Linux) — canonical Rykan V install path.
#
# Documented one-liner:
#   curl -fsSL https://rykanv.com/install | sh
# Fallback (same script, GitHub raw):
#   curl -fsSL https://raw.githubusercontent.com/christopherkarani/ryk/main/scripts/install.sh | sh
#
# Environment (RYK_* only (hard-cut)):
#   RYK_VERSION         Pin release version (default: latest / local VERSION / 1.2.9)
#   RYK_INSTALL_DIR Binary install dir (default: ~/.local/bin)
#   RYK_SHARE_DIR     Runtime share root (default: ~/.local/share/ryk — kept in 5a)
#   RYK_BASE_URL       Override release base URL
#   RYK_ARTIFACT_DIR Offline install from a local dist/ folder
#   RYK_INSTALL_FORCE=1 Allow overwriting a non-product file at the destination
#   RYK_INSTALL_QUIET=1 Suppress non-error UI (still installs; prints activation line)
#   RYK_INSTALL_SKIP_ONBOARD=1  Skip post-install ensure
#   NO_COLOR             Disable ANSI color even on a TTY
#
# Ensure door (release/install contract):
# - The hard-cut release contract requires `doctor --fix --from-install`.
# - An artifact whose CLI does not advertise that door is rejected instead of
#   being silently onboarded through a removed or weaker command.
#
# Robust VERSION resolution (piped-safe):
# - File execution (dev, local checkout): read ../VERSION when present.
# - Piped public install (curl | sh): $0 is not a regular file, so we skip the
#   local read and fall through to the GitHub API (or RYK_VERSION / 1.2.9).
# - RYK_VERSION always wins. Hardcoded value is only the final safety net.

SCRIPT_DIR=""
if [ -f "$0" ] 2>/dev/null; then
  SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
fi

# ── Presentation ─────────────────────────────────────────────────────────────
# Brand + named steps + activation hero. Quiet / NO_COLOR / pipe degrade cleanly.
# Glyphs align with src/tui/render.zig (active/done use success green).

QUIET=0
if [ "${RYK_INSTALL_QUIET:-0}" = "1" ]; then
  QUIET=1
fi

IS_TTY=0
if [ -t 1 ] 2>/dev/null; then
  IS_TTY=1
fi

USE_COLOR=0
if [ "$QUIET" -eq 0 ] && [ "$IS_TTY" -eq 1 ] && [ -z "${NO_COLOR:-}" ] && [ "${TERM:-}" != "dumb" ]; then
  USE_COLOR=1
fi

# Progress is TTY+!quiet only — NO_COLOR must not hide bars.
SHOW_PROGRESS=0
if [ "$QUIET" -eq 0 ] && [ "$IS_TTY" -eq 1 ]; then
  SHOW_PROGRESS=1
fi

if [ "$USE_COLOR" -eq 1 ]; then
  C_RESET="$(printf '\033[0m')"
  C_BOLD="$(printf '\033[1m')"
  C_DIM="$(printf '\033[2m')"
  C_RED="$(printf '\033[31m')"
  C_GREEN="$(printf '\033[32m')"
  C_YELLOW="$(printf '\033[33m')"
  C_CYAN="$(printf '\033[36m')"
else
  C_RESET="" C_BOLD="" C_DIM="" C_RED="" C_GREEN="" C_YELLOW="" C_CYAN=""
fi

ui_dim() {
  [ "$QUIET" -eq 1 ] && return 0
  printf '%s%s%s\n' "$C_DIM" "$*" "$C_RESET"
}

ui_err() {
  printf '  %s✗%s %s\n' "$C_RED" "$C_RESET" "$*" >&2
}

print_banner() {
  [ "$QUIET" -eq 1 ] && return 0
  printf '\n'
  # Single neutral title — no split color, no rule line.
  printf '  %sRykan V  v%s%s\n' "$C_BOLD" "$1" "$C_RESET"
  printf '  %s%s → %s%s\n' "$C_DIM" "$2" "$3" "$C_RESET"
  printf '\n'
}

step_active() {
  [ "$QUIET" -eq 1 ] && return 0
  printf '  %s›%s %s%s%s\n' "$C_GREEN" "$C_RESET" "$C_BOLD" "$1" "$C_RESET"
}

step_done() {
  [ "$QUIET" -eq 1 ] && return 0
  if [ -n "${2:-}" ]; then
    printf '  %s✓%s %s  %s%s%s\n' "$C_GREEN" "$C_RESET" "$1" "$C_DIM" "$2" "$C_RESET"
  else
    printf '  %s✓%s %s\n' "$C_GREEN" "$C_RESET" "$1"
  fi
}

# fail MESSAGE [REMEDIATION]
fail() {
  msg="$1"
  remediation="${2:-}"
  printf '\n' >&2
  ui_err "$msg"
  if [ -n "$remediation" ]; then
    printf '%s\n' "$remediation" | while IFS= read -r line || [ -n "$line" ]; do
      [ -n "$line" ] && printf '    %s%s%s\n' "$C_DIM" "$line" "$C_RESET" >&2
    done
  fi
  printf '\n' >&2
  printf '  %sDocs%s  https://github.com/christopherkarani/ryk/blob/main/docs/install.md\n' "$C_DIM" "$C_RESET" >&2
  exit 1
}

# Refuse to write through symlink components in a configured install path.
# Generic runtime paths reject their final component too; binary destinations
# use the parent-only helper below so a managed final binary link can be
# replaced without following it. Paths are required to be absolute because
# the installer changes working directory during onboarding.
reject_symlink_components() {
  checked_path="$1"
  checked_label="$2"
  case "$checked_path" in
    /*) ;;
    *) fail "$checked_label must be an absolute path: $checked_path" ;;
  esac

  checked_cursor="/"
  checked_remaining="${checked_path#/}"
  while [ -n "$checked_remaining" ]; do
    case "$checked_remaining" in
      */*)
        checked_component="${checked_remaining%%/*}"
        checked_remaining="${checked_remaining#*/}"
        ;;
      *)
        checked_component="$checked_remaining"
        checked_remaining=""
        ;;
    esac
    case "$checked_component" in
      ""|.) continue ;;
      ..)
        fail "$checked_label must not contain '..': $checked_path" \
          "Choose an absolute path without parent-directory components."
        ;;
    esac
    checked_cursor="${checked_cursor%/}/$checked_component"
    if [ -L "$checked_cursor" ]; then
      fail "refusing symlinked $checked_label path: $checked_cursor" \
        "Choose a path whose parents and final target are real directories or files."
    fi
  done
}

# Binary destinations support one managed exception: an existing final symlink
# may point at an older ryk binary. The staged `mv` replaces that link itself,
# but would move into a directory symlink, so validate the parents and final
# destination separately.
reject_symlink_parents() {
  checked_path="$1"
  checked_label="$2"
  reject_symlink_components "$(dirname "$checked_path")" "$checked_label"
}

# Contract: /^    eval / — always printed, including quiet.
print_activation() {
  printf '    eval "$(%s env)"\n' "$1"
}

# ── Version resolution ───────────────────────────────────────────────────────

DEFAULT_VERSION=""
if [ -n "$SCRIPT_DIR" ] && [ -r "${SCRIPT_DIR}/../VERSION" ]; then
  DEFAULT_VERSION="$(tr -d '[:space:]' < "${SCRIPT_DIR}/../VERSION" 2>/dev/null || true)"
fi

RESOLVED_FROM="fallback 1.2.9"
if [ -n "${RYK_VERSION:-}" ]; then
  RESOLVED_FROM="version environment override"
elif [ -n "${DEFAULT_VERSION}" ]; then
  RESOLVED_FROM="local VERSION"
else
  # Piped / non-filesystem path: best-effort latest release.
  _url="https://api.github.com/repos/christopherkarani/ryk/releases/latest"
  _resp=""
  if command -v curl >/dev/null 2>&1; then
    _resp="$(curl -fsSL --max-time 8 -H "User-Agent: ryk-install-script/1.0 (github.com/christopherkarani/ryk)" "$_url" 2>/dev/null || true)"
  elif command -v wget >/dev/null 2>&1; then
    _resp="$(wget -qO- --timeout=8 --user-agent="ryk-install-script/1.0 (github.com/christopherkarani/ryk)" "$_url" 2>/dev/null || true)"
  fi
  if [ -n "${_resp:-}" ]; then
    _tag="$(printf '%s' "$_resp" | grep -o '"tag_name"[[:space:]]*:[[:space:]]*"[vV]*[^"]*"' | head -n1 | \
      sed -E 's/.*"tag_name"[[:space:]]*:[[:space:]]*"[vV]?([^"]*)".*/\1/' || true)"
    if [ -n "${_tag:-}" ]; then
      DEFAULT_VERSION="$_tag"
      RESOLVED_FROM="GitHub latest"
    fi
  fi
fi

VERSION="${RYK_VERSION:-${DEFAULT_VERSION:-1.2.9}}"
BASE_URL="${RYK_BASE_URL:-https://github.com/christopherkarani/ryk/releases/download/v${VERSION}}"
INSTALL_DIR="${RYK_INSTALL_DIR:-${HOME}/.local/bin}"
SHARE_DIR="${RYK_SHARE_DIR:-${HOME}/.local/share/ryk}"
RESOURCE_ROOT="${SHARE_DIR}/${VERSION}"
CURRENT_LINK="${SHARE_DIR}/current"
ARTIFACT_DIR="${RYK_ARTIFACT_DIR:-}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/ryk-install.XXXXXX")"
RUNTIME_DIRS="integrations fixtures schemas policies ryk-pi"
INSTALL_MARKER=".ryk-installation"
install_stage=""
runtime_stage=""
runtime_backup=""
current_stage=""

# `mv source destination` follows a destination symlink to a directory on
# macOS/BSD. Use the platform-specific no-follow form so replacement always
# targets the final path itself. If neither form is available, fail closed.
replace_path_without_following_destination() {
  replace_source="$1"
  replace_destination="$2"

  if mv --version >/dev/null 2>&1; then
    mv -f -T "$replace_source" "$replace_destination"
    return $?
  fi
  mv -f -h "$replace_source" "$replace_destination" 2>/dev/null
}

cleanup() {
  if [ -n "${current_stage:-}" ] && {
    [ -e "$current_stage" ] || [ -L "$current_stage" ]
  }; then
    rm -f "$current_stage" 2>/dev/null || true
  fi
  if [ -n "${install_stage:-}" ] && {
    [ -e "$install_stage" ] || [ -L "$install_stage" ]
  }; then
    rm -f "$install_stage" 2>/dev/null || true
  fi
  if [ -n "${runtime_stage:-}" ] && {
    [ -e "$runtime_stage" ] || [ -L "$runtime_stage" ]
  }; then
    rm -rf "$runtime_stage" 2>/dev/null || true
  fi
  if [ -n "${runtime_backup:-}" ]; then
    backup_marker="$runtime_backup/$INSTALL_MARKER"
    if [ -f "$backup_marker" ] && [ ! -L "$backup_marker" ] &&
      grep -q '^ryk-runtime-v1$' "$backup_marker" 2>/dev/null; then
      if [ -d "$RESOURCE_ROOT" ] && [ -f "$RESOURCE_ROOT/$INSTALL_MARKER" ] &&
        [ ! -L "$RESOURCE_ROOT/$INSTALL_MARKER" ] &&
        grep -q '^ryk-runtime-v1$' "$RESOURCE_ROOT/$INSTALL_MARKER" 2>/dev/null; then
        rm -rf "$RESOURCE_ROOT" 2>/dev/null || true
      elif [ -L "$RESOURCE_ROOT" ]; then
        rm -f "$RESOURCE_ROOT" 2>/dev/null || true
      fi
      if [ ! -e "$RESOURCE_ROOT" ] && [ ! -L "$RESOURCE_ROOT" ]; then
        replace_path_without_following_destination "$runtime_backup" "$RESOURCE_ROOT" \
          >/dev/null 2>&1 || true
      fi
    fi
    if [ ! -f "$backup_marker" ]; then
      rm -rf "$runtime_backup" 2>/dev/null || true
    fi
  fi
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

detect_os() {
  case "${RYK_OS_OVERRIDE:-$(uname -s)}" in
    Darwin|darwin) printf 'darwin' ;;
    Linux|linux) printf 'linux' ;;
    *) fail "unsupported operating system: ${RYK_OS_OVERRIDE:-$(uname -s)}" \
         "ryk's curl installer supports macOS and Linux only.
Windows: use scripts/install.ps1
Docs:    https://github.com/christopherkarani/ryk/blob/main/docs/install.md" ;;
  esac
}

detect_arch() {
  case "${RYK_ARCH_OVERRIDE:-$(uname -m)}" in
    x86_64|amd64) printf 'amd64' ;;
    arm64|aarch64) printf 'arm64' ;;
    *) fail "unsupported architecture: ${RYK_ARCH_OVERRIDE:-$(uname -m)}" \
         "Supported: amd64 (x86_64), arm64 (aarch64)." ;;
  esac
}

download() {
  url="$1"
  output="$2"
  if command -v curl >/dev/null 2>&1; then
    if [ "$SHOW_PROGRESS" -eq 1 ]; then
      set -- curl -fL --progress-bar "$url" -o "$output"
    else
      set -- curl -fsSL "$url" -o "$output"
    fi
  elif command -v wget >/dev/null 2>&1; then
    if [ "$SHOW_PROGRESS" -eq 1 ]; then
      # Fall back if --show-progress is unsupported.
      wget --show-progress -q "$url" -O "$output" 2>&1 || wget -q "$url" -O "$output" || \
        fail "download failed: $url" "Check network access and that release v${VERSION} exists.
	Retry: RYK_VERSION=${VERSION} curl -fsSL https://rykanv.com/install | sh"
      return 0
    fi
    set -- wget -q "$url" -O "$output"
  else
    fail "curl or wget is required to download release artifacts" \
      "Install curl, then re-run the installer."
  fi
  "$@" || fail "download failed: $url" "Check network access and that release v${VERSION} exists.
	Retry: RYK_VERSION=${VERSION} curl -fsSL https://rykanv.com/install | sh"
}

sha256_file() {
  file="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$file" | awk '{print $1}'
  else
    return 1
  fi
}

shell_quote() {
  printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"
}

verify_checksum() {
  artifact_name="$1"
  artifact_path="$2"
  checksums_path="$3"

  [ -f "$checksums_path" ] || fail "checksums.txt not found" \
    "Download checksums.txt with the archive and verify manually before installing.
Offline: set RYK_ARTIFACT_DIR to a folder containing the archive + checksums.txt."
  expected="$(awk -v name="$artifact_name" '$2 == name {print $1}' "$checksums_path")"
  [ -n "$expected" ] || fail "no checksum entry found for $artifact_name" \
    "The release checksums.txt may not list this platform artifact yet."
  actual="$(sha256_file "$artifact_path")" || fail "no SHA-256 tool found" \
    "Install sha256sum (coreutils) or shasum and retry."
  if [ "$expected" != "$actual" ]; then
    fail "checksum mismatch for $artifact_name" \
      "Expected: ${expected}
Got:      ${actual}
Refuse to install a corrupted or tampered archive.
	Retry:    RYK_VERSION=${VERSION} curl -fsSL https://rykanv.com/install | sh
	Offline:  set RYK_ARTIFACT_DIR after verifying checksums by hand."
  fi
}

# Exit 0 if the install-managed runtime selector contains the static marker
# written by this installer; print its semver on stdout. Product detection must
# never execute an existing destination because it may be an attacker-controlled
# executable reached through a symlink.
managed_runtime_version() {
  managed_marker="$CURRENT_LINK/$INSTALL_MARKER"
  managed_target="$(readlink "$CURRENT_LINK" 2>/dev/null || true)"
  reject_symlink_parents "$CURRENT_LINK" "runtime selector"
  [ -L "$CURRENT_LINK" ] || return 1
  case "$managed_target" in
    "$SHARE_DIR"/*) ;;
    *) return 1 ;;
  esac
  reject_symlink_components "$managed_target" "runtime selector target"
  [ -f "$managed_marker" ] || return 1
  [ ! -L "$managed_marker" ] || return 1
  grep -q '^ryk-runtime-v1$' "$managed_marker" 2>/dev/null || return 1
  managed_version="$(sed -n 's/^version=\([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\)$/\1/p' \
    "$managed_marker" | head -n1)"
  [ -n "$managed_version" ] || return 1
  printf '%s\n' "$managed_version"
}

validate_binary_destination() {
  validate_destination="$1"
  reject_symlink_parents "$validate_destination" "binary destination"

  if [ -d "$validate_destination" ]; then
    fail "refusing directory binary destination path: $validate_destination" \
      "Choose a path whose final target is a regular file or an existing ryk symlink."
  fi

  if [ -L "$validate_destination" ]; then
    if ! managed_runtime_version >/dev/null; then
      fail "refusing symlinked binary destination path: $validate_destination" \
        "Remove the link or complete a managed ryk install under ${SHARE_DIR}, then retry."
    fi
    return 0
  fi

  if [ -e "$validate_destination" ]; then
    [ -f "$validate_destination" ] ||
      fail "refusing non-file binary destination path: $validate_destination" \
        "Choose a path whose final target is a regular file or an existing ryk symlink."
    if [ "${RYK_INSTALL_FORCE:-0}" != "1" ] && ! managed_runtime_version >/dev/null; then
      fail "refusing to overwrite non-ryk file at $validate_destination" \
        "Set RYK_INSTALL_FORCE=1 to replace it, or choose another install dir."
    fi
  fi
}

safe_install() {
  source_bin="$1"
  destination="$2"

  validate_binary_destination "$destination"

  reject_symlink_components "$INSTALL_DIR" "binary install directory"
  mkdir -p "$INSTALL_DIR"
  reject_symlink_components "$INSTALL_DIR" "binary install directory"
  install_stage="$(mktemp "$INSTALL_DIR/.ryk-install.XXXXXX")" ||
    fail "could not create binary staging file under $INSTALL_DIR"
  cp "$source_bin" "$install_stage" || {
    rm -f "$install_stage"
    fail "could not stage ryk binary under $INSTALL_DIR"
  }
  chmod 0755 "$install_stage" || {
    rm -f "$install_stage"
    install_stage=""
    fail "could not make the staged ryk binary executable"
  }
  validate_binary_destination "$destination"
  if ! replace_path_without_following_destination "$install_stage" "$destination"; then
    fail "could not atomically install ryk at $destination"
  fi
  install_stage=""
}

install_runtime_assets() {
  extract_root="$1"

  reject_symlink_components "$SHARE_DIR" "runtime share directory"
  reject_symlink_components "$RESOURCE_ROOT" "runtime destination"
  mkdir -p "$SHARE_DIR"
  reject_symlink_components "$SHARE_DIR" "runtime share directory"
  if [ -e "$CURRENT_LINK" ] && [ ! -L "$CURRENT_LINK" ]; then
    fail "refusing to replace non-symlink runtime selector: $CURRENT_LINK"
  fi

  for dir in $RUNTIME_DIRS; do
    [ -d "$extract_root/$dir" ] || fail "release archive missing runtime directory: $dir" \
      "Re-download the official release artifact for v${VERSION}."
  done

  runtime_stage="$(mktemp -d "$SHARE_DIR/.ryk-runtime.XXXXXX")" ||
    fail "could not create runtime staging directory under $SHARE_DIR"
  for dir in $RUNTIME_DIRS; do
    cp -R "$extract_root/$dir" "$runtime_stage/" || {
      rm -rf "$runtime_stage"
      runtime_stage=""
      fail "could not stage runtime directory: $dir"
    }
  done
  if [ -d "$extract_root/ryk-dashboard-ui" ]; then
    cp -R "$extract_root/ryk-dashboard-ui" "$runtime_stage/" || {
      rm -rf "$runtime_stage"
      runtime_stage=""
      fail "could not stage dashboard UI assets"
    }
  fi
  {
    printf 'ryk-runtime-v1\n'
    printf 'version=%s\n' "$VERSION"
  } > "$runtime_stage/$INSTALL_MARKER"

  reject_symlink_components "$RESOURCE_ROOT" "runtime destination"
  runtime_backup=""
  if [ -e "$RESOURCE_ROOT" ]; then
    [ -d "$RESOURCE_ROOT" ] || {
      rm -rf "$runtime_stage"
      runtime_stage=""
      fail "refusing to replace non-directory runtime destination: $RESOURCE_ROOT"
    }
    [ -f "$RESOURCE_ROOT/$INSTALL_MARKER" ] &&
      [ ! -L "$RESOURCE_ROOT/$INSTALL_MARKER" ] &&
      grep -q '^ryk-runtime-v1$' "$RESOURCE_ROOT/$INSTALL_MARKER" 2>/dev/null || {
      rm -rf "$runtime_stage"
      runtime_stage=""
      fail "refusing to replace an unmanaged runtime directory: $RESOURCE_ROOT"
    }
    runtime_backup="$(mktemp -d "$SHARE_DIR/.ryk-old.XXXXXX")" ||
      fail "could not reserve runtime backup path under $SHARE_DIR"
    rmdir "$runtime_backup" || fail "could not prepare the runtime backup path"
    if ! replace_path_without_following_destination "$RESOURCE_ROOT" "$runtime_backup"; then
      rm -rf "$runtime_stage"
      runtime_stage=""
      fail "could not move the prior runtime into a safe backup"
    fi
  fi

  reject_symlink_components "$SHARE_DIR" "runtime share directory"
  reject_symlink_components "$RESOURCE_ROOT" "runtime destination"
  if ! replace_path_without_following_destination "$runtime_stage" "$RESOURCE_ROOT"; then
    fail "could not atomically install runtime assets at $RESOURCE_ROOT"
  fi
  runtime_stage=""

  reject_symlink_components "$SHARE_DIR" "runtime share directory"
  # Update the selector without following an existing current→version symlink.
  # A staged link plus the same no-follow move used for binaries also avoids
  # macOS/BSD's `mv`-into-directory behavior and never mutates the old target.
  if [ -e "$CURRENT_LINK" ] && [ ! -L "$CURRENT_LINK" ]; then
    fail "refusing to replace non-symlink runtime selector: $CURRENT_LINK"
  fi
  current_stage="$(mktemp "$SHARE_DIR/.ryk-current.XXXXXX")" ||
    fail "could not create runtime selector staging link under $SHARE_DIR"
  rm -f "$current_stage" || fail "could not prepare runtime selector staging link"
  ln -s "$RESOURCE_ROOT" "$current_stage" ||
    fail "could not stage the installed runtime selector"
  reject_symlink_components "$SHARE_DIR" "runtime share directory"
  if [ -e "$CURRENT_LINK" ] && [ ! -L "$CURRENT_LINK" ]; then
    fail "refusing to replace non-symlink runtime selector: $CURRENT_LINK"
  fi
  if ! replace_path_without_following_destination "$current_stage" "$CURRENT_LINK"; then
    fail "could not atomically select the installed runtime" \
      "Could not point ${CURRENT_LINK} at ${RESOURCE_ROOT}."
  fi
  current_stage=""
  if [ -n "$runtime_backup" ]; then
    rm -rf "$runtime_backup" || fail "could not remove the prior runtime backup"
    runtime_backup=""
  fi
}

rc_file_for_shell() {
  shell_name="$1"
  case "$shell_name" in
    */zsh) printf '%s' "${ZDOTDIR:-$HOME}/.zshrc" ;;
    */bash)
      if [ -f "$HOME/.bashrc" ]; then
        printf '%s' "$HOME/.bashrc"
      elif [ -f "$HOME/.bash_profile" ]; then
        printf '%s' "$HOME/.bash_profile"
      else
        printf '%s' "$HOME/.bashrc"
      fi
      ;;
    */fish) printf '%s' "$HOME/.config/fish/config.fish" ;;
    *) printf '%s' "$HOME/.profile" ;;
  esac
}

ensure_path_entry() {
  dir="$1"
  shell_path="${SHELL:-/bin/sh}"
  shell_name="$(basename "$shell_path")"
  rc_file="$(rc_file_for_shell "$shell_path")"

  if [ ! -d "$(dirname "$rc_file")" ] && [ "$(dirname "$rc_file")" != "$HOME" ]; then
    mkdir -p "$(dirname "$rc_file")"
  fi

  marker="# Added by ryk installer"
  previous_marker="# Added by ryk installer"
  quoted_dir="$(shell_quote "$dir")"
  if [ "$shell_name" = "fish" ]; then
    path_line="fish_add_path -- $quoted_dir"
  else
    path_line="export PATH=$quoted_dir:\"\$PATH\""
  fi

  if [ -f "$rc_file" ] && {
    grep -qF "$marker" "$rc_file" 2>/dev/null ||
      grep -qF "$previous_marker" "$rc_file" 2>/dev/null
  }; then
    tmp="$(mktemp)"
    awk -v marker="$marker" -v previous_marker="$previous_marker" -v new_line="$path_line" '
      $0 == marker || $0 == previous_marker { print marker; print new_line; skip=1; next }
      skip && (/^export PATH=/ || /^fish_add_path -- /) { next }
      skip && $0 == "" { skip=0 }
      { print }
    ' "$rc_file" > "$tmp"
    mv "$tmp" "$rc_file"
    return 0
  fi

  printf '\n%s\n%s\n' "$marker" "$path_line" >> "$rc_file"
}

ensure_resource_root_entry() {
  shell_path="${SHELL:-/bin/sh}"
  shell_name="$(basename "$shell_path")"
  rc_file="$(rc_file_for_shell "$shell_path")"
  marker="# ryk runtime assets"
  previous_marker="# ryk runtime assets"
  quoted_current="$(shell_quote "$CURRENT_LINK")"
  if [ "$shell_name" = "fish" ]; then
    resource_line="set -gx RYK_RESOURCE_ROOT $quoted_current"
  else
    resource_line="export RYK_RESOURCE_ROOT=$quoted_current"
  fi

  if [ ! -d "$(dirname "$rc_file")" ] && [ "$(dirname "$rc_file")" != "$HOME" ]; then
    mkdir -p "$(dirname "$rc_file")"
  fi

  if [ -f "$rc_file" ] && {
    grep -qF "$marker" "$rc_file" 2>/dev/null ||
      grep -qF "$previous_marker" "$rc_file" 2>/dev/null
  }; then
    tmp="$(mktemp)"
    awk -v marker="$marker" -v previous_marker="$previous_marker" -v new_line="$resource_line" '
      $0 == marker || $0 == previous_marker { print marker; print new_line; skip=1; next }
      skip && (/^export RYK_RESOURCE_ROOT=/ || /^set -gx RYK_RESOURCE_ROOT /) { next }
      skip && $0 == "" { skip=0 }
      { print }
    ' "$rc_file" > "$tmp"
    mv "$tmp" "$rc_file"
    return 0
  fi

  {
    printf '\n%s\n' "$marker"
    printf '%s\n' "$resource_line"
  } >> "$rc_file"
}

# previous_version may be empty (fresh), a semver (upgrade/reinstall), or "installed".
print_success() {
  previous_version="$1"
  quoted_destination="$2"
  missing_dashboard="$3"
  onboarding_ran="${4:-0}"

  if [ "$QUIET" -eq 1 ]; then
    print_activation "$quoted_destination"
    return 0
  fi

  printf '\n'
  if [ -n "$previous_version" ] && [ "$previous_version" != "$VERSION" ] && [ "$previous_version" != "installed" ]; then
    printf '  %s✓%s  %sryk v%s installed%s  %s(upgraded from %s)%s\n' \
      "$C_GREEN" "$C_RESET" "$C_BOLD" "$VERSION" "$C_RESET" "$C_DIM" "$previous_version" "$C_RESET"
  elif [ -n "$previous_version" ]; then
    printf '  %s✓%s  %sryk v%s reinstalled%s\n' \
      "$C_GREEN" "$C_RESET" "$C_BOLD" "$VERSION" "$C_RESET"
  else
    printf '  %s✓%s  %sryk v%s installed%s\n' \
      "$C_GREEN" "$C_RESET" "$C_BOLD" "$VERSION" "$C_RESET"
  fi

  printf '\n'
  print_activation "$quoted_destination"

  if [ "$onboarding_ran" -eq 0 ]; then
    printf '\n'
    printf '    ryk doctor --fix --from-install\n'
  fi

  if [ "$missing_dashboard" -eq 1 ]; then
    printf '\n'
    printf '  %s⚠%s Dashboard assets missing from this archive.\n' "$C_YELLOW" "$C_RESET"
  fi
  printf '\n'
}

# ── Main ─────────────────────────────────────────────────────────────────────

OS="$(detect_os)"
ARCH="$(detect_arch)"
ARTIFACT="ryk-v${VERSION}-${OS}-${ARCH}.tar.gz"
DESTINATION="$INSTALL_DIR/ryk"

# Empty = fresh install; semver or "installed" = existing CLI at destination.
PREVIOUS_VERSION=""
if previous_out="$(managed_runtime_version)"; then
  PREVIOUS_VERSION="$previous_out"
  if [ -z "$PREVIOUS_VERSION" ]; then
    PREVIOUS_VERSION="installed"
  fi
fi

print_banner "$VERSION" "${OS}/${ARCH}" "$INSTALL_DIR"

resolve_detail="v${VERSION} (${RESOLVED_FROM})"
if [ -n "$PREVIOUS_VERSION" ] && [ "$PREVIOUS_VERSION" != "$VERSION" ] && [ "$PREVIOUS_VERSION" != "installed" ]; then
  resolve_detail="${resolve_detail}; upgrading ${PREVIOUS_VERSION} → ${VERSION}"
elif [ -n "$PREVIOUS_VERSION" ]; then
  resolve_detail="${resolve_detail}; reinstall"
fi
step_done "Resolve release" "$resolve_detail"

if [ -n "$ARTIFACT_DIR" ]; then
  if [ -f "$ARTIFACT_DIR/$ARTIFACT" ]; then
    :
  else
    fail "artifact not found: $ARTIFACT_DIR/$ARTIFACT" \
      "Expected the canonical release archive under RYK_ARTIFACT_DIR."
  fi
  cp "$ARTIFACT_DIR/$ARTIFACT" "$TMP_DIR/$ARTIFACT"
  [ -f "$ARTIFACT_DIR/checksums.txt" ] || fail "checksums.txt not found in $ARTIFACT_DIR" \
    "Place checksums.txt next to the archive for offline install."
  cp "$ARTIFACT_DIR/checksums.txt" "$TMP_DIR/checksums.txt"
  step_done "Use local artifacts" "$ARTIFACT_DIR"
else
  step_active "Download archive"
  download "$BASE_URL/$ARTIFACT" "$TMP_DIR/$ARTIFACT"
  download "$BASE_URL/checksums.txt" "$TMP_DIR/checksums.txt"
  step_done "Download archive" "$ARTIFACT"
fi

verify_checksum "$ARTIFACT" "$TMP_DIR/$ARTIFACT" "$TMP_DIR/checksums.txt"
step_done "Verify SHA-256" "ok"

step_active "Install binaries + runtime"
# Suppress only harmless macOS provenance xattr noise from Linux tar of macOS archives.
tar -xzf "$TMP_DIR/$ARTIFACT" -C "$TMP_DIR" 2>"$TMP_DIR/.tar.err" || {
  grep -v 'LIBARCHIVE.xattr.com.apple.provenance' "$TMP_DIR/.tar.err" | \
    grep -v 'Ignoring unknown extended header keyword' >&2 || true
  rm -f "$TMP_DIR/.tar.err"
  fail "tar extraction failed" \
    "The archive may be corrupt. Re-download and verify checksums."
}
rm -f "$TMP_DIR/.tar.err"

EXTRACT_ROOT="$(find "$TMP_DIR" -mindepth 1 -maxdepth 1 -type d | head -n 1)"
[ -n "$EXTRACT_ROOT" ] || fail "artifact did not contain an extracted release root" \
  "Unexpected archive layout for ${ARTIFACT}."

FOUND_BIN=""
if [ -x "$EXTRACT_ROOT/bin/ryk" ]; then
  FOUND_BIN="$EXTRACT_ROOT/bin/ryk"
fi
[ -n "$FOUND_BIN" ] || fail "artifact did not contain an executable ryk binary" \
  "Unexpected archive layout for ${ARTIFACT}."

safe_install "$FOUND_BIN" "$DESTINATION"
install_runtime_assets "$EXTRACT_ROOT"
step_done "Install binaries + runtime" "ryk + assets"

ensure_path_entry "$INSTALL_DIR"
ensure_resource_root_entry "$CURRENT_LINK"
step_done "Configure shell" "PATH + runtime resource root"

# ── Global onboarding (ensure door) ──────────────────────────────────────────
# Setup is operational, not presentation: run for TTY, non-TTY, and quiet
# installs. HOME is the global policy/plugin scope; never mutate an arbitrary
# caller or Homebrew working directory. Trust scope: cd "$HOME" + export
# RYK_RESOURCE_ROOT to the installed share current link.
# Soft host fails exit 0 with partial honesty from the ensure door — install
# must not claim full-protection completion copy.
#
# Release/install contract: the installed binary must advertise the canonical
# hard-cut ensure door before the installer invokes it.

# Returns 0 when BIN supports the W1 ensure door (help advertises --fix).
cli_supports_doctor_fix() {
  _cli_bin="$1"
  _cli_help="$("$_cli_bin" doctor --help 2>&1)" || true
  printf '%s\n' "$_cli_help" | grep -Eq -- '(^|[^[:alnum:]_-])--fix([^[:alnum:]_-]|$)'
}

# Run the canonical ensure door for the installed binary.
run_install_ensure() {
  if ! cli_supports_doctor_fix "$DESTINATION"; then
    fail "installed ryk binary does not support the required doctor --fix ensure door" \
      "This installer requires a current Rykan V release. Re-download the installer or set RYK_VERSION to a current release, then retry."
  fi
  ENSURE_MODE=doctor_fix
  "$DESTINATION" doctor --fix --from-install
}

# One-line step receipt from captured ensure output. Install owns the UI —
# never stream ensure's TUI/tables/banners. No D06 full-protection claims.
summarize_ensure_receipt() {
  _ob_file="$1"
  _plain=""
  if [ -s "$_ob_file" ]; then
    _plain="$(sed $'s/\033\\[[0-9;]*m//g' "$_ob_file" 2>/dev/null || cat "$_ob_file")"
  fi
  _incomplete=0
  if [ -n "$_plain" ]; then
    _incomplete="$(printf '%s\n' "$_plain" | grep -Eic 'incomplete|partial' 2>/dev/null || true)"
  fi
  case "$_incomplete" in ''|*[!0-9]*) _incomplete=0 ;; esac
  if printf '%s\n' "$_plain" | grep -Eiq 'core failed|policy.*(missing|invalid)|could not create policy'; then
    printf '%s' "policy issue · run ryk doctor --fix"
    return 0
  fi
  if [ "$_incomplete" -gt 0 ] || printf '%s\n' "$_plain" | grep -Eiq 'protection partial|some hosts incomplete'; then
    printf '%s' "policy ready · some hosts incomplete · verify deferred"
    return 0
  fi
  if printf '%s\n' "$_plain" | grep -Eiq 'verification skipped|verify deferred|--skip-verify'; then
    printf '%s' "policy ready · hosts configured · verify deferred"
    return 0
  fi
  if printf '%s\n' "$_plain" | grep -Eiq 'core ready|policy.*(created|preserved|ready)|Integrations configured'; then
    printf '%s' "policy ready · hosts configured"
    return 0
  fi
  printf '%s' "policy ready · hosts configured · verify deferred"
}

ONBOARDING_RAN=0
ENSURE_MODE=doctor_fix
if [ "${RYK_INSTALL_SKIP_ONBOARD:-0}" != "1" ]; then
  step_active "Set up protection"
  set +e
  # Always capture ensure: install owns presentation (no second banner / TUI dump).
  (
    cd "$HOME"
    export RYK_RESOURCE_ROOT="$CURRENT_LINK"
    PATH="$INSTALL_DIR:$PATH"
    export PATH
    # Prefer plain ensure output if the CLI honors NO_COLOR / non-TTY.
    NO_COLOR=1
    export NO_COLOR
    run_install_ensure
  ) >"$TMP_DIR/.onboarding.out" 2>"$TMP_DIR/.onboarding.err"
  _ob_exit=$?
  set -e
  if [ "$_ob_exit" -ne 0 ]; then
    # Fail path only: short remediation + a few ensure lines (not full TUI).
    if [ -s "$TMP_DIR/.onboarding.err" ]; then
      grep -Eiv '^[+|──]|Status|Hosts|Try next|Re-run safely|Daemon|Protection|Verify[[:space:]]' \
        "$TMP_DIR/.onboarding.err" 2>/dev/null | head -6 | sed 's/^/    /' >&2 || true
    fi
    if [ -s "$TMP_DIR/.onboarding.out" ]; then
      grep -Eiq 'error|failed|unknown option|refusing' "$TMP_DIR/.onboarding.out" 2>/dev/null &&
        grep -Ei 'error|failed|unknown option|refusing' "$TMP_DIR/.onboarding.out" 2>/dev/null |
        head -4 | sed 's/^/    /' >&2 || true
    fi
    # Re-teach install trust scope: HOME cwd + --from-install.
    fail "ryk protection setup failed (exit ${_ob_exit})" \
      "The CLI was installed, but protection setup did not finish.
Re-run from your home directory: ryk doctor --fix --from-install
(cd \"\$HOME\" first; keep RYK_RESOURCE_ROOT on the installed share current link if you set them.)
Re-run the installer after resolving the host integration error."
  fi
  # Merge stderr into summary scan (some CLIs put status on stderr).
  if [ -s "$TMP_DIR/.onboarding.err" ]; then
    cat "$TMP_DIR/.onboarding.err" >>"$TMP_DIR/.onboarding.out" 2>/dev/null || true
  fi
  _ensure_detail="$(summarize_ensure_receipt "$TMP_DIR/.onboarding.out")"
  step_done "Set up protection" "$_ensure_detail"
  ONBOARDING_RAN=1
fi

MISSING_DASHBOARD=0
if [ ! -d "$RESOURCE_ROOT/ryk-dashboard-ui" ]; then
  MISSING_DASHBOARD=1
fi

print_success "$PREVIOUS_VERSION" "$(shell_quote "$DESTINATION")" "$MISSING_DASHBOARD" "$ONBOARDING_RAN"
