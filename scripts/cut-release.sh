#!/usr/bin/env bash
# Mac-local release cutter for ryk (Rykan V).
#
# Orchestrates: preflight → version → notes → gate → bump → build → verify
#               → publish-git → done
#
# Default is dry-run (no push or tag). Pass --live after human confirm
# (Shortcuts.app or terminal). Resume with --resume-from PHASE after a partial cut.
#
# Usage:
#   ./scripts/cut-release.sh --bump patch|minor|major [--live] [--plan-only]
#   ./scripts/cut-release.sh --version 1.3.0 [--live]
#   ./scripts/cut-release.sh --live --resume-from publish-git --version 1.2.9
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "$REPO_ROOT"

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
LIVE=0
PLAN_ONLY=0
SKIP_GATE=0
BUMP=""
VERSION_ARG=""
RESUME_FROM=""
DIST_DIR="${RYK_DIST_DIR:-dist}"
STATE_DIR="${RYK_CUT_RELEASE_STATE_DIR:-${REPO_ROOT}/.release-cut}"
STATE_FILE="${STATE_DIR}/state.env"
CLI_BINS_DIR="${RYK_CLI_ARTIFACT_DIR:-${REPO_ROOT}/.release-cli-bins}"
ALLOWED_BRANCHES="${RYK_RELEASE_BRANCHES:-main master}"
LOG_FILE=""

PHASES=(preflight version notes gate bump build verify sign publish-git "done")
COMPLETED_PHASES=()

# ---------------------------------------------------------------------------
# Logging / errors
# ---------------------------------------------------------------------------
log() { printf 'cut-release: %s\n' "$*"; }
warn() { printf 'cut-release: warning: %s\n' "$*" >&2; }
fail() {
  printf 'cut-release: error: %s\n' "$*" >&2
  print_recovery
  exit 1
}

print_recovery() {
  local last=""
  if [[ ${#COMPLETED_PHASES[@]} -gt 0 ]]; then
    last="${COMPLETED_PHASES[${#COMPLETED_PHASES[@]} - 1]}"
  fi
  printf '\n' >&2
  printf '=== cut-release recovery ===\n' >&2
  printf 'Last completed phase: %s\n' "${last:-none}" >&2
  if [[ -n "${VERSION:-}" ]]; then
    printf 'Version: %s\n' "$VERSION" >&2
    printf 'Tag/release left intact if already published (no automatic rollback).\n' >&2
    printf 'Resume remaining work:\n' >&2
    printf '  ./scripts/cut-release.sh --live --version %s --resume-from <PHASE>\n' "$VERSION" >&2
    printf 'Phases: %s\n' "${PHASES[*]}" >&2
  fi
  if [[ -n "${LOG_FILE:-}" && -f "$LOG_FILE" ]]; then
    printf 'Log: %s\n' "$LOG_FILE" >&2
  fi
  if [[ -f "$STATE_FILE" ]]; then
    printf 'State: %s\n' "$STATE_FILE" >&2
  fi
  printf '============================\n' >&2
}

usage() {
  cat <<'EOF'
Usage:
  ./scripts/cut-release.sh --bump patch|minor|major [options]
  ./scripts/cut-release.sh --version X.Y.Z [options]

Options:
  --live              Perform irreversible publish steps (push, tag, GitHub release)
  --plan-only         Stop after version + notes; print plan (no gate/build)
  --resume-from PHASE Skip phases before PHASE (requires --version matching state)
  --skip-gate         Skip verify-pre-merge.sh (not recommended)
  -h, --help          Show this help

Default without --live is dry-run: runs through verify, never publishes.
EOF
}

# ---------------------------------------------------------------------------
# Args
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --bump)
      BUMP="${2:-}"
      shift 2
      ;;
    --version)
      VERSION_ARG="${2:-}"
      shift 2
      ;;
    --live)
      LIVE=1
      shift
      ;;
    --plan-only)
      PLAN_ONLY=1
      shift
      ;;
    --resume-from)
      RESUME_FROM="${2:-}"
      shift 2
      ;;
    --skip-gate)
      SKIP_GATE=1
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      fail "unknown argument: $1"
      ;;
  esac
done

if [[ -z "$BUMP" && -z "$VERSION_ARG" && -z "$RESUME_FROM" ]]; then
  usage >&2
  fail "pass --bump patch|minor|major or --version X.Y.Z"
fi
if [[ -n "$BUMP" && -n "$VERSION_ARG" ]]; then
  fail "use either --bump or --version, not both"
fi
if [[ -n "$BUMP" && "$BUMP" != "patch" && "$BUMP" != "minor" && "$BUMP" != "major" ]]; then
  fail "--bump must be patch, minor, or major"
fi
if [[ "$LIVE" -eq 1 && "$PLAN_ONLY" -eq 1 ]]; then
  fail "--live and --plan-only are mutually exclusive"
fi

# ---------------------------------------------------------------------------
# Phase control
# ---------------------------------------------------------------------------
phase_index() {
  local name="$1" i
  for i in "${!PHASES[@]}"; do
    if [[ "${PHASES[$i]}" == "$name" ]]; then
      printf '%s' "$i"
      return 0
    fi
  done
  return 1
}

should_run_phase() {
  local name="$1"
  local idx resume_idx
  idx="$(phase_index "$name")" || fail "unknown phase: $name"
  if [[ -z "$RESUME_FROM" ]]; then
    return 0
  fi
  resume_idx="$(phase_index "$RESUME_FROM")" || fail "unknown --resume-from phase: $RESUME_FROM"
  [[ "$idx" -ge "$resume_idx" ]]
}

mark_phase() {
  local name="$1"
  COMPLETED_PHASES+=("$name")
  save_state
  log "phase complete: $name"
}

save_state() {
  mkdir -p "$STATE_DIR"
  {
    printf 'VERSION=%s\n' "${VERSION:-}"
    printf 'PREV_VERSION=%s\n' "${PREV_VERSION:-}"
    printf 'LIVE=%s\n' "$LIVE"
    printf 'COMPLETED=%q\n' "${COMPLETED_PHASES[*]}"
    printf 'NOTES_FILE=%s\n' "${NOTES_FILE:-}"
    printf 'LOG_FILE=%s\n' "${LOG_FILE:-}"
    printf 'BUMP=%s\n' "${BUMP:-}"
  } >"$STATE_FILE"
}

load_state_if_resume() {
  if [[ -z "$RESUME_FROM" ]]; then
    return 0
  fi
  if [[ ! -f "$STATE_FILE" ]]; then
    warn "no state file at $STATE_FILE; resume relies on --version and existing artifacts"
    return 0
  fi
  # shellcheck disable=SC1090
  source "$STATE_FILE"
  if [[ -n "$VERSION_ARG" && -n "${VERSION:-}" && "$VERSION_ARG" != "$VERSION" ]]; then
    fail "--version $VERSION_ARG does not match state VERSION=$VERSION"
  fi
  if [[ -n "${VERSION:-}" && -z "$VERSION_ARG" ]]; then
    VERSION_ARG="$VERSION"
  fi
  if [[ -n "${COMPLETED:-}" ]]; then
    # shellcheck disable=SC2206
    COMPLETED_PHASES=($COMPLETED)
  fi
}

# ---------------------------------------------------------------------------
# Semver helpers
# ---------------------------------------------------------------------------
read_version_file() {
  tr -d '[:space:]' <"${REPO_ROOT}/VERSION"
}

bump_semver() {
  local cur="$1" kind="$2"
  local major minor patch
  if [[ ! "$cur" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
    fail "VERSION is not X.Y.Z: $cur"
  fi
  major="${BASH_REMATCH[1]}"
  minor="${BASH_REMATCH[2]}"
  patch="${BASH_REMATCH[3]}"
  case "$kind" in
    major) major=$((major + 1)); minor=0; patch=0 ;;
    minor) minor=$((minor + 1)); patch=0 ;;
    patch) patch=$((patch + 1)) ;;
    *) fail "invalid bump kind: $kind" ;;
  esac
  printf '%s.%s.%s' "$major" "$minor" "$patch"
}

validate_semver() {
  local v="$1"
  [[ "$v" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "invalid semver: $v"
}

# ---------------------------------------------------------------------------
# preflight
# ---------------------------------------------------------------------------
phase_preflight() {
  log "preflight…"
  command -v git >/dev/null || fail "git is required"
  command -v gh >/dev/null || fail "gh (GitHub CLI) is required"
  command -v node >/dev/null || fail "node is required for release metadata"

  if [[ "$PLAN_ONLY" -ne 1 && -f ryk-dashboard-ui/package.json && ! -f ryk-dashboard-ui/dist/index.html ]]; then
    command -v npm >/dev/null || fail "npm is required only when the dashboard must be built"
  fi

  if [[ "$PLAN_ONLY" -ne 1 && "${RYK_TELEMETRY_BUILD_DISABLED:-0}" != "1" && -z "${RYK_POSTHOG_PROJECT_TOKEN:-}" ]]; then
    fail "RYK_POSTHOG_PROJECT_TOKEN is required for release telemetry (or set RYK_TELEMETRY_BUILD_DISABLED=1 for a local dry-run)"
  fi
  if [[ "$LIVE" -eq 1 && "${RYK_TELEMETRY_BUILD_DISABLED:-0}" == "1" ]]; then
    fail "live releases cannot disable telemetry transport"
  fi

  if [[ "$PLAN_ONLY" -ne 1 ]]; then
    command -v docker >/dev/null || fail "docker is required for Linux artifacts"
    docker info >/dev/null 2>&1 || fail "Docker daemon unavailable (start Docker Desktop)"
  fi

  if ! gh auth status >/dev/null 2>&1; then
    if [[ "$PLAN_ONLY" -eq 1 ]]; then
      warn "gh is not authenticated (notes may fall back to git log)"
    else
      fail "gh is not authenticated (gh auth login)"
    fi
  fi

  if [[ ! -x "${REPO_ROOT}/scripts/zig" ]]; then
    fail "scripts/zig missing; run ./scripts/ensure-zig-toolchain.sh --install"
  fi
  local zig_ver wanted
  zig_ver="$("${REPO_ROOT}/scripts/zig" version 2>/dev/null || true)"
  wanted="$(tr -d '[:space:]' <"${REPO_ROOT}/.zigversion" 2>/dev/null || true)"
  if [[ -n "$wanted" && "$zig_ver" != "$wanted" ]]; then
    fail "Zig version is '${zig_ver}', expected '${wanted}' (see .zigversion)"
  fi

  # Git cleanliness / branch / sync (skip dirty checks only when resuming past bump)
  local branch
  branch="$(git rev-parse --abbrev-ref HEAD)"
  local allowed=0 b
  for b in $ALLOWED_BRANCHES; do
    if [[ "$branch" == "$b" ]]; then
      allowed=1
      break
    fi
  done
  if [[ "$allowed" -ne 1 ]]; then
    fail "branch must be one of [${ALLOWED_BRANCHES}], got: $branch"
  fi

  if [[ -n "$(git status --porcelain)" ]]; then
    # Allow dirty only if resuming after bump and dirt is expected release artifacts
    if [[ -n "$RESUME_FROM" ]]; then
      local ridx
      ridx="$(phase_index "$RESUME_FROM")"
      if [[ "$ridx" -lt "$(phase_index bump)" ]]; then
        fail "working tree is dirty; commit or stash before cut-release"
      else
        warn "working tree dirty during resume from $RESUME_FROM (continuing)"
      fi
    else
      fail "working tree is dirty; commit or stash before cut-release"
    fi
  fi

  git fetch origin "$branch" >/dev/null 2>&1 || fail "git fetch origin $branch failed"
  local local_sha remote_sha
  local_sha="$(git rev-parse HEAD)"
  remote_sha="$(git rev-parse "origin/${branch}" 2>/dev/null || true)"
  if [[ -z "$remote_sha" ]]; then
    fail "origin/${branch} not found after fetch"
  fi
  if [[ "$local_sha" != "$remote_sha" ]]; then
    fail "HEAD is not equal to origin/${branch} (push or pull first)
  local:  $local_sha
  remote: $remote_sha"
  fi

  log "preflight OK (branch=$branch, zig=$zig_ver, distribution=curl/GitHub release)"
}

# ---------------------------------------------------------------------------
# version
# ---------------------------------------------------------------------------
phase_version() {
  log "version…"
  PREV_VERSION="$(read_version_file)"
  validate_semver "$PREV_VERSION"

  if [[ -n "$VERSION_ARG" ]]; then
    VERSION="$VERSION_ARG"
  else
    VERSION="$(bump_semver "$PREV_VERSION" "$BUMP")"
  fi
  validate_semver "$VERSION"

  if [[ "$VERSION" == "$PREV_VERSION" && -z "$RESUME_FROM" ]]; then
    fail "new version equals current VERSION ($VERSION); nothing to bump"
  fi

  if git rev-parse "v${VERSION}" >/dev/null 2>&1; then
    if [[ -z "$RESUME_FROM" ]]; then
      fail "git tag v${VERSION} already exists"
    fi
  fi

  if gh release view "v${VERSION}" >/dev/null 2>&1; then
    if [[ -z "$RESUME_FROM" ]]; then
      fail "GitHub release v${VERSION} already exists"
    else
      warn "GitHub release v${VERSION} already exists (resume mode)"
    fi
  fi

  mkdir -p "$STATE_DIR" "$DIST_DIR"
  LOG_FILE="${DIST_DIR}/cut-release-v${VERSION}.log"
  # Tee remaining stdout/stderr if not already
  if [[ -z "${CUT_RELEASE_LOGGING:-}" ]]; then
    export CUT_RELEASE_LOGGING=1
    exec > >(tee -a "$LOG_FILE") 2>&1
  fi

  log "will release ${PREV_VERSION} → ${VERSION} (live=${LIVE}, plan_only=${PLAN_ONLY})"
}

# ---------------------------------------------------------------------------
# notes
# ---------------------------------------------------------------------------
phase_notes() {
  log "notes…"
  NOTES_FILE="${DIST_DIR}/release-notes-v${VERSION}.md"
  mkdir -p "$DIST_DIR"

  local prev_tag="" repo
  prev_tag="$(git describe --tags --abbrev=0 2>/dev/null || true)"
  repo="$(gh repo view --json nameWithOwner -q .nameWithOwner 2>/dev/null || printf 'christopherkarani/ryk')"

  local body=""
  if command -v gh >/dev/null; then
    body="$(
      gh api "repos/${repo}/releases/generate-notes" \
        -f tag_name="v${VERSION}" \
        -f target_commitish="$(git rev-parse HEAD)" \
        ${prev_tag:+-f previous_tag_name="${prev_tag}"} \
        --jq .body 2>/dev/null || true
    )"
  fi

  if [[ -z "$body" ]]; then
    local range="HEAD"
    if [[ -n "$prev_tag" ]]; then
      range="${prev_tag}..HEAD"
    fi
    body="$(git log --pretty=format:'- %s (%h)' "$range" 2>/dev/null || printf '- (no commits found)\n')"
  fi

  {
    printf '## [%s] - %s\n\n' "$VERSION" "$(date -u +%Y-%m-%d)"
    printf '%s\n' "$body"
  } >"$NOTES_FILE"

  log "wrote notes: $NOTES_FILE"
  if [[ "$PLAN_ONLY" -eq 1 ]]; then
    printf '\n=== RELEASE PLAN (dry / plan-only) ===\n'
    printf 'Version:   %s → %s\n' "$PREV_VERSION" "$VERSION"
    printf 'Branch:    %s\n' "$(git rev-parse --abbrev-ref HEAD)"
    printf 'Live:      no (plan-only)\n'
    printf 'Channel:   GitHub Release assets for the curl installer\n'
    printf 'Gate:      ./scripts/verify-pre-merge.sh\n'
    printf 'Linux:     Docker (build-linux-release-docker.sh)\n'
    printf 'Notes:     %s\n' "$NOTES_FILE"
    printf 'Command:   ./scripts/cut-release.sh --version %s --live\n' "$VERSION"
    printf '=====================================\n\n'
  fi
}

# ---------------------------------------------------------------------------
# gate
# ---------------------------------------------------------------------------
phase_gate() {
  if [[ "$SKIP_GATE" -eq 1 ]]; then
    warn "skipping verify-pre-merge (--skip-gate)"
    return 0
  fi
  log "gate: verify-pre-merge.sh (this can take a long time)…"
  ./scripts/verify-pre-merge.sh
}

# ---------------------------------------------------------------------------
# bump
# ---------------------------------------------------------------------------
set_package_json_version() {
  local file="$1"
  local ver="$2"
  [[ -f "$file" ]] || return 0
  node -e '
const fs = require("fs");
const p = process.argv[1];
const v = process.argv[2];
const j = JSON.parse(fs.readFileSync(p, "utf8"));
j.version = v;
if (j.dependencies) {
  for (const k of Object.keys(j.dependencies)) {
    if (k === "@rykan/ryk") j.dependencies[k] = v;
  }
}
if (j.ryk && j.ryk.artifactBaseUrl) {
  j.ryk.artifactBaseUrl = j.ryk.artifactBaseUrl.replace(/\/v[0-9][^/]*$/, "/v" + v);
}
fs.writeFileSync(p, JSON.stringify(j, null, 2) + "\n");
' "$file" "$ver"
}

phase_bump() {
  log "bump → ${VERSION}…"

  printf '%s\n' "$VERSION" >"${REPO_ROOT}/VERSION"

  # Keep install.sh piped fallback current when discovery is unavailable.
  if [[ -f scripts/install.sh ]] && grep -q '^INSTALL_FALLBACK_VERSION=' scripts/install.sh; then
    PREVIOUS_RELEASE_VERSION="$PREV_VERSION" NEXT_RELEASE_VERSION="$VERSION" node <<'NODE'
const fs = require('fs');
const previous = process.env.PREVIOUS_RELEASE_VERSION;
const next = process.env.NEXT_RELEASE_VERSION;
const path = 'scripts/install.sh';
let source = fs.readFileSync(path, 'utf8');
const re = /^INSTALL_FALLBACK_VERSION="[0-9]+\.[0-9]+\.[0-9]+"/m;
if (!re.test(source)) {
  throw new Error(`${path} missing INSTALL_FALLBACK_VERSION="X.Y.Z" line`);
}
source = source.replace(re, `INSTALL_FALLBACK_VERSION="${next}"`);
// Also rewrite stale documented fallback mentions of the previous version.
if (previous) {
  source = source.replaceAll(`fallback ${previous}`, `fallback ${next}`);
}
fs.writeFileSync(path, source);
NODE
  fi

  set_package_json_version integrations/openclaw-plugin/package.json "$VERSION"
  set_package_json_version integrations/opencode-plugin/package.json "$VERSION"
  set_package_json_version ryk-pi/package.json "$VERSION"

  # Keep every release-facing manifest on the same hard-cut version. These
  # files are consumed directly by the runtime and integrations and are not
  # regenerated by build-release.sh's dist-only manifest renderer.
  PREVIOUS_RELEASE_VERSION="$PREV_VERSION" NEXT_RELEASE_VERSION="$VERSION" node <<'NODE'
const fs = require('fs');
const previous = process.env.PREVIOUS_RELEASE_VERSION;
const next = process.env.NEXT_RELEASE_VERSION;
const files = [
  'build.zig.zon',
  'integrations/hermes-plugin/plugin.yaml',
  'integrations/codex-plugin/.codex-plugin/plugin.json',
  'integrations/claude-code-plugin/.claude-plugin/plugin.json',
  'integrations/openclaw-plugin/openclaw.plugin.json',
  'packaging/scoop/ryk.json',
  'packaging/winget/ryk.yaml',
  'packaging/homebrew/Formula/ryk.rb',
  'packaging/npm/package.json',
];
for (const file of files) {
  const source = fs.readFileSync(file, 'utf8');
  if (!source.includes(previous)) {
    throw new Error(`${file} does not contain the current VERSION ${previous}`);
  }
  fs.writeFileSync(file, source.replaceAll(previous, next));
}
NODE

  # Prepend notes section into CHANGELOG.md (avoid duplicating if already present).
  if [[ -f CHANGELOG.md && -f "$NOTES_FILE" ]]; then
    if grep -qE "^## \\[${VERSION}\\]" CHANGELOG.md; then
      warn "CHANGELOG.md already has section for ${VERSION}; leaving as-is"
    else
      local tmp header rest notes_body
      tmp="$(mktemp)"
      notes_body="$(cat "$NOTES_FILE")"
      if head -1 CHANGELOG.md | grep -qi changelog; then
        header="$(head -1 CHANGELOG.md)"
        rest="$(tail -n +2 CHANGELOG.md)"
        {
          printf '%s\n\n' "$header"
          printf '%s\n\n' "$notes_body"
          # Drop a leading blank from rest
          printf '%s\n' "$rest" | sed '1{/^$/d;}'
        } >"$tmp"
      else
        {
          printf '%s\n\n' "$notes_body"
          cat CHANGELOG.md
        } >"$tmp"
      fi
      mv "$tmp" CHANGELOG.md
    fi
  fi

  git add VERSION CHANGELOG.md \
    scripts/install.sh \
    integrations/openclaw-plugin/package.json \
    integrations/opencode-plugin/package.json \
    ryk-pi/package.json
  git add build.zig.zon integrations/hermes-plugin/plugin.yaml \
    integrations/codex-plugin/.codex-plugin/plugin.json \
    integrations/claude-code-plugin/.claude-plugin/plugin.json \
    integrations/openclaw-plugin/openclaw.plugin.json \
    packaging/scoop/ryk.json packaging/winget/ryk.yaml \
    packaging/homebrew/Formula/ryk.rb packaging/npm/package.json

  if git diff --cached --quiet; then
    warn "nothing to commit for version bump (already at ${VERSION}?)"
  else
    git commit -m "chore(release): v${VERSION}"
    log "committed chore(release): v${VERSION}"
  fi
}

# ---------------------------------------------------------------------------
# build
# ---------------------------------------------------------------------------
phase_build() {
  log "build…"
  if [[ "$LIVE" -eq 1 && "${RYK_TELEMETRY_BUILD_DISABLED:-0}" == "1" ]]; then
    fail "live releases cannot disable telemetry transport"
  fi
  if [[ "${RYK_TELEMETRY_BUILD_DISABLED:-0}" != "1" && -z "${RYK_POSTHOG_PROJECT_TOKEN:-}" ]]; then
    fail "RYK_POSTHOG_PROJECT_TOKEN is required for release telemetry (or set RYK_TELEMETRY_BUILD_DISABLED=1 for a local dry-run)"
  fi
  export RYK_VERSION="$VERSION"
  export RYK_COMMIT RYK_BUILD_DATE
  RYK_COMMIT="$(git rev-parse --short=12 HEAD)"
  RYK_BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  # Dashboard assets required by build-release payload.
  if [[ -f ryk-dashboard-ui/package.json ]]; then
    log "building dashboard UI…"
    (cd ryk-dashboard-ui && npm ci && npm run build)
    [[ -f ryk-dashboard-ui/dist/index.html ]] || fail "dashboard build missing dist/index.html"
  fi

  # Linux binaries via Docker — stage outside dist/ (build-release wipes dist/).
  log "building Linux bins via Docker → ${CLI_BINS_DIR}…"
  rm -rf "$CLI_BINS_DIR"
  mkdir -p "$CLI_BINS_DIR"
  RYK_VERSION="$VERSION" \
    RYK_COMMIT="$RYK_COMMIT" \
    RYK_BUILD_DATE="$RYK_BUILD_DATE" \
    RYK_POSTHOG_PROJECT_TOKEN="${RYK_POSTHOG_PROJECT_TOKEN:-}" \
    RYK_TELEMETRY_BUILD_DISABLED="${RYK_TELEMETRY_BUILD_DISABLED:-0}" \
    RYK_RELEASE_LIVE="$LIVE" \
    ./scripts/build-linux-release-docker.sh "$CLI_BINS_DIR"

  # Prefer primary ryk staged name for CLI_ARTIFACT_DIR contract.
  for arch in amd64 arm64; do
    if [[ -x "${CLI_BINS_DIR}/linux-${arch}/ryk" ]]; then
      :
    else
      fail "missing Linux staged binary for linux-${arch} under ${CLI_BINS_DIR}"
    fi
  done

  log "building full release archives…"
  RYK_VERSION="$VERSION" \
    RYK_COMMIT="$RYK_COMMIT" \
    RYK_BUILD_DATE="$RYK_BUILD_DATE" \
    RYK_POSTHOG_PROJECT_TOKEN="${RYK_POSTHOG_PROJECT_TOKEN:-}" \
    RYK_TELEMETRY_BUILD_DISABLED="${RYK_TELEMETRY_BUILD_DISABLED:-0}" \
    RYK_RELEASE_LIVE="$LIVE" \
    RYK_RELEASE_PRODUCT=curl \
    RYK_CLI_ARTIFACT_DIR="$CLI_BINS_DIR" \
    RYK_DIST_DIR="$DIST_DIR" \
    ./scripts/build-release.sh
}

# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------
phase_verify() {
  log "verify…"
  RYK_RELEASE_LIVE="$LIVE" RYK_RELEASE_PRODUCT=curl ./scripts/verify-release.sh "$DIST_DIR"
  for f in \
    "${DIST_DIR}/checksums.txt" \
    "${DIST_DIR}/telemetry-contract.txt" \
    "${DIST_DIR}/sbom.json" \
    "${DIST_DIR}/release-manifest.json" \
    "${DIST_DIR}/ryk-v${VERSION}-darwin-arm64.tar.gz" \
    "${DIST_DIR}/ryk-v${VERSION}-darwin-amd64.tar.gz" \
    "${DIST_DIR}/ryk-v${VERSION}-linux-arm64.tar.gz" \
    "${DIST_DIR}/ryk-v${VERSION}-linux-amd64.tar.gz" \
    "${DIST_DIR}/ryk-v${VERSION}-windows-amd64.zip"
  do
    [[ -f "$f" ]] || fail "missing required artifact: $f"
  done

  if [[ "$LIVE" -eq 0 ]]; then
    printf '\n=== DRY-RUN COMPLETE ===\n'
    printf 'Version %s built and verified under %s/\n' "$VERSION" "$DIST_DIR"
    printf 'No push or tag was performed.\n'
    printf 'To publish:\n'
    printf '  ./scripts/cut-release.sh --version %s --live --resume-from publish-git\n' "$VERSION"
    printf '  (or re-run full --live after resetting if you need a clean bump path)\n'
    printf '========================\n\n'
  fi
}

# ---------------------------------------------------------------------------
# sign
#
# One detached signature over checksums.txt authenticates every artifact, since
# checksums.txt already covers their contents. Signing before publish means an
# unsigned release never reaches users: a live cut with no key fails here, having
# pushed nothing.
# ---------------------------------------------------------------------------
phase_sign() {
  local checksums="${DIST_DIR}/checksums.txt"
  local sig="${checksums}.minisig"
  local key="${RYK_MINISIGN_SECRET_KEY:-}"

  [[ -s "$checksums" ]] || fail "sign: ${checksums} missing; run the build phase first"

  local signer=""
  if command -v minisign >/dev/null 2>&1; then
    signer=minisign
  elif command -v rsign >/dev/null 2>&1; then
    signer=rsign
  fi

  if [[ -z "$key" || -z "$signer" ]]; then
    local why="RYK_MINISIGN_SECRET_KEY is not set"
    [[ -n "$key" ]] && why="no signer found (install minisign, or cargo install rsign2)"
    if [[ "$LIVE" -eq 1 ]]; then
      fail "sign: ${why}
Refuse to publish an unsigned release. Nothing has been pushed.
  Provision the key: docs/release-signing.md
  Then resume:       ./scripts/cut-release.sh --version ${VERSION} --live --resume-from sign"
    fi
    warn "sign: skipped in dry-run (${why}); a live cut would stop here"
    return 0
  fi

  log "sign: minisign over checksums.txt…"
  rm -f "$sig"
  case "$signer" in
    minisign)
      minisign -S -s "$key" -m "$checksums" -x "$sig" \
        -c "ryk v${VERSION} release checksums" \
        -t "ryk v${VERSION}" || fail "sign: minisign failed"
      ;;
    rsign)
      rsign sign -s "$key" -x "$sig" -c "ryk v${VERSION} release checksums" \
        -t "ryk v${VERSION}" "$checksums" || fail "sign: rsign failed"
      ;;
  esac
  [[ -s "$sig" ]] || fail "sign: ${sig} was not produced"

  # Verify what we just produced with the published public key, not the secret
  # key's own copy: this is the assertion that users will be able to verify it.
  local pub="keys/ryk-release-minisign.pub"
  if [[ -f "$pub" ]] && ! grep -q 'UNPROVISIONED' "$pub"; then
    local pubkey
    pubkey="$(grep -v '^untrusted comment:' "$pub" | head -n1)"
    case "$signer" in
      minisign) minisign -V -P "$pubkey" -x "$sig" -m "$checksums" >/dev/null 2>&1 ;;
      rsign) rsign verify -P "$pubkey" -x "$sig" "$checksums" >/dev/null 2>&1 ;;
    esac || fail "sign: signature does not verify against ${pub}
The signing key and the published public key disagree; users would be unable to
verify this release. Nothing has been pushed."
    log "sign: verified against ${pub}"
  else
    warn "sign: ${pub} is not provisioned, so the signature was not cross-checked"
  fi
}

# ---------------------------------------------------------------------------
# publish-git
# ---------------------------------------------------------------------------
phase_publish_git() {
  [[ "$LIVE" -eq 1 ]] || fail "internal: publish-git requires --live"

  local branch sha
  branch="$(git rev-parse --abbrev-ref HEAD)"
  sha="$(git rev-parse HEAD)"
  log "publish-git: push ${branch}, GitHub Release v${VERSION} (assets before CI tag race)…"

  git push origin "$branch"

  # Collect assets; require checksums.txt so installers never 404.
  [[ -s "${DIST_DIR}/checksums.txt" ]] || fail "dist/checksums.txt missing; refuse to publish"

  local -a assets=()
  local f
  shopt -s nullglob
  for f in \
    "${DIST_DIR}/ryk-v${VERSION}-"*.tar.gz \
    "${DIST_DIR}/ryk-v${VERSION}-"*.zip \
    "${DIST_DIR}/checksums.txt" \
    "${DIST_DIR}/checksums.txt.minisig" \
    "${DIST_DIR}/telemetry-contract.txt" \
    "${DIST_DIR}/sbom.json" \
    "${DIST_DIR}/release-manifest.json"
  do
    [[ -f "$f" ]] && assets+=("$f")
  done
  shopt -u nullglob

  # The installer refuses a release whose signature is missing once the public key
  # is provisioned, so publishing without it would break the install path.
  if [[ -f keys/ryk-release-minisign.pub ]] && ! grep -q 'UNPROVISIONED' keys/ryk-release-minisign.pub; then
    [[ -s "${DIST_DIR}/checksums.txt.minisig" ]] || \
      fail "publish-git: checksums.txt.minisig missing while signing is active; run the sign phase"
  fi
  [[ ${#assets[@]} -gt 0 ]] || fail "no release assets found under ${DIST_DIR}"

  local -a notes_arg=(--generate-notes)
  if [[ -f "${NOTES_FILE:-}" ]]; then
    notes_arg=(--notes-file "$NOTES_FILE")
  fi

  # Create release + tag on GitHub with assets in one shot so CI's tag-push
  # job sees checksums.txt and no-ops (see release.yml skip guard).
  if gh release view "v${VERSION}" >/dev/null 2>&1; then
    warn "release v${VERSION} exists; uploading assets with --clobber"
    gh release upload "v${VERSION}" --clobber "${assets[@]}"
  else
    gh release create "v${VERSION}" \
      --title "ryk v${VERSION}" \
      --target "$sha" \
      "${notes_arg[@]}" \
      "${assets[@]}"
  fi

  # Sync local tag to match remote (created by gh if new).
  git fetch origin "refs/tags/v${VERSION}:refs/tags/v${VERSION}" 2>/dev/null || true
  if ! git rev-parse "v${VERSION}" >/dev/null 2>&1; then
    git tag -a "v${VERSION}" -m "v${VERSION}" "$sha"
  fi

  log "GitHub Release v${VERSION} assets uploaded"
}

# ---------------------------------------------------------------------------
# done
# ---------------------------------------------------------------------------
phase_done() {
  local repo url
  repo="$(gh repo view --json nameWithOwner -q .nameWithOwner 2>/dev/null || printf 'christopherkarani/ryk')"
  url="https://github.com/${repo}/releases/tag/v${VERSION}"

  printf '\n=== cut-release complete ===\n'
  printf 'Version:  v%s\n' "$VERSION"
  printf 'Release:  %s\n' "$url"
  printf 'Install:  curl installer downloads the GitHub Release assets\n'
  printf 'Log:      %s\n' "${LOG_FILE:-n/a}"
  printf '============================\n'

  if command -v osascript >/dev/null 2>&1; then
    osascript -e "display notification \"ryk v${VERSION} released\" with title \"cut-release\"" 2>/dev/null || true
  fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
  load_state_if_resume

  run_phase() {
    local name="$1"
    if ! should_run_phase "$name"; then
      log "skip phase (resume): $name"
      return 0
    fi
    case "$name" in
      preflight) phase_preflight ;;
      version) phase_version ;;
      notes) phase_notes ;;
      gate)
        if [[ "$PLAN_ONLY" -eq 1 ]]; then
          log "plan-only: stopping before gate"
          mark_phase notes
          exit 0
        fi
        phase_gate
        ;;
      bump)
        if [[ "$LIVE" -ne 1 ]]; then
          log "dry-run: skipping version-file bump/commit (build uses VERSION env only)"
        else
          phase_bump
        fi
        ;;
      build) phase_build ;;
      verify) phase_verify ;;
      publish-git)
        if [[ "$LIVE" -ne 1 ]]; then
          log "dry-run: skipping publish-git and later phases"
          mark_phase verify
          exit 0
        fi
        phase_publish_git
        ;;
      done) phase_done ;;
      *) fail "unknown phase $name" ;;
    esac
    mark_phase "$name"
  }

  for ph in "${PHASES[@]}"; do
    run_phase "$ph"
  done
}

main "$@"
