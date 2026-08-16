#!/usr/bin/env bash
# Pick the narrowest useful verification gate for coding agents (Zig 0.16.0).
#
# Usage:
#   ./scripts/agent-gate.sh                 # auto from git dirty + staged paths
#   ./scripts/agent-gate.sh --dry-run       # print chosen command only
#   ./scripts/agent-gate.sh --paths a.zig src/shell_engine/mod.zig
#   ./scripts/agent-gate.sh compile|units|full|check|core|rust|shell-engine|dx|sandbox|policy|intercept|dashboard|plugin|scripts
#
# Explicit modes always run that gate. Auto mode uses path heuristics.
# Domain slices: prefer test-slice.sh for -Dtest-filter; agent-gate picks the slice.
# src/shell_engine/** → L0.5 ./scripts/zig build test-shell-engine
# See CONTRIBUTING.md for the repository verification gates.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

dry_run=0
mode=""
paths=()

usage() {
  cat >&2 <<'EOF'
usage: ./scripts/agent-gate.sh [--dry-run] [--paths FILE...] [MODE]

Modes:
  check         ./scripts/compile-fast.sh check
  compile       ./scripts/test-fast.sh compile
  units         ./scripts/test-fast.sh units
  full          ./scripts/test-fast.sh full
  core          ./scripts/zig build test-core test-core-contract
  sandbox       ./scripts/test-slice.sh sandbox
  policy        ./scripts/test-slice.sh policy
  intercept     ./scripts/test-slice.sh intercept
  shell-engine  ./scripts/zig build test-shell-engine (L0.5)
  rust          deprecated alias → shell-engine
  dx            quick-install-dx-verify (builds CLI if needed)
  dashboard     npm test in ryk-dashboard-ui/
  plugin        package-local tests for dirty integrations/*-plugin paths
  scripts       bash -n (+ light dry-run smoke) for dirty scripts/**
  auto          (default) choose from dirty paths / --paths
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) dry_run=1; shift ;;
    --paths)
      shift
      while [[ $# -gt 0 && "$1" != --* ]]; do
        paths+=("$1")
        shift
      done
      ;;
    -h|--help) usage; exit 0 ;;
    check|compile|units|full|core|sandbox|policy|intercept|shell-engine|dx|rust|dashboard|plugin|scripts|auto)
      mode="$1"
      shift
      ;;
    *)
      echo "error: unknown arg: $1" >&2
      usage
      exit 2
      ;;
  esac
done

mode="${mode:-auto}"

# Incremental compile; -j1 keeps test binary runs serial (parallel hangs on some hosts).
ZIG_BUILD_RUN=(./scripts/zig build -fincremental -j1 -Dincremental=true)

if [[ ${#paths[@]} -eq 0 && "${mode}" == "auto" ]]; then
  # Dirty + staged; fall back to empty (→ check).
  while IFS= read -r line; do
    [[ -n "${line}" ]] || continue
    paths+=("${line}")
  done < <(git status --porcelain 2>/dev/null | awk '{print $NF}' || true)
fi

# Collect unique plugin package roots touched by $paths (integrations/<name>-plugin).
plugin_dirs_from_paths() {
  local p dir
  local -a seen=()
  for p in "${paths[@]}"; do
    case "${p}" in
      integrations/*-plugin|integrations/*-plugin/*)
        dir="${p#integrations/}"
        dir="integrations/${dir%%/*}"
        local s
        local found=0
        for s in "${seen[@]+"${seen[@]}"}"; do
          if [[ "${s}" == "${dir}" ]]; then found=1; break; fi
        done
        if [[ "${found}" -eq 0 ]]; then
          seen+=("${dir}")
          printf '%s\n' "${dir}"
        fi
        ;;
    esac
  done
}

choose_auto() {
  local p
  local has_zig=0 has_core=0 has_policy=0 has_scripts=0 has_other=0
  local has_sandbox=0 has_intercept=0 has_policy_src=0 has_shell_engine=0
  local has_dashboard=0 has_plugin=0
  local only_md=1
  local only_sandbox=1 only_intercept=1 only_policy_src=1 only_shell_engine=1

  if [[ ${#paths[@]} -eq 0 ]]; then
    echo check
    return
  fi

  for p in "${paths[@]}"; do
    case "${p}" in
      *.md|docs/*|planning/*|.grok/*) ;;
      *) only_md=0 ;;
    esac
    # Legacy dashboard assets are covered by ryk-dashboard-ui contract tests,
    # not the Zig monopath — keep them out of has_zig so pure asset PRs route
    # to the dashboard gate (matches CI path filter).
    case "${p}" in
      src/dashboard/*) has_dashboard=1 ;;
      src/*|packages/*|build.zig|build.zig.zon|tests/*) has_zig=1 ;;
    esac
    case "${p}" in
      packages/core/*|src/core/*|src/core_engine.zig|src/policy/*|src/audit/*) has_core=1 ;;
    esac
    case "${p}" in
      src/sandbox/*|src/sandbox_slice_root.zig) has_sandbox=1 ;;
      *)
        case "${p}" in
          *.md|docs/*|planning/*|.grok/*) ;;
          *) only_sandbox=0 ;;
        esac
        ;;
    esac
    case "${p}" in
      src/intercept/*|src/intercept_slice_root.zig) has_intercept=1 ;;
      *)
        case "${p}" in
          *.md|docs/*|planning/*|.grok/*) ;;
          *) only_intercept=0 ;;
        esac
        ;;
    esac
    case "${p}" in
      src/shell_engine/*|src/shell_engine_slice_root.zig) has_shell_engine=1 ;;
      *)
        case "${p}" in
          *.md|docs/*|planning/*|.grok/*) ;;
          *) only_shell_engine=0 ;;
        esac
        ;;
    esac
    case "${p}" in
      src/policy/*) has_policy_src=1 ;;
      *)
        case "${p}" in
          *.md|docs/*|planning/*|.grok/*|packages/core/*|src/core/*|src/core_engine.zig|src/audit/*) ;;
          *) only_policy_src=0 ;;
        esac
        ;;
    esac
    case "${p}" in
      policies/*|schemas/policy*|src/policy/presets.zig) has_policy=1 ;;
    esac
    case "${p}" in
      scripts/*) has_scripts=1 ;;
    esac
    case "${p}" in
      ryk-dashboard-ui/*) has_dashboard=1 ;;
      integrations/*-plugin|integrations/*-plugin/*) has_plugin=1 ;;
      integrations/*) has_other=1 ;;
    esac
  done

  if [[ "${only_md}" -eq 1 && "${has_zig}" -eq 0 && "${has_dashboard}" -eq 0 && "${has_plugin}" -eq 0 && "${has_policy}" -eq 0 && "${has_scripts}" -eq 0 ]]; then
    echo check
    return
  fi

  # Append companion package gates to a primary selection. Mixed dirty trees
  # must never green after validating only one stack (Codex P2).
  append_package_gates() {
    local out="$1"
    if [[ "${has_dashboard}" -eq 1 ]]; then
      case " ${out} " in
        *" dashboard "*) ;;
        *) out+=" dashboard" ;;
      esac
    fi
    if [[ "${has_plugin}" -eq 1 ]]; then
      case " ${out} " in
        *" plugin "*) ;;
        *) out+=" plugin" ;;
      esac
    fi
    if [[ "${has_scripts}" -eq 1 ]]; then
      case " ${out} " in
        *" scripts "*) ;;
        *) out+=" scripts" ;;
      esac
    fi
    # shellcheck disable=SC2086
    # Trim leading space if primary was empty.
    out="${out# }"
    printf '%s\n' "${out}"
  }

  if [[ "${has_zig}" -eq 1 ]]; then
    local zig_gate=""
    # Prefer domain slices when dirty paths stay inside one domain.
    if [[ "${has_shell_engine}" -eq 1 && "${only_shell_engine}" -eq 1 ]]; then
      zig_gate=shell-engine
    elif [[ "${has_sandbox}" -eq 1 && "${only_sandbox}" -eq 1 ]]; then
      zig_gate=sandbox
    elif [[ "${has_intercept}" -eq 1 && "${only_intercept}" -eq 1 ]]; then
      zig_gate=intercept
    elif [[ "${has_policy_src}" -eq 1 && "${only_policy_src}" -eq 1 ]]; then
      zig_gate=policy
    elif [[ "${has_core}" -eq 1 ]]; then
      # Core-only surface → focused core tests (still cheap).
      local non_core=0
      for p in "${paths[@]}"; do
        case "${p}" in
          packages/core/*|src/core/*|src/core_engine.zig|src/policy/*|src/audit/*|*.md|docs/*|planning/*) ;;
          src/*|packages/*|build.zig|tests/*) non_core=1 ;;
        esac
      done
      if [[ "${non_core}" -eq 0 ]]; then
        zig_gate=core
      fi
    fi
    if [[ -z "${zig_gate}" ]]; then
      zig_gate=units
    fi
    append_package_gates "${zig_gate}"
    return
  fi

  # Non-Zig trees: compose every relevant package gate (no early single-stack
  # return that drops scripts/dashboard/plugin companions).
  local primary=""
  if [[ "${has_policy}" -eq 1 ]]; then
    primary="dx"
  fi
  local composed
  composed="$(append_package_gates "${primary}")"
  if [[ -n "${composed}" ]]; then
    echo "${composed}"
    return
  fi
  if [[ "${has_other}" -eq 1 ]]; then
    echo check
    return
  fi
  echo check
}

# Shell scripts under scripts/ that path heuristics should syntax-check.
script_sh_paths() {
  local p
  if [[ ${#paths[@]} -eq 0 ]]; then
    # Forced `scripts` mode with no path list: syntax-check this gate itself.
    printf '%s\n' "scripts/agent-gate.sh"
    return
  fi
  for p in "${paths[@]}"; do
    case "${p}" in
      scripts/*.sh|scripts/*/*.sh) printf '%s\n' "${p}" ;;
    esac
  done
}

run_scripts_gate() {
  local -a sh_files=()
  local f
  local saw_agent_gate=0

  while IFS= read -r f; do
    [[ -n "${f}" ]] || continue
    sh_files+=("${f}")
    if [[ "${f}" == "scripts/agent-gate.sh" ]]; then
      saw_agent_gate=1
    fi
  done < <(script_sh_paths)

  if [[ ${#sh_files[@]} -eq 0 ]]; then
    echo "[agent-gate] scripts gate: no scripts/**/*.sh paths to check"
    return 0
  fi

  for f in "${sh_files[@]}"; do
    if [[ ! -f "${f}" ]]; then
      echo "[agent-gate] scripts gate: skip missing ${f}"
      continue
    fi
    if [[ "${dry_run}" -eq 1 ]]; then
      echo "[agent-gate] dry-run: bash -n ${f}"
    else
      echo "[agent-gate] bash -n ${f}"
      bash -n "${f}"
    fi
  done

  # Light smoke when agent-gate itself changed: selection must compose mixed gates.
  if [[ "${saw_agent_gate}" -eq 1 ]]; then
    agent_gate_smoke_case() {
      # Usage: agent_gate_smoke_case LABEL EXPECT_TOKEN... -- PATH...
      local label="$1"
      shift
      local -a expect=()
      local -a smoke_paths=()
      local seen_sep=0
      local arg
      for arg in "$@"; do
        if [[ "${seen_sep}" -eq 0 && "${arg}" == "--" ]]; then
          seen_sep=1
          continue
        fi
        if [[ "${seen_sep}" -eq 0 ]]; then
          expect+=("${arg}")
        else
          smoke_paths+=("${arg}")
        fi
      done
      if [[ "${dry_run}" -eq 1 ]]; then
        echo "[agent-gate] dry-run: smoke ${label} --paths ${smoke_paths[*]}"
        return 0
      fi
      echo "[agent-gate] scripts smoke: ${label}"
      local out
      out="$(./scripts/agent-gate.sh --dry-run --paths "${smoke_paths[@]}")"
      printf '%s\n' "${out}"
      local token
      for token in "${expect[@]}"; do
        if ! printf '%s\n' "${out}" | grep -q "${token}"; then
          echo "error: agent-gate smoke (${label}) expected '${token}' in selection" >&2
          exit 3
        fi
      done
    }

    agent_gate_smoke_case "zig+dashboard+scripts" \
      selected=units dashboard scripts -- \
      src/cli/run.zig ryk-dashboard-ui/app/dashboard.ts scripts/test-fast.sh

    # L0.5: pure shell_engine tree → test-shell-engine (not monopath units).
    agent_gate_smoke_case "shell-engine-only" \
      selected=shell-engine -- \
      src/shell_engine/mod.zig src/shell_engine/normalize.zig

    # Mixed non-Zig trees must compose every gate (scripts companion).
    agent_gate_smoke_case "scripts+dashboard" \
      selected=dashboard scripts -- \
      ryk-dashboard-ui/app/foo.ts scripts/test-fast.sh

    agent_gate_smoke_case "policy+dashboard" \
      selected=dx dashboard -- \
      policies/default.yaml ryk-dashboard-ui/app/foo.ts
  fi
}

run_dashboard_gate() {
  if [[ "${dry_run}" -eq 1 ]]; then
    echo "[agent-gate] dry-run: (cd ryk-dashboard-ui && npm test)"
    return 0
  fi
  if [[ ! -d ryk-dashboard-ui ]]; then
    echo "error: ryk-dashboard-ui/ missing" >&2
    exit 3
  fi
  (cd ryk-dashboard-ui && npm test)
}

run_plugin_gate() {
  local -a dirs=()
  local d

  if [[ ${#paths[@]} -gt 0 ]]; then
    while IFS= read -r d; do
      [[ -n "${d}" ]] || continue
      dirs+=("${d}")
    done < <(plugin_dirs_from_paths)
  fi

  # Forced `plugin` mode with no paths: exercise packages that ship npm/python tests.
  if [[ ${#dirs[@]} -eq 0 ]]; then
    dirs=(
      integrations/openclaw-plugin
      integrations/opencode-plugin
      integrations/hermes-plugin
    )
  fi

  if [[ ${#dirs[@]} -eq 0 ]]; then
    echo "error: plugin gate selected but no integrations/*-plugin paths found" >&2
    exit 3
  fi

  for d in "${dirs[@]}"; do
    if [[ ! -d "${d}" ]]; then
      echo "[agent-gate] skip missing plugin dir: ${d}"
      continue
    fi
    if [[ -f "${d}/package.json" ]]; then
      if [[ "${dry_run}" -eq 1 ]]; then
        echo "[agent-gate] dry-run: (cd ${d} && npm test)"
      else
        echo "[agent-gate] plugin npm test: ${d}"
        (cd "${d}" && npm test)
      fi
    elif [[ -f "${d}/test_discovery.py" ]] || compgen -G "${d}/test_*.py" >/dev/null 2>&1; then
      if [[ "${dry_run}" -eq 1 ]]; then
        echo "[agent-gate] dry-run: (cd ${d} && python3 -m unittest discover -s . -p 'test_*.py' -v)"
      else
        echo "[agent-gate] plugin python tests: ${d}"
        (cd "${d}" && python3 -m unittest discover -s . -p 'test_*.py' -v)
      fi
    else
      echo "[agent-gate] no package-local test runner for ${d} (hooks/skills-only); skip"
    fi

    # OpenClaw ships committed dist/; unit tests import src/. When that package
    # is on the dirty path, also prove dist matches TypeScript (release assets).
    if [[ "${d}" == "integrations/openclaw-plugin" ]]; then
      if [[ "${dry_run}" -eq 1 ]]; then
        echo "[agent-gate] dry-run: ./scripts/test-openclaw-release-assets.sh"
      else
        echo "[agent-gate] openclaw release assets"
        ./scripts/test-openclaw-release-assets.sh
      fi
    fi
  done
}

run_gate() {
  local g="$1"

  echo "[agent-gate] selected=${g}"
  if [[ "${g}" == "dashboard" ]]; then
    run_dashboard_gate
    return
  fi
  if [[ "${g}" == "plugin" ]]; then
    run_plugin_gate
    return
  fi
  if [[ "${g}" == "scripts" ]]; then
    run_scripts_gate
    return
  fi

  if [[ "${dry_run}" -eq 1 ]]; then
    case "${g}" in
      check) echo "[agent-gate] dry-run: ./scripts/compile-fast.sh check" ;;
      compile) echo "[agent-gate] dry-run: ./scripts/test-fast.sh compile" ;;
      units) echo "[agent-gate] dry-run: ./scripts/test-fast.sh units" ;;
      full) echo "[agent-gate] dry-run: ./scripts/test-fast.sh full" ;;
      core) echo "[agent-gate] dry-run: ${ZIG_BUILD_RUN[*]} test-core test-core-contract" ;;
      sandbox) echo "[agent-gate] dry-run: ./scripts/test-slice.sh sandbox" ;;
      policy) echo "[agent-gate] dry-run: ./scripts/test-slice.sh policy" ;;
      intercept) echo "[agent-gate] dry-run: ./scripts/test-slice.sh intercept" ;;
      dx) echo "[agent-gate] dry-run: ./scripts/quick-install-dx-verify.sh" ;;
      rust) echo "[agent-gate] dry-run: ./scripts/zig build test-shell-engine (deprecated rust alias)" ;;
      shell-engine) echo "[agent-gate] dry-run: ./scripts/zig build test-shell-engine" ;;
      *)
        echo "error: internal unknown gate ${g}" >&2
        exit 3
        ;;
    esac
    return 0
  fi

  case "${g}" in
    check) ./scripts/compile-fast.sh check ;;
    compile) ./scripts/test-fast.sh compile ;;
    units) ./scripts/test-fast.sh units ;;
    full) ./scripts/test-fast.sh full ;;
    core)
      "${ZIG_BUILD_RUN[@]}" test-core test-core-contract
      ;;
    sandbox) ./scripts/test-slice.sh sandbox ;;
    policy) ./scripts/test-slice.sh policy ;;
    intercept) ./scripts/test-slice.sh intercept ;;
    dx)
      if [[ ! -x zig-out/bin/ryk ]]; then
        echo "[agent-gate] building CLI for DX matrix"
        ./scripts/zig build -fincremental -Dincremental=true
      fi
      ./scripts/quick-install-dx-verify.sh
      ;;
    rust|shell-engine) ./scripts/zig build test-shell-engine ;;
    *)
      echo "error: internal unknown gate ${g}" >&2
      exit 3
      ;;
  esac
}

if [[ "${mode}" == "auto" ]]; then
  selected="$(choose_auto)"
else
  selected="${mode}"
fi

# Auto may emit multiple gates (e.g. "units dashboard", "dashboard plugin") for mixed trees.
# shellcheck disable=SC2206
gates=( ${selected} )
for g in "${gates[@]}"; do
  run_gate "${g}"
done
