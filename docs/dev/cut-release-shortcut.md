# Cut release (Mac Shortcuts + `scripts/cut-release.sh`)

Primary way to ship ryk: **build on your Mac** and cut a GitHub Release for the curl installer.

GitHub Actions `release.yml` remains a **manual backup** (`workflow_dispatch`). On `v*` tag push it **no-ops** if the release already has the complete curl installer asset inventory (so the Mac cutter is not raced).

## Prerequisites

| Tool | Check |
|------|--------|
| Zig pin | `./scripts/zig version` matches `.zigversion` |
| Docker Desktop | `docker info` |
| GitHub CLI | `gh auth status` (repo write + release) |
| Clean `main` | equal to `origin/main`, no dirty files |

## CLI (source of truth)

```sh
# Plan only (no tests/build/publish)
./scripts/cut-release.sh --bump patch --plan-only

# Dry-run: preflight → … → verify → sign (no push or tag)
./scripts/cut-release.sh --bump patch

# Live cut after one human confirm (Shortcut or terminal)
./scripts/cut-release.sh --bump patch --live
./scripts/cut-release.sh --version 1.3.0 --live

# Resume after a dry-run or a mid-flight failure (no automatic rollback).
# Next step is sign, never publish-git — that would skip signing.
./scripts/cut-release.sh --live --version 1.2.9 --resume-from sign
```

### Release stages

`preflight` → `version` → `notes` → `gate` → `bump` → `build` → `verify` → `sign` → `publish-git` → `done`

| Stage | What it does |
|-------|----------------|
| `gate` | `./scripts/verify-pre-merge.sh` |
| `build` | Dashboard UI, Linux via Docker, and curl installer archives |
| `sign` | Detached minisign over `checksums.txt`; a live cut with no key stops here. See [release signing](../release-signing.md) |
| `publish-git` | Push branch; `gh release create` **with assets** (tag + checksums + `checksums.txt.minisig`) |

Logs: `dist/cut-release-vX.Y.Z.log`  
State: `.release-cut/state.env` (gitignored)

### Environment overrides

| Variable | Default / meaning |
|----------|-------------------|
| `RYK_RELEASE_BRANCHES` | `main master` |
| `RYK_DIST_DIR` | `dist` |
| `RYK_CLI_ARTIFACT_DIR` | `.release-cli-bins` (outside `dist/` — build-release wipes `dist/`) |
| `RYK_MINISIGN_SECRET_KEY` | Path to the offline minisign secret; required for a live cut. Never commit this file |
| `RYK_POSTHOG_PROJECT_TOKEN` | Required for release telemetry; this is a public project token |
| `RYK_TELEMETRY_BUILD_DISABLED` | `0`; set to `1` only for local dry-runs that must disable transport |

## Build the Shortcuts.app shortcut

1. Open **Shortcuts** → **+** → name it **ryk cut-release**.
2. **Ask for Input** (or **Choose from Menu**): options `patch`, `minor`, `major`. Store as `Bump`.
3. **Run Shell Script** (pass input as argument or environment):

   ```sh
   set -euo pipefail
   REPO="${RYK_REPO:-$HOME/CodingProjects/ryk}"
   BUMP="$1"   # or wire Shortcut variable
   cd "$REPO"
   # Show computed version for confirm
   CUR="$(tr -d '[:space:]' < VERSION)"
   NEXT="$(./scripts/cut-release.sh --bump "$BUMP" --plan-only 2>/dev/null | sed -n 's/^Version:[[:space:]]*//p' | head -1 || true)"
   # plan-only prints "Version: A → B"; fallback:
   if [ -z "$NEXT" ]; then
     NEXT="$(python3 - <<'PY' "$CUR" "$BUMP"
import sys
cur, kind = sys.argv[1], sys.argv[2]
maj, mi, pa = map(int, cur.split("."))
if kind == "major": maj, mi, pa = maj+1, 0, 0
elif kind == "minor": mi, pa = mi+1, 0
else: pa += 1
print(f"{maj}.{mi}.{pa}")
PY
)"
   fi
   echo "NEXT=$NEXT"
   ```

   Prefer a simpler Shortcut: two shell steps — plan-only for display, then live after confirm.

4. **Show Alert** / **Ask for Confirmation**:

   > Release ryk v{NEXT} to GitHub for the curl installer from main?

5. On confirm, **Run Shell Script**:

   ```sh
   set -euo pipefail
   REPO="${RYK_REPO:-$HOME/CodingProjects/ryk}"
   BUMP="$1"
   cd "$REPO"
   # PATH for GUI-launched Shortcuts (adjust if needed)
   export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"
   ./scripts/cut-release.sh --bump "$BUMP" --live
   ```

6. **Show Notification** on success; on failure open `dist/cut-release-v*.log`.

### Shortcut tips

- Set **Shell** to `/bin/bash` or `/bin/zsh`.
- Grant Shortcuts **Developer Tools** / full disk if `git`/`docker` fail when run from the app.
- Pin `RYK_REPO` in the shell preamble if the checkout path differs.
- Never embed the PostHog or GitHub token in the Shortcut. Prefer running `--live` from **Terminal** so the release environment is explicit.

## First live cut checklist

1. `./scripts/cut-release.sh --bump patch --plan-only` on a clean `main`.
2. Optional dry-run (long): `./scripts/cut-release.sh --bump patch` — runs full gate + build; **creates a local version commit** without pushing. Prefer doing dry-run on a throwaway clone/worktree if you do not want that commit.
3. Live: Shortcut or `./scripts/cut-release.sh --bump patch --live`.
4. Verify: GitHub Release assets include `checksums.txt`, `telemetry-contract.txt`, `sbom.json`, `release-manifest.json`, and the platform archives. Test the public curl installer with `RYK_VERSION=X.Y.Z curl -fsSL https://rykanv.com/install | sh`.

## Failure recovery

No automatic rollback of tags or releases.

```sh
./scripts/cut-release.sh --live --version X.Y.Z --resume-from sign
```

See the recovery block printed on failure and `.release-cut/state.env`.

## Related scripts

- `scripts/build-release.sh` — archives + checksums + release inventory
- `scripts/build-linux-release-docker.sh` — Linux bins for Mac hosts  
- `scripts/verify-release.sh` — artifact contract  
