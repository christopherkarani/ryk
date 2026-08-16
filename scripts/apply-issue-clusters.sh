#!/usr/bin/env bash
# Create cluster:* labels and stamp them on related issues.
# Requires a token with Issues read/write (classic PAT or fine-grained).
#
#   GITHUB_ISSUES_TOKEN=ghp_… ./scripts/apply-issue-clusters.sh
#   ./scripts/apply-issue-clusters.sh --dry-run
set -euo pipefail

REPO="${REPO:-christopherkarani/ryk}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CLUSTERS="$ROOT/.github/issue-clusters.json"
DRY_RUN=0
if [[ "${1:-}" == "--dry-run" ]]; then
  DRY_RUN=1
fi

if [[ ! -f "$CLUSTERS" ]]; then
  echo "missing $CLUSTERS" >&2
  exit 1
fi

if [[ "$DRY_RUN" -eq 0 ]]; then
  if [[ -n "${GITHUB_ISSUES_TOKEN:-}" ]]; then
    export GH_TOKEN="$GITHUB_ISSUES_TOKEN"
  fi
  if ! gh auth status -h github.com >/dev/null 2>&1; then
    echo "gh is not authenticated. Set GITHUB_ISSUES_TOKEN or run gh auth login." >&2
    exit 1
  fi
fi

python3 - "$CLUSTERS" "$REPO" "$DRY_RUN" <<'PY'
import json, subprocess, sys

clusters_path, repo, dry = sys.argv[1], sys.argv[2], sys.argv[3] == "1"
clusters = json.load(open(clusters_path))["clusters"]

def gh(*args):
    p = subprocess.run(["gh", *args], capture_output=True, text=True)
    return p.returncode, (p.stdout or "") + (p.stderr or "")

created = stamped = comments = failed = 0
for name, spec in clusters.items():
    label = spec["label"]
    color = spec.get("color", "5319E7")
    desc = spec.get("description", name)[:100]
    siblings = spec["issues"]
    sibling_list = ", ".join(f"#{n}" for n in siblings)
    body = "\n".join(
        [
            f"## Related issues (`{label}`)",
            "",
            spec.get("summary", "").strip(),
            "",
            f"**Cluster members:** {sibling_list}",
            "",
            "Work this cluster as one stream. Check sibling issues before opening a PR so you do not collide.",
        ]
    )
    if dry:
        print(f"DRY {label} -> {sibling_list}")
        continue

    code, out = gh(
        "label",
        "create",
        label,
        "-R",
        repo,
        "--color",
        color,
        "--description",
        desc,
        "--force",
    )
    if code != 0:
        print(f"FAIL label {label}: {out.strip()[:240]}")
        failed += 1
        continue
    created += 1
    print(f"OK label {label}")

    for num in siblings:
        code, out = gh("issue", "edit", str(num), "-R", repo, "--add-label", label)
        if code != 0:
            print(f"FAIL stamp #{num} {label}: {out.strip()[:240]}")
            failed += 1
            continue
        stamped += 1
        print(f"OK stamp #{num} {label}")
        code, out = gh("issue", "comment", str(num), "-R", repo, "--body", body)
        if code != 0:
            print(f"FAIL comment #{num}: {out.strip()[:240]}")
            failed += 1
        else:
            comments += 1

if dry:
    print(f"DRY {len(clusters)} clusters")
    sys.exit(0)
print(f"DONE labels={created} stamped={stamped} comments={comments} failed={failed}")
sys.exit(1 if failed else 0)
PY
