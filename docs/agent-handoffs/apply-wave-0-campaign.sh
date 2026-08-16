#!/usr/bin/env bash
# Filtered Wave 0 for the grouped-issue campaign.
# Do not run apply-wave-2-triage.sh (closed parents + wrong factory:auto on caps).
# Requires gh with issues:write.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PLAN="${PLAN:-$ROOT/docs/agent-handoffs/wave-0-campaign-apply.json}"
REPO="${REPO:-christopherkarani/ryk}"

command -v gh >/dev/null || { echo "gh is required" >&2; exit 1; }
command -v python3 >/dev/null || { echo "python3 is required" >&2; exit 1; }

python3 - "$PLAN" "$REPO" <<'PY'
import json, subprocess, sys

plan = json.load(open(sys.argv[1]))
repo = sys.argv[2]

def gh_api(method, path, payload=None):
    cmd = ["gh", "api", "--method", method, f"repos/{repo}{path}"]
    if payload is not None:
        cmd.extend(["--input", "-"])
        subprocess.run(cmd, check=True, input=json.dumps(payload), text=True)
    else:
        subprocess.run(cmd, check=True)

def issue_state(n):
    raw = subprocess.check_output(
        ["gh", "api", f"repos/{repo}/issues/{n}", "--jq", ".state"],
        text=True,
    )
    return raw.strip()

for item in plan["promote"]:
    n = item["number"]
    if issue_state(n) != "open":
        print(f"skip promote #{n} (not open)", flush=True)
        continue
    print(f"promote #{n}", flush=True)
    gh_api("POST", f"/issues/{n}/comments", {"body": item["comment"]})
    gh_api("PATCH", f"/issues/{n}", {"labels": item["labels"]})

for item in plan["close"]:
    n = item["number"]
    if issue_state(n) != "open":
        print(f"skip close #{n} (not open)", flush=True)
        continue
    print(f"close #{n}", flush=True)
    gh_api("POST", f"/issues/{n}/comments", {"body": item["comment"]})
    payload = {"state": "closed", "state_reason": item["state_reason"]}
    if item.get("labels"):
        payload["labels"] = item["labels"]
    gh_api("PATCH", f"/issues/{n}", payload)

print("done")
PY
