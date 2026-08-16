#!/usr/bin/env python3
"""Validate .github/issue-clusters.json: unique membership, label names, required fields."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / ".github" / "issue-clusters.json"
REQUIRED = ("label", "color", "description", "summary", "issues", "primary_files", "coordinate")


def main() -> int:
    data = json.loads(PATH.read_text())
    clusters = data["clusters"]
    seen: dict[int, str] = {}
    errors: list[str] = []
    for name, spec in clusters.items():
        for key in REQUIRED:
            if key not in spec:
                errors.append(f"{name}: missing {key}")
        label = spec.get("label", "")
        if not label.startswith("cluster:"):
            errors.append(f"{name}: label must start with cluster: ({label!r})")
        if label != f"cluster:{name}":
            errors.append(f"{name}: label {label!r} should be 'cluster:{name}'")
        issues = spec.get("issues") or []
        if not issues:
            errors.append(f"{name}: empty issues")
        if len(issues) != len(set(issues)):
            errors.append(f"{name}: duplicate issue numbers in cluster")
        for num in issues:
            if num in seen:
                errors.append(f"#{num} in both {seen[num]} and {name}")
            else:
                seen[num] = name
        for other in spec.get("conflicts_with") or []:
            if other not in clusters:
                errors.append(f"{name}: conflicts_with unknown cluster {other!r}")
        for num in spec.get("in_flight") or []:
            if num not in issues:
                errors.append(f"{name}: in_flight #{num} is not a cluster member")
    if errors:
        print("issue-clusters check failed:")
        for err in errors:
            print(f"  - {err}")
        return 1
    print(f"ok: {len(clusters)} clusters, {len(seen)} issues, unique membership")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
