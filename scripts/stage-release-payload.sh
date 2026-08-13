#!/usr/bin/env bash
set -euo pipefail

SOURCE_ROOT="${1:?source root is required}"
DEST_ROOT="${2:?destination root is required}"

git -C "$SOURCE_ROOT" rev-parse --is-inside-work-tree >/dev/null
mkdir -p "$DEST_ROOT"

if git -C "$SOURCE_ROOT" ls-files -s -- \
    README.md LICENSE SECURITY.md CONTRIBUTING.md \
    docs policies schemas fixtures examples packages packaging scripts integrations ryk-pi |
    awk '$1 == "120000" { print $4; found = 1 } END { exit found ? 0 : 1 }' |
    grep -q .; then
  printf 'release staging: tracked symlinks are forbidden in the release payload\n' >&2
  exit 1
fi

# Package only reviewed, tracked source files. Generated dashboard output is
# added separately by build-release.sh after its own presence checks.
git -C "$SOURCE_ROOT" ls-files -z -- \
  README.md LICENSE SECURITY.md CONTRIBUTING.md \
  docs policies schemas fixtures examples packages packaging scripts integrations ryk-pi |
  tar -C "$SOURCE_ROOT" --null -T - -cf - |
  tar -C "$DEST_ROOT" -xf -
