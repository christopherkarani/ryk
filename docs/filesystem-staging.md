# Filesystem Staging

Staged writes let users review ryk-mediated file changes before applying them.

```sh
./zig-out/bin/ryk diff --session last
./zig-out/bin/ryk apply --session last --file path/to/file
./zig-out/bin/ryk discard --session last
```

## Layout

Session directories may include:

- `staged/`
- `original/`
- `staging-index.json`
- `events.jsonl`
- `summary.json`
- `summary.md`

## Protections

ryk normalizes paths, records original hashes where feasible, verifies staged blob hashes before apply, and denies protected paths such as `.git/**`, `.ryk/**`, `.env`, SSH keys, and cloud credentials according to policy.

**OS control roots (session-attach):** when Seatbelt/Landlock attach succeeds, default write-deny control roots are `{workspace}/.ryk` and `{workspace}/.git` (readable, not agent-writable). This matches policy/builtin `files.write` deny so raw bash cannot plant under `.git` while YAML claims otherwise. Side effect: `git commit` / index writers under attach get EPERM until a mediated git path exists. Without OS attach, only policy/hook evaluation applies. Nested submodule `.git` paths are not default control roots. A non-directory workspace `.git` (gitdir file in linked worktrees) fails control validation closed rather than granting an agent-writable alias.

## Symlink And Traversal Notes

Path traversal and symlink escape attempts are treated as security-sensitive and covered by tests. Review diffs before applying staged writes.

## Current Interception Limitations

Staging applies to ryk-mediated writes. It is not universal transparent filesystem interception. OS FS isolation is **session-attach** only: claimable after protected agent child apply succeeds for that session — doctor capability probes alone are not a live session claim.

## Platform Notes

- **Linux:** staged writes always; Landlock session-attach when ABI ≥ 1 (kernel 5.13+) on protected agent child launches. CI attach evidence: linux amd64.
- **macOS:** staged writes always; Seatbelt session-attach on product majors 14–26 (capability gate) via the same `--os-sandbox` flag. CI attach evidence: macos-14; other majors local until freeze jobs cover them.
- **Windows:** no OS filesystem attach. Staged writes and protected-path matching only (wrapper/hook grade).

See [platform-linux.md](platform-linux.md), [platform-macos.md](platform-macos.md), and [compatibility.md](compatibility.md#protection-grades-canonical).
