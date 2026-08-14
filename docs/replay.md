# Replay

ryk writes per-session artifacts under `.ryk/sessions/<session-id>/`.

## Files

- `events.jsonl`: deterministic security events.
- `summary.json`: machine-readable session summary.
- `summary.md`: human-readable summary.
- `.ryk/last`: pointer to the last session.

## Commands

Bare `ryk replay` loads the **last** session and highlights denied actions. No sessions yet → friendly empty state pointing at Safe Launch (`ryk start` then `ryk <agent>`).

```sh
./zig-out/bin/ryk replay
./zig-out/bin/ryk replay --json
./zig-out/bin/ryk replay --only denied
./zig-out/bin/ryk replay --verify
./zig-out/bin/ryk replay --tui
./zig-out/bin/ryk replay --session <id>
./zig-out/bin/ryk replay --list
```

## Alt-screen timeline

`--tui` opens the replay timeline in an interactive alt-screen view for terminals that support rich output. It is opt-in; the default replay output stays linear for logs and copy/paste. `--tui` is TTY-only and cannot be combined with `--json` because replay JSON is a frozen machine contract.

## Hash-chain Verification

Each event includes previous and current hashes. `--verify` detects modified, deleted, reordered, or malformed events and summary hash mismatches.

A local actor who rewrites both `events.jsonl` and `summary.json` together can produce a new internally consistent chain. Detecting that rewrite is out of scope (ryk does not sign audit files). Session end prints the final chain hash (`Audit chain: …`) and records it in `summary.json` / `summary.md` so you can copy it out of band and compare later.

## Redaction

Secret-like values are redacted before persistence, not only during replay. Replay should not be used as a raw terminal transcript.
