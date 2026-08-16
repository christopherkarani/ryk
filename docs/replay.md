# Replay

ryk writes per-session artifacts under `.ryk/sessions/<session-id>/`.

## Files

- `events.jsonl`: deterministic security events.
- `summary.json`: machine-readable session summary.
- `summary.md`: human-readable summary.
- `.ryk/last`: pointer to the last session.

## Commands

Bare `ryk replay` loads the last session and highlights denied actions. With no sessions, it prints: run `ryk start` then `ryk <agent>` (for example `ryk claude`).

```sh
ryk replay
ryk replay --json
ryk replay --only denied
ryk replay --verify
ryk replay --tui
ryk replay --session <id>
ryk replay --list
```

## Alt-screen timeline

`--tui` opens the replay timeline in an interactive alt-screen view for terminals that support rich output. It is opt-in; the default replay output stays linear for logs and copy/paste. On a pipe, `--plain`, `--no-rich`, or `NO_COLOR`, `--tui` falls back to that linear timeline (same exit as linear replay). `--tui` cannot be combined with `--json` because replay JSON is a frozen machine contract.

## Hash-chain Verification

Each event includes previous and current hashes. `--verify` detects modified, deleted, reordered, or malformed events and summary hash mismatches.

A local actor who rewrites both `events.jsonl` and `summary.json` together can produce a new internally consistent chain. Detecting that rewrite is out of scope (ryk does not sign audit files). Session end prints the final chain hash (`Audit chain: …`) and records it in `summary.json` / `summary.md` so you can copy it out of band and compare later.

## Redaction

Secret-like values are redacted before persistence, not only during replay. Replay should not be used as a raw terminal transcript.
