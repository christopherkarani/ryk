# Tests

CLI tests live beside the Zig CLI module in `src/cli/mod.zig` and run through `zig build test`. Domain roots under this directory are wired from `build.zig` (`test` and `test-hooks`).

`tests/hook_host_matrix.zig` is the product harness gate: it installs `./zig-out/bin/ryk` and exercises every day-one host (claude, codex, opencode, openclaw, hermes, grok, pi, cursor) on the Zig shell_engine. It does not require the removed Rust daemon. Fixture JSON lives under `tests/plugin-fixtures/<host>/`. `./scripts/host-live-e2e.sh` and `./scripts/harness-stress.sh` are the same matrix from the shell.
