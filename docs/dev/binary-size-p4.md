# Binary size P4 — flags-only vs optional `ryk-dev`

P4 is a product decision, not a silent split. This chat has **not** signed a
second shipped binary. PATH `ryk` stays the full CLI. No `ryk-dev` was built
or packaged.

Measured 2026-08-15 on `x86_64` Linux with `./scripts/zig` **0.16.0** at
`fa8ddd5` (post P0 strip, P1 `-Dhttp`, P2 `-Dtui`, P3 PCRE2 slim). Optimize
`ReleaseSafe` (product strip). Isolated `--prefix` so Debug `zig-out/bin/ryk`
was not replaced.

## Decision: still open — recommend flags-only

Do **not** land an optional `ryk-dev`. Keep one `bin/ryk`. Use `-Dtui` /
`-Dhttp` for optional slim compile-outs. Revisit a sibling only if a later
signed decision wants extras off the default artifact **and** PATH `ryk`
still ships doctor / update / uninstall / hook / evaluate / run / host
aliases / `agent_hook`.

A split does not shrink curl|sh, Homebrew, npm, checksums, or minisig: those
channels install one `bin/ryk`. `scripts/install.sh` requires
`ryk doctor --help` to advertise `--fix`, then runs
`doctor --fix --from-install`. Plugins spawn `ryk hook` / `evaluate` (and
sometimes `decide` + `doctor`). Missing hook is fail-closed deny JSON. Ask
is not allow. `verify-release.sh` forbids an archive binary named
`ryk-daemon`.

## Full CLI vs 1.8–2.5 MiB core floor

| Profile | Linkage | Bytes | MiB | vs 1.8 MiB | vs 2.5 MiB |
| --- | --- | ---: | ---: | ---: | ---: |
| Full (`-Dtui` `-Dhttp` default on) | glibc dynamic | 5,615,752 | 5.356 | +3.556 | +2.856 |
| `-Dtui=false` | glibc dynamic | 5,269,944 | 5.026 | +3.226 | +2.526 |
| `-Dhttp=false` | glibc dynamic | 4,981,272 | 4.751 | +2.951 | +2.251 |
| both flags off | glibc dynamic | 4,635,128 | 4.420 | +2.620 | +1.920 |
| Full | musl static | 5,692,064 | 5.428 | +3.628 | +2.928 |
| both flags off | musl static | 4,725,744 | 4.507 | +2.707 | +2.007 |

Committed `docs/dev/binary-size-baseline.tsv` linux-amd64 is 6,103,760 B
(5.821 MiB). This tree’s musl full is **−402 KiB** vs that row (P3 + later).
`scripts/build-release.sh` still passes `-Dtarget=x86_64-linux` (gnu dynamic
on this host). `docs/dev/pcre2-slim.md` says Linux release stays musl static.
Record both; do not treat them as the same artifact.

Flag savings on glibc: TUI **338 KiB**, HTTP **620 KiB**, both **958 KiB**.
Musl both-off saves **944 KiB**. The slimmest same-`ryk` profile is still
**~2×** the 2.5 MiB ceiling. Dropping `.eh_frame` (~120–130 KiB) cannot
close the gap.

## `__eh_frame` / panic usability

No custom `pub const panic` / `std.debug.FullPanic` override — Zig
**FullPanic**. ReleaseSafe applies `-fstrip` (`applyReleaseSafeStrip` in
`build.zig`). `nm` reports no symbols. There is no `.debug_*`.

`.eh_frame` remains (unwind tables, not DWARF):

| Profile | `.eh_frame` | `.eh_frame_hdr` |
| --- | ---: | ---: |
| glibc full | 119.6 KiB | 20.8 KiB |
| musl full | 129.9 KiB | 22.8 KiB |
| glibc both-off | 102.1 KiB | 17.7 KiB |
| musl both-off | 111.8 KiB | 19.6 KiB |

`std.options.allow_stack_tracing` defaults to `!builtin.strip_debug_info`.
Stripped ReleaseSafe therefore embeds
`Cannot print stack trace: stack tracing is disabled`. Frame pointers are
still present (`push %rbp` / `mov %rsp,%rbp` in `.text`).
`omit_frame_pointer` is **off**. Turning it on without a dSYM/PDB sidecar
would drop the remaining FP unwind. Do not enable it on the shipped CLI.

## Why not optional `ryk-dev`

`ryk-dev` for dashboard / redteam / scan / TUI extras only helps the
*install* size if PATH `ryk` stops being full. That inverts product law
(curl|sh, plugins, `doctor --fix`). If PATH `ryk` stays full, the sibling
is extra bytes the installer ignores — complexity with no floor movement.

Flags-only keeps one artifact, one checksum row, and proven slim profiles
(`./scripts/check-slim-tui-symbols.sh`, `-Dhttp=false` stub checks). Further
cuts belong on the same `ryk` (more compile-outs), not a second name.

## Install / plugin proof (full PATH-shaped `ryk`)

On `/tmp/ryk-p4/full/bin/ryk` (TUI+HTTP on, ReleaseSafe):

- `doctor --help` matches the installer `--fix` advertisement; slim both-off
  does too.
- `hook` / `evaluate` / `run` / `update` / `uninstall` / `dashboard` /
  `redteam` / `scan` `--help` succeed. Host aliases
  `claude|codex|pi|opencode|openclaw|hermes|grok` `--help` succeed.
- Empty `ryk hook claude PreToolUse` stdout is deny JSON
  (`permissionDecision":"deny"`). Ask is not allow.
- `evaluate --json --stdin` without `schema_version` is
  `decision":"error"` / `invalid_input` (not allow).

No release was cut. Baseline TSV was not rewritten.
