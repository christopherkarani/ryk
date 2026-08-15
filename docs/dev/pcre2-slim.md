# PCRE2 slim build (binary-size P3)

ryk pins [PCRE2 10.48](https://github.com/PCRE2Project/pcre2) at
`5a632d3cf0dbcc6821cfc39cacf88b19f3281791` (`build.zig.zon`). The in-process
shell evaluator only **compile / match / span** via `src/shell_engine/pcre2_shim.c`.
JIT is already default-off in upstream's Zig build. UTF is off at the shim
(`PCRE2_DOTALL` only).

Upstream `pcre2/build.zig` at that commit has **no option** to drop Unicode/UCD,
DFA, or substitute. `SUPPORT_UNICODE` is hardcoded `true`, and the C file list
always includes `pcre2_ucd.c` (116 KiB of property tables when Unicode is on),
`pcre2_dfa_match.c`, `pcre2_substitute.c`, convert/serialize, and UTF helpers.

Slim is therefore a **documented fork of that build**, not a one-liner on
`b.dependency("pcre2").artifact("pcre2-8")`.

## What we compile

`build/pcre2_slim.zig` fetches the same tarball and compiles a static `pcre2-8`
with:

| Upstream | Slim |
| --- | --- |
| `SUPPORT_UNICODE = true` | `false` (dummy UCD records only) |
| `SUPPORT_JIT` option (default false) | `false` |
| DFA / substitute / convert / serialize | omitted |
| `pcre2_extuni.c`, `pcre2_ord2utf.c` | omitted |
| `pcre2_valid_utf.c`, `pcre2_script_run.c` | kept (referenced from compile/match even with UNICODE off) |
| `pcre2test` + `pcre2-posix` | not built |

`pcre2_ucd.c` is still in the file list so the dummy `PRIV(ucd_*)` objects exist;
the Unicode 17 property tables are behind `#ifdef SUPPORT_UNICODE` and do not
land in `ryk`. `pcre2_valid_utf.c` and `pcre2_script_run.c` stay because
compile/match reference those symbols even with UNICODE off.

On this tree, ReleaseSafe `libpcre2-8.a` went from 642,728 B (upstream artifact)
to 312,320 B (slim). The default musl `ryk` dropped ~179 KiB vs post-P1.

## UNICODE=false contract

Pack patterns are byte-oriented (POSIX classes such as `[:alnum:]`, not `\p{L}`).
`UNICODE=false` must be proven with:

- `./scripts/zig build test-shell-engine` (oracle corpus + PCRE unit tests)
- `./zig-out/bin/ryk redteam --ci`

`\p{…}` / `\P{…}` must **fail compile** (`error.CompileFailed`), never compile
and silently no-match.

## Error polarity

Unchanged: PCRE2 errors stay `<0`. Only `PCRE2_ERROR_NOMATCH` is `0`. The shim
must not collapse infrastructure errors into no-match (fail closed).

## What this is not

- Not a GitHub fork of PCRE2 sources. Provenance stays the upstream tarball hash.
- Not `x86_64-linux-gnu`. Linux release artifacts stay musl static + strip.
