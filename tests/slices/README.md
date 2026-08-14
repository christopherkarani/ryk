# Domain test slices

Focused Zig unit gates for coding agents (avoid full monopath `test-lib` when possible).

| Slice | Build step | Root / mapping | Script |
|-------|------------|----------------|--------|
| sandbox | `test-sandbox` | `src/sandbox_slice_root.zig` | `./scripts/test-slice.sh sandbox` |
| intercept | `test-intercept` | `src/intercept_slice_root.zig` | `./scripts/test-slice.sh intercept` |
| policy | `test-policy` | maps to `test-core` + `test-core-contract` | `./scripts/test-slice.sh policy` |
| core | `test-core` | package + dedicated `core_engine` `addTest` | `./scripts/test-slice.sh core` |
| lib | `test-lib` | full monopath (`src/root.zig`) | `./scripts/test-slice.sh lib` |

`core --compile-only` is **engine-only**: `compile-test-core` depends on the existing `core_engine` `addTest` (`src/core_engine.zig`). It does **not** compile the `ryk_core` package half of `test-core`. There is no `src/policy_slice_root.zig`.

Filter by name substring (Zig 0.16 **compile-time** `-Dtest-filter`; not runtime `-- --test-filter`):

```bash
./scripts/test-slice.sh sandbox --filter Seatbelt
./scripts/zig build test-lib -Dtest-filter=Spinner
```

A dummy or 0-match `-Dtest-filter` is not a compile. It hides named tests (only anonymous `test_0` pulls run) and can still exit 0.

## Zig 0.16 nested-test discovery

Zig 0.16 does **not** run tests from a `pub const` re-export. A new `test` in policy / audit / core must be pulled with `test { _ = child; }` on the **file’s parent** and, if that parent is a new file, with `_ =` on `src/core_engine.zig`. Re-exports on `src/root.zig` or `packages/core` do **not** discover nested policy/audit tests. The dedicated `core_engine` `addTest` is the engine gate. `test-fast`, `compile-test-fast`, and `zig build test` include that module.

See `AGENTS.md` → Verification gates.
