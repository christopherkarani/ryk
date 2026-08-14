# Windows Platform

ryk is macOS/Linux-first. Windows has no operating-system sandbox. Sessions
run at `wrapper` / `hook` grade only: PATH shims, command wrappers, staged
writes, env filtering, policy decisions, and the MCP stdio proxy. There is no
Seatbelt/Landlock-equivalent session-attach backend. `ryk doctor` reports
capability; it cannot promote Windows to `OS-enforced`. See the
[compatibility matrix](compatibility.md).

Run:

```powershell
.\ryk.exe doctor
```

## Capability Matrix

| Feature | Status |
|---|---|
| Process supervision/cleanup | partial (Job Object process-tree cleanup is not installed) |
| Env filtering | active |
| Staged writes | active |
| PATH shims | wrapper-only |
| cmd and PowerShell wrappers | wrapper-only |
| MCP stdio proxy | active |
| Network decision engine | active |
| Transparent network enforcement | unavailable; wrapper/proxy-mediated only, routes not forced |
| Transparent file enforcement | limited (no OS filesystem attach; ryk-mediated staging and protected-path matching only) |
| Strong sandbox | unavailable |

## Path Normalization

Policy matching handles Windows drive, UNC, backslash, and case-normalization edges where implemented. Validate policies on Windows before relying on them in CI.

## Protected Paths

Use policy deny rules for `.env`, SSH keys, cloud credentials, browser credential stores, and project metadata directories.

## Limitations

Windows sessions are wrapper/hook grade. Batch forwarding is not a security boundary. Absolute paths and non-shimmed tools can skip PATH shims. There is no OS sandbox to attach, and doctor cannot report one. Use ryk-managed sessions and read the [compatibility matrix](compatibility.md) before making an enforcement claim.
