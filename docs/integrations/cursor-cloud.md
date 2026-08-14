# Cursor Cloud Terminal

The Cursor Cloud plugin adds a Vercel-style terminal for blocked commands. It does not evaluate policy. The ryk CLI and the existing Cursor `beforeShellExecution` hook remain the decision path.

## Open

```sh
ryk cloud
ryk cloud --demo
ryk dashboard --view terminal
```

`ryk cloud` is local and loopback-only. It opens `http://127.0.0.1:7742/#terminal` and reads the same blocked-action feed as the dashboard.

## Plugin location

- UI: `integrations/cursor-cloud-plugin/ui/`
- Mapping: `integrations/cursor-cloud-plugin/src/terminal.mjs`
- Demo stream: `integrations/cursor-cloud-plugin/fixtures/blocked-commands.json`

When no live denials exist yet, `--demo` (or an empty feed) shows the fixture stream so operators can see `ryk cloud` and `ryk agent` blocks before a real session records them.
