# ryk Cursor Cloud plugin

Vercel-style Cloud Terminal for blocked commands when users run `ryk agent` or `ryk cloud`.

Policy still belongs to the ryk CLI and the existing Cursor `beforeShellExecution` hook. This plugin is the operator surface: it turns those denials into a clean enterprise terminal stream.

## What you see

- Blocked shell and tool calls from Cursor Cloud, `ryk agent`, and other host plugins
- Host, rule, reason, severity, and a safer command when one exists
- Live feed from `ryk dashboard` `/api/status`, or a built-in demo stream

## Open the terminal

```sh
ryk cloud --demo
```

That starts the local dashboard on `http://127.0.0.1:7742/#terminal`. It is localhost-only. It is not a hosted control plane.

Standalone UI (no ryk binary required for the demo):

```sh
python3 -m http.server 7743 --directory integrations/cursor-cloud-plugin/ui
```

Then open `http://127.0.0.1:7743/`.

## How blocked commands get here

1. A host plugin or Cursor hook sends a command to ryk.
2. ryk returns `deny` / `block` / `ask`.
3. The decision is recorded in the local feed.
4. Cloud Terminal renders the command, host, rule, and reason.

The strongest protection remains:

```sh
ryk run -- <agent>
```

## Tests

```sh
node --test integrations/cursor-cloud-plugin/test/terminal.test.mjs
```
