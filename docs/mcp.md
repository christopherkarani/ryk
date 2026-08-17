# MCP

ryk supports stdio MCP proxying for servers launched through ryk.

## Inspect

```sh
./zig-out/bin/ryk mcp inspect --name demo --command python3 -- fixtures/mcp/fake_server.py
./zig-out/bin/ryk mcp inspect --name demo --policy policies/presets/mcp-dev.yaml --command python3 -- fixtures/mcp/fake_server.py
```

`inspect` initializes the server, sends `notifications/initialized`, calls `tools/list`, and reports risk findings. For each tool it also prints **inferred effect hits** from the built-in catalog (and user effect packs when present), e.g. `effects: comms.message [high catalog…]` or `effects: (none)`.

When `--policy <path>` is provided, it evaluates each listed tool through the loaded Core policy (including `effects:` when configured) and prints the policy decision and matched rule. Example line:

```text
  send_email    risk: high  default: ask  effects: comms.message [high catalog…]  policy: deny rule: effects.deny[comms.message]
```

Effect output never includes raw argument values. For interactive classification without starting a server, use `ryk tools classify <name>`.

## Proxy

```sh
python3 fixtures/mcp/fake_client.py | ./zig-out/bin/ryk mcp proxy --name demo --policy policies/presets/mcp-dev.yaml --command python3 -- fixtures/mcp/fake_server.py
```

The proxy reads client JSON-RPC from stdin and writes protocol responses to stdout. Ryk human diagnostics use stderr, but child-server stderr is discarded because it is attacker-controlled and may contain credentials; this does not affect the separate stdout JSON-RPC channel. Running `ryk mcp proxy` without a client input stream waits for JSON-RPC on stdin. When the proxy session ends, stderr prints `ryk mcp proxy: audit chain <sha256>` for out-of-band comparison. That print is not an integrity guarantee; detecting a local rewrite of both the event log and the summary is out of scope.

## Manifest Support

`ryk doctor` and `ryk mcp list` count YAML files under the workspace `.ryk/mcp/` directory (`<name>.yaml` or `<name>.yml`). The example fixture `examples/mcp/demo-manifest.yaml` is for local inspect/proxy demos; it is not the path doctor scans. Manifests are launch and inventory metadata, not OS grants. ryk mediates MCP only through `ryk mcp proxy`.

Create a workspace manifest, then check it:

```sh
mkdir -p .ryk/mcp
./zig-out/bin/ryk mcp manifest generate --server demo > .ryk/mcp/demo.yaml
./zig-out/bin/ryk mcp manifest check .ryk/mcp/demo.yaml
```

You can copy the example fixture into `.ryk/mcp/` instead of generating. Doctor then reports `manifests under .ryk/mcp: 1 found` instead of `none`. Doctor does not write this directory or rewrite policy. `generate` prints YAML on stdout; redirect it yourself.

If `.ryk/policy.yaml` has no `mcp.default`, doctor prints MCP policy default `ask`. That report is diagnose-only; `ask` is never treated as allow.

```sh
./zig-out/bin/ryk mcp manifest check examples/mcp/demo-manifest.yaml
./zig-out/bin/ryk mcp proxy --name demo --manifest examples/mcp/demo-manifest.yaml --command python3 -- fixtures/mcp/fake_server.py
```

Manifest defaults only apply when the launched command and manifest binding match.

## Mediated Methods

ryk policy-gates:

- `tools/call`
- `resources/read`
- `prompts/get`
- sampling requests, default-denied unless policy permits them

An interactive **Session** approval is kept for the lifetime of that `ryk mcp proxy` process when the JSON-RPC method and canonical args match. That is process-session sticky, not a permanent ryk allowlist write. **Once** still applies to a single call. `ask` is never treated as allow. Args that cannot be stringified are not stored as a shared session key. CI and non-interactive proxy runs convert `ask` to deny.

ryk also observes and audits `tools/list`, `resources/list`, and `prompts/list` metadata so later calls can be evaluated with the discovered risk context.

## Unmediated Methods: deny by default

The proxy forwards only an explicit allowlist of known-safe, side-effect-free methods without policy gating:

- `initialize` — protocol handshake
- `ping` — keepalive (no params, no side effects; forwarded unaudited)
- `notifications/*` — spec notification channel (forwarded, audited)
- `tools/list`, `resources/list`, `prompts/list` — read-only discovery (responses inspected/audited)

Every other method is denied with a JSON-RPC error and an audited `mcp_unknown_method` deny event. This includes `completion/complete` (argument content would leave the client unmediated), `logging/setLevel` (server side effect), vendor/extension namespaces such as `vendor/private`, and any future spec method until it is reviewed and allowlisted. A request-shaped message without an `id` that is not a `notifications/*` method is likewise denied rather than forwarded.

## Protocol Warning

Stdio MCP stdout must contain only newline-delimited JSON-RPC protocol messages. Do not send child-server logs to stderr: `ryk mcp proxy` discards the server's stderr. ryk's own diagnostics stay on ryk's stderr.

## Remote/HTTP Status

Remote HTTP MCP, OAuth, and hosted gateway support are not current defaults. Use stdio proxying unless a future release documents a supported alternative.

## Limitations

ryk mediates MCP traffic that passes through `ryk mcp proxy`. It does not protect an MCP server launched directly by another client.
