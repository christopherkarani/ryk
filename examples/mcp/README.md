# MCP Example

Inspect the deterministic fake server:

```sh
../../zig-out/bin/ryk mcp inspect --name demo --command python3 -- ../../fixtures/mcp/fake_server.py
```

Proxy it with policy:

```sh
../../zig-out/bin/ryk mcp proxy --name demo --policy ../policies/mcp-stdio-demo.yaml --command python3 -- ../../fixtures/mcp/fake_server.py
```

The proxy is stdio-only. Server stdout must be protocol JSON-RPC only. Do not send server logs to stderr: the proxy discards child-server stderr. ryk's own diagnostics stay on ryk's stderr.
