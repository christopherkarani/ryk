# Schemas

The repository contains versioned JSON Schemas for the local ryk runtime:

- `policy-v1.json`: policy files and their rule sections.
- `event-v1.json`: audit event records.
- `mcp-manifest-v1.json`: stdio MCP server manifests.
- `macos/fm-steward/Schemas/`: risk-card-v1 and classify-response-v1 (Mac FM
  steward wire contract). Swift source is
  [ryk-fm-steward](https://github.com/christopherkarani/ryk-fm-steward).

The runtime rejects unknown keys in these v1 formats. A breaking schema change requires a new version and migration notes.
