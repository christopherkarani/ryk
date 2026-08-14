# Project-Local Plugin Path

This example shows how to install the ryk plugin locally within a single project.

## Steps

1. From your project root, create the OpenCode plugins directory:

   ```bash
   mkdir -p .opencode/plugins
   ```

2. Copy the ryk plugin file into the project-local plugins directory:

   ```bash
   # Adjust the source path to point to the ryk repository
   cp /path/to/ryk-repo/integrations/opencode-plugin/ryk.ts .opencode/plugins/ryk.ts
   cp /path/to/ryk-repo/integrations/opencode-plugin/ryk-tui.ts .opencode/plugins/ryk-tui.ts
   ```

   Or create a symlink:

   ```bash
   ln -s /path/to/ryk-repo/integrations/opencode-plugin/ryk.ts .opencode/plugins/ryk.ts
   ```

3. OpenCode will automatically discover plugins in `.opencode/plugins/` when running inside the project.

## Verify

Run the ryk plugin doctor from the project root:

```bash
ryk plugin doctor opencode
```

Expected output includes:
- `opencode: found` in the plugin directories section.
- ryk binary detected in PATH or at a known build path.

## Notes

- Project-local plugins are scoped to the current workspace.
- They travel with the repo if committed (the plugin file is small and contains no secrets).
- For stronger protection, also run OpenCode through ryk: `ryk run -- opencode`.
