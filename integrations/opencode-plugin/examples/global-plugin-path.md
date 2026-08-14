# Global Plugin Path

This example shows how to install the ryk plugin globally so it applies to all OpenCode sessions on your machine.

## Steps

1. Create the OpenCode global plugins directory:

   ```bash
   mkdir -p ~/.config/opencode/plugins
   ```

2. Copy the ryk plugin file into the global plugins directory:

   ```bash
   # Adjust the source path to point to the ryk repository
   cp /path/to/ryk-repo/integrations/opencode-plugin/ryk.ts ~/.config/opencode/plugins/ryk.ts
   cp /path/to/ryk-repo/integrations/opencode-plugin/ryk-tui.ts ~/.config/opencode/plugins/ryk-tui.ts
   ```

   Or create a symlink:

   ```bash
   ln -s /path/to/ryk-repo/integrations/opencode-plugin/ryk.ts ~/.config/opencode/plugins/ryk.ts
   ```

3. OpenCode will discover plugins in `~/.config/opencode/plugins/` for every session.

## Verify

Run the ryk plugin doctor:

```bash
ryk plugin doctor opencode
```

Expected output includes:
- `opencode: found` in the plugin directories section.
- ryk binary detected in PATH or at a known build path.

## Notes

- Global plugins apply across all projects and sessions.
- They are useful for consistent policy enforcement on a single machine.
- For stronger protection, also run OpenCode through ryk: `ryk run -- opencode`.
- The plugin file contains no secrets and is safe to keep in your home directory.
