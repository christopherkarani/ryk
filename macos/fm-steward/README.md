# fm-steward (contract pin)

Swift source for the Mac on-device Foundation Models steward lives in
**[christopherkarani/ryk-fm-steward](https://github.com/christopherkarani/ryk-fm-steward)**.

This directory keeps the **wire contract** ryk encodes and parses:

- `Schemas/risk-card-v1.json`
- `Schemas/classify-response-v1.json`
- `Fixtures/*.json` — golden shell cards

Zig never links Swift. It runs `fm-steward classify --card <temp> --json` as a
subprocess (`src/cli/fm_steward_client.zig`). Resolve order: `RYK_FM_STEWARD_BIN`,
else `fm-steward` on `PATH`. Missing binary / timeout / `RYK_FM_STEWARD=0` /
non-macOS → **continue** (fail-open). FM may upgrade a soft outcome to `ask`;
it must **never** soften a deny.

## Install the binary

```sh
git clone https://github.com/christopherkarani/ryk-fm-steward
cd ryk-fm-steward
swift build
export RYK_FM_STEWARD_BIN="$(pwd)/.build/debug/fm-steward"
# or: install .build/debug/fm-steward onto PATH
```

Requires macOS 26+ and Apple Intelligence / Foundation Models assets. Linux
skips the steward.

## Check this pin

```sh
bash macos/fm-steward/Fixtures/validate.sh
```

When you change the Swift schemas, update these copies in the same change (or
immediately after) so ryk and the steward stay on the same v1 wire.
