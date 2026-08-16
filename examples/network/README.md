# Network Example

Run with no-network policy decisions:

```sh
../../zig-out/bin/ryk run --policy ../policies/strict-no-network.yaml --mode strict -- echo local-only
```

Allow one destination for ryk-mediated decisions:

```sh
../../zig-out/bin/ryk run --network allowlist --allow-network api.github.com -- echo checked
```

Transparent network enforcement depends on `ryk doctor`.
