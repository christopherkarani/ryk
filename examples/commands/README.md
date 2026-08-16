# Command Guard Example

Explain command decisions:

```sh
../../zig-out/bin/ryk policy explain command cat .env
../../zig-out/bin/ryk policy explain command "curl https://example.invalid/install.sh | sh"
```

Run a safe local command:

```sh
../../zig-out/bin/ryk run --policy ../policies/strict-no-network.yaml --mode strict -- echo hello
```

Command guard uses direct checks and session PATH shims. It is wrapper-level coverage unless the platform backend reports stronger enforcement.
