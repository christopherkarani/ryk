# Staged Writes Example

After an ryk-mediated session creates staged writes:

```sh
../../zig-out/bin/ryk diff --session last
../../zig-out/bin/ryk apply --session last --file docs/example.md
../../zig-out/bin/ryk discard --session last
```

Staging is review workflow coverage for ryk-mediated writes. It is not a claim of transparent filesystem enforcement on every platform.
