# Homebrew channel

Homebrew is the **recommended macOS install path** and how an install stays
current: `brew upgrade ryk` replaces the binary, and `ryk doctor --fix`
afterwards refreshes managed host plugins. An install that never upgrades keeps
stale plugin files, so keeping this channel current is a protection concern, not
just packaging hygiene.

```sh
brew tap christopherkarani/ryk
brew install ryk
ryk doctor --fix
ryk doctor
```

`Formula/ryk.rb` is a **real formula**, not a template: it carries the published
release URLs and the four platform SHA-256 digests.

## Why the formula does not run onboarding

The formula deliberately has **no `post_install`**. Homebrew runs post-install
inside `Dir.mktmpdir` with `HOME` set to that temp directory (see
`Formula#run_post_install`), so `ryk doctor --fix --from-install` writes the
policy and every host plugin into a directory brew deletes on the way out —
verified locally, where the user policy landed at
`/private/tmp/ryk-postinstall-*/.config/ryk/policy.yaml`. The user would end up
with an install that claimed onboarding ran and protected nothing.

Writing ryk's ~41 onboarding files into that temp HOME additionally made brew's
own cleanup fail with `Errno::ENOTEMPTY`, so `brew install` exited non-zero after
otherwise installing correctly.

Two smaller landmines worth remembering if onboarding is ever revisited:
Homebrew's `Formula#system` is `(cmd, *args)` and raises on failure — it does not
accept an env hash, so `system env_hash, "cmd"` executes the hash itself — and
`brew audit` for homebrew-core rejects formulae that write to `$HOME` at all.
`scripts/test-homebrew-formula.sh` guards the `system`-with-env-hash mistake.

Consequence: `caveats` must tell users to run `ryk doctor --fix` themselves, and
must not imply protection is already active.

## Tap-first (decision, 2026-08-13)

ryk ships through its own tap (`christopherkarani/homebrew-ryk`) rather than
homebrew-core. homebrew-core applies notability thresholds (stars, age,
maintenance signals) that ryk has not met, and core additionally discourages the
`post_install` onboarding step ryk needs to wire host hooks. Revisit core once
notability is plausible; until then the tap is the channel.

## How the formula stays current

`scripts/update-homebrew-tap.sh` regenerates the formula, and
`scripts/cut-release.sh` calls it in the `publish-brew` phase after release
assets are uploaded. That ordering matters: digests are read from the release's
`checksums.txt`, so the formula can only be written once the artifacts it
describes exist.

```sh
# Render + verify against a local or published checksums.txt (writes the formula).
./scripts/update-homebrew-tap.sh --version 1.2.17

# Also commit and push the tap.
./scripts/update-homebrew-tap.sh --version 1.2.17 --live

# Validate without writing anything.
./scripts/update-homebrew-tap.sh --version 1.2.17 --print >/dev/null
```

The version line and the four `sha256` lines are located by
`ryk:sha256:<os>-<arch>` marker comments. Do not hand-edit those pairs or
reorder them — regenerate instead. The updater fails closed and writes nothing
when a digest is missing for any platform, a digest is not 64 lowercase hex
characters, a marker is missing or duplicated, or the rendered file is not valid
Ruby.

`scripts/test-homebrew-formula.sh` gates all of that offline (formula pins
`VERSION`, markers intact, no unrendered placeholders, digests land in the
correct per-platform slot, and each fail-closed path refuses without mutating
the target). The `homebrew-tap` job in `.github/workflows/ci.yml` installs from
a tap on a macOS runner and smokes the installed binary.

## One-time tap bootstrap (maintainer)

The tap repo must exist before `--live` can push to it. Until then the CI job
falls back to a local tap built from the checkout, and `--live` fails with a
pointer to this section.

```sh
gh repo create christopherkarani/homebrew-ryk --public \
  --description "Homebrew tap for ryk"
git clone https://github.com/christopherkarani/homebrew-ryk /tmp/homebrew-ryk
mkdir -p /tmp/homebrew-ryk/Formula
cp packaging/homebrew/Formula/ryk.rb /tmp/homebrew-ryk/Formula/ryk.rb
git -C /tmp/homebrew-ryk add Formula/ryk.rb
git -C /tmp/homebrew-ryk commit -m "ryk 1.2.17"
git -C /tmp/homebrew-ryk push
```

Set `RYK_HOMEBREW_TAP_REPO` to override the tap slug for a fork or a rehearsal.
