# ryk — local runtime firewall for AI coding agents.
#
# Tap-first by decision (2026-08-13): homebrew-core has notability thresholds ryk
# has not met yet, and a tap is what makes `brew upgrade` refresh managed host
# plugins the moment a release lands. See packaging/homebrew/README.md.
#
# The version line and the four sha256 lines below are rewritten by
# scripts/update-homebrew-tap.sh during cut-release (phase: publish-brew). Each
# sha256 is located by the `ryk:sha256:<os>-<arch>` marker on the line above it,
# so do not reorder, reformat, or hand-edit those pairs — regenerate instead.
class Ryk < Formula
  desc "Local runtime firewall for AI agents"
  homepage "https://github.com/christopherkarani/ryk"
  version "0.2.22"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/christopherkarani/ryk/releases/download/v#{version}/ryk-v#{version}-darwin-arm64.tar.gz"
      # ryk:sha256:darwin-arm64
      sha256 "3e3a34f356e652f4c0423dfcbaf1e6c151d26751fff07bae501ad5086f772cbb"
    else
      url "https://github.com/christopherkarani/ryk/releases/download/v#{version}/ryk-v#{version}-darwin-amd64.tar.gz"
      # ryk:sha256:darwin-amd64
      sha256 "4dea48e472818bb1e0248c519d3fdf24a279d2f62ba068205fc8805133341dff"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/christopherkarani/ryk/releases/download/v#{version}/ryk-v#{version}-linux-arm64.tar.gz"
      # ryk:sha256:linux-arm64
      sha256 "1fefe35c88c352b5f6b3707173c4d23227bee9ff2be90cb34aae941cd198ec41"
    else
      url "https://github.com/christopherkarani/ryk/releases/download/v#{version}/ryk-v#{version}-linux-amd64.tar.gz"
      # ryk:sha256:linux-amd64
      sha256 "0e9f2007893befb7f41567a9becd89caba173351721b4a6e9980fdb230065237"
    end
  end

  def install
    bin.install "bin/ryk"
    (share/"ryk/current").install "ryk-dashboard-ui"
    (share/"ryk/current").install "integrations"
    (share/"ryk/current").install "fixtures"
    (share/"ryk/current").install "schemas"
    (share/"ryk/current").install "policies"
    (share/"ryk/current").install "ryk-pi"
  end

  # Deliberately no post_install onboarding. Homebrew runs post_install inside
  # Dir.mktmpdir with HOME pointed at that temp directory (formula.rb
  # run_post_install), so `ryk doctor --fix --from-install` would wire hooks into a
  # directory brew then deletes — onboarding that silently protects nothing, while
  # the install output claimed it ran. Writing ryk's ~41 onboarding files into that
  # temp HOME also made brew's own cleanup fail (Errno::ENOTEMPTY), so
  # `brew install` exited non-zero after a successful install.
  #
  # Nothing gates the user's agents until they run the setup door themselves, so
  # caveats say exactly that rather than implying protection is already active.
  def caveats
    <<~EOS
      ryk is installed but NOT yet wired into any agent host. Run the setup door:

        ryk doctor --fix    # wire host hooks, seed the coding default policy
        ryk doctor          # per-host wiring and protection grade

      Run it again after `brew upgrade ryk` to refresh managed host plugins.

      Grades are literal: hook and wrapper are in-process gates, OS-enforced means
      a Seatbelt/Landlock attach succeeded for that session. Doctor probes report
      capability, not a live session claim.

      Off-ramp (remove host hooks):
        ryk stop
    EOS
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/ryk --version")

    # Fixture engine self-test; needs the runtime assets this formula installed.
    with_env(RYK_RESOURCE_ROOT: (share/"ryk/current").to_s) do
      system bin/"ryk", "redteam", "--ci"
    end
    system bin/"ryk", "packs", "--help"
  end
end
