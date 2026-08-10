class Ryk < Formula
  desc "Local runtime firewall for AI agents"
  homepage "https://github.com/christopherkarani/ryk"
  version "1.2.12"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/christopherkarani/ryk/releases/download/v#{version}/ryk-v#{version}-darwin-arm64.tar.gz"
      sha256 "{{DARWIN_ARM64_SHA256}}"
    else
      url "https://github.com/christopherkarani/ryk/releases/download/v#{version}/ryk-v#{version}-darwin-amd64.tar.gz"
      sha256 "{{DARWIN_AMD64_SHA256}}"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/christopherkarani/ryk/releases/download/v#{version}/ryk-v#{version}-linux-arm64.tar.gz"
      sha256 "{{LINUX_ARM64_SHA256}}"
    else
      url "https://github.com/christopherkarani/ryk/releases/download/v#{version}/ryk-v#{version}-linux-amd64.tar.gz"
      sha256 "{{LINUX_AMD64_SHA256}}"
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

  def post_install
    ohai "Running ryk onboarding to wire host hooks..."
    user_bins = %w[
      .local/bin
      .npm-global/bin
      .bun/bin
      .cargo/bin
      .grok/bin
      .codex/bin
    ].map { |path| File.join(Dir.home, path) }
    onboard_env = {
      "RYK_RESOURCE_ROOT" => (share/"ryk/current").to_s,
      "PATH" => ([bin.to_s] + user_bins + [ENV.fetch("PATH", "")]).join(File::PATH_SEPARATOR),
    }
    success = Dir.chdir(Dir.home) do
      system onboard_env, "#{bin}/ryk", "doctor", "--fix", "--from-install"
    end
    odie "ryk was installed, but protection setup failed; resolve the reported host error and reinstall ryk" unless success
  end

  def caveats
    <<~EOS
      ryk setup ran automatically. Its onboarding result reports whether active
      protection was verified or whether a host still needs attention.

      Off-ramp (remove host hooks):
        ryk stop
    EOS
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/ryk --version")
    system "#{bin}/ryk", "doctor"
    system "#{bin}/ryk", "packs", "--help"
    system "#{bin}/ryk", "plugin", "doctor", "hermes", "--json"
    system "#{bin}/ryk", "redteam", "--ci"
  end
end
