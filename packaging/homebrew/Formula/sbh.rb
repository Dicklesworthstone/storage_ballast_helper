class Sbh < Formula
  desc "Disk-pressure defense system for AI coding workloads"
  homepage "https://github.com/Dicklesworthstone/storage_ballast_helper"
  license "MIT"

  depends_on :macos

  # Release automation copies this skeleton into Dicklesworthstone/homebrew-sbh
  # and replaces both placeholder checksums before opening the tap PR.
  on_macos do
    on_arm do
      url "https://github.com/Dicklesworthstone/storage_ballast_helper/releases/download/v0.4.8/" \
          "sbh-v0.4.8-aarch64-apple-darwin.tar.xz"
      # REPLACE_WITH_AARCH64_APPLE_DARWIN_SHA256
      sha256 "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    end

    on_intel do
      url "https://github.com/Dicklesworthstone/storage_ballast_helper/releases/download/v0.4.8/" \
          "sbh-v0.4.8-x86_64-apple-darwin.tar.xz"
      # REPLACE_WITH_X86_64_APPLE_DARWIN_SHA256
      sha256 "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    end
  end

  def install
    bin.install "sbh"
  end

  def post_install
    system bin/"sbh", "setup", "--verify", "--bin-dir", bin
  end

  service do
    run [opt_bin/"sbh", "daemon"]
    keep_alive crashed: true
    process_type :background
    throttle_interval 60
    environment_variables PATH: std_service_path_env
    log_path var/"log/sbh.log"
    error_log_path var/"log/sbh.err.log"
  end

  def caveats
    <<~EOS
      Finish interactive setup when you want shell PATH/completion changes:
        sbh setup --all --bin-dir #{HOMEBREW_PREFIX}/bin

      Start the daemon with Homebrew services:
        brew services start sbh

      On macOS, grant Full Disk Access to the installed sbh binary if scans need
      to inspect protected user locations:
        #{HOMEBREW_PREFIX}/bin/sbh doctor --pal
    EOS
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/sbh --version")
  end
end
