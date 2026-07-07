class Arbitraitor < Formula
  desc "Policy-enforced download, inspection, provenance verification, and execution gate"
  homepage "https://github.com/arbsec/arbitraitor"
  version "nightly"
  license "MIT OR Apache-2.0"
  head "https://github.com/arbsec/arbitraitor.git", branch: "main"

  on_macos do
    on_arm do
      url "https://github.com/arbsec/arbitraitor/releases/download/nightly-latest/arbitraitor-aarch64-apple-darwin.tar.gz"
    end
  end

  on_linux do
    on_intel do
      url "https://github.com/arbsec/arbitraitor/releases/download/nightly-latest/arbitraitor-x86_64-unknown-linux-gnu.tar.gz"
    end

    on_arm do
      url "https://github.com/arbsec/arbitraitor/releases/download/nightly-latest/arbitraitor-aarch64-unknown-linux-gnu.tar.gz"
    end
  end

  def install
    bin.install "arbitraitor"
  end

  test do
    assert_match "arbitraitor", shell_output("#{bin}/arbitraitor version")
  end
end
