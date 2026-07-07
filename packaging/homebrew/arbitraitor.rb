class Arbitraitor < Formula
  desc "Policy-enforced download, inspection, provenance verification, and execution gate"
  homepage "https://github.com/arbsec/arbitraitor"
  version "nightly"
  license "MIT OR Apache-2.0"
  head "https://github.com/arbsec/arbitraitor.git", branch: "main"

  # Builds from source via cargo. For pre-built binaries, see:
  # https://github.com/arbsec/arbitraitor/releases
  depends_on "rust" => :build

  def install
    system "cargo", "install", "--path", "crates/arbitraitor-cli", "--root", prefix
  end

  test do
    assert_match "arbitraitor", shell_output("#{bin}/arbitraitor version")
  end
end
