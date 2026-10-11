# DRAFT release asset. The pinned commit must be pushed by the coordinator first.
# Install through a local tap; see docs/revenue/install-one-liners.md.
class Tunn < Formula
  desc "HTTPS tunnels for local MCP tools and webhooks"
  homepage "https://tunn.to"
  url "https://github.com/ehrlich-b/tunn.git",
      revision: "1ae3c8dc59ce321132305a1321cf8d75bb8158cd"
  version "2026.10.11"

  depends_on "go" => :build

  def install
    system "go", "build", "-trimpath", "-ldflags=-s -w", "-o", bin/"tunn", "."
  end

  test do
    assert_match "tunn http", shell_output("#{bin}/tunn --help 2>&1")
  end
end
