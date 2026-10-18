# Local tap draft; publish and qualify the exact GitLab tag before installation.
class Tunn < Formula
  desc "HTTPS tunnels for local MCP tools and webhooks"
  homepage "https://tunn.to"
  url "https://gitlab.com/ehrlich-b/tunn.git", tag: "v0.1.4",
      revision: "b2d0525df62c517ce7005977505c7af05d4033d3"
  version "0.1.4"

  depends_on "go" => :build

  def install
    system "go", "build", "-trimpath",
           "-ldflags=-s -w -X main.version=v0.1.4", "-o", bin/"tunn", "."
  end

  test do
    assert_equal "tunn v0.1.4\n", shell_output("#{bin}/tunn --version")
    assert_match "tunn http", shell_output("#{bin}/tunn http --help 2>&1")
    assert_match "tunn mcp", shell_output("#{bin}/tunn mcp --help 2>&1")
  end
end
