#!/usr/bin/env python3
"""Build a tagged local download tree and GitLab release request; never upload."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

REPO = Path(__file__).resolve().parents[1]
PROJECT = "https://gitlab.com/ehrlich-b/tunn"
PACKAGE_BASE = "https://gitlab.com/api/v4/projects/ehrlich-b%2Ftunn/packages/generic/tunn"
ASSETS = ("tunn-linux-amd64", "tunn-linux-arm64", "tunn-darwin-amd64", "tunn-darwin-arm64")


def run(*args, cwd=REPO, env=None):
    return subprocess.check_output(["nice", "-n", "10", *map(str, args)], cwd=cwd, env=env, text=True).strip()


def formula(tag, source):
    return f'''# Local tap draft; publish and qualify the exact GitLab tag before installation.
class Tunn < Formula
  desc "HTTPS tunnels for local MCP tools and webhooks"
  homepage "https://tunn.to"
  url "{PROJECT}.git", tag: "{tag}",
      revision: "{source}"
  version "{tag[1:]}"

  depends_on "go" => :build

  def install
    system "go", "build", "-trimpath",
           "-ldflags=-s -w -X main.version={tag}", "-o", bin/"tunn", "."
  end

  test do
    assert_equal "tunn {tag}\\n", shell_output("#{{bin}}/tunn --version")
    assert_match "tunn http", shell_output("#{{bin}}/tunn http --help 2>&1")
    assert_match "tunn mcp", shell_output("#{{bin}}/tunn mcp --help 2>&1")
  end
end
'''


def stage(tag, source, output):
    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", tag):
        raise ValueError("only stable vMAJOR.MINOR.PATCH tags may produce latest.json")
    if not re.fullmatch(r"[0-9a-f]{40}", source):
        raise ValueError("source must be the full selected commit SHA")
    if run("git", "rev-parse", "--verify", f"refs/tags/{tag}^{{commit}}") != source:
        raise ValueError("tag does not resolve to the selected source")
    output = output.absolute()
    # A fresh destination makes versioned assets immutable; never overwrite a release.
    output.mkdir(parents=True, exist_ok=False)
    checkout = output / "source"
    run("git", "clone", "--no-hardlinks", "--no-checkout", REPO, checkout)
    run("git", "checkout", "--detach", source, cwd=checkout)
    downloads = output / "downloads"
    release = downloads / tag
    release.mkdir(parents=True)
    records = []
    for name in ASSETS:
        _, system, arch = name.split("-")
        env = dict(os.environ, CGO_ENABLED="0", GOOS=system, GOARCH=arch)
        target = release / name
        run("go", "build", "-p", "2", "-trimpath", "-buildvcs=true",
            "-ldflags", f"-s -w -X main.version={tag}", "-o", target, ".", cwd=checkout, env=env)
        provenance = run("go", "version", "-m", target)
        if f"vcs.revision={source}" not in provenance or "vcs.modified=false" not in provenance:
            raise ValueError(f"missing clean source provenance: {name}")
        (output / f"{name}.build.txt").write_text(provenance + "\n")
        records.append({"name": name, "sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
                        "size": target.stat().st_size, "url": f"{PACKAGE_BASE}/{tag}/{name}"})
    sums = "".join(f"{item['sha256']}  {item['name']}\n" for item in records)
    for name in ("SHA256SUMS", "checksums.txt"):
        (release / name).write_text(sums)
    license_path = checkout / "LICENSE"
    license_ready = license_path.is_file() and bool(license_path.read_bytes().strip())
    manifest = {"tag": tag, "source_commit": source, "source_url": PROJECT + ".git",
                "builder_commit": run("git", "rev-parse", "HEAD"),
                "license_file_present": license_ready,
                "publication_requires": ["maintainer-approved distribution rights and full license text",
                                         "approved protected tag reachable on GitLab",
                                         "owner credentials and immutable package settings",
                                         "logged-out downloads and native OS qualification"],
                "assets": records}
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    (output / "tunn.rb").write_text(formula(tag, source))
    names = (*ASSETS, "SHA256SUMS", "checksums.txt")
    request = {"name": f"tunn {tag}", "tag_name": tag,
               "description": f"Source {source}. Publish only after distribution and native acceptance.",
               "assets": {"links": [{"name": name, "url": f"{PACKAGE_BASE}/{tag}/{name}",
                                      "direct_asset_path": f"/{name}", "link_type": "package"} for name in names]}}
    (output / "gitlab-release.json").write_text(json.dumps(request, indent=2) + "\n")
    feed = {"tag_name": tag, "draft": False, "prerelease": False,
            "assets": [{"name": name, "browser_download_url": f"https://tunn.to/dl/{tag}/{name}"} for name in names]}
    # Feed is the final write, only after four builds, both checksum manifests and metadata.
    (downloads / "latest.json").write_text(json.dumps(feed, indent=2) + "\n")
    run("go", "run", "-p", "2", "./cmd/check-downloads", downloads)
    print(f"PASS: staged {tag} from {source}; local preparation only; publication requires owner acceptance")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        stage(args.tag, args.source, args.output)
    except (ValueError, FileExistsError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"Release staging refused: {error}\n")


if __name__ == "__main__":
    main()
