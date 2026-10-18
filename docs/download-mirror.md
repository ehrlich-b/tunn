# Release download mirror

Set `TUNN_DOWNLOAD_DIR` to a staged release tree to serve `/dl/` from the relay.
An unset directory disables downloads. The Docker image copies its ignored
`downloads/` directory to `/app/downloads`. Only recognized release assets and
feed files can be served; symlinks and directory listings are refused.

Use immutable `<tag>/tunn-{linux,darwin}-{amd64,arm64}` paths, with `checksums.txt`
and the equivalent `SHA256SUMS`. Stage all files before replacing `latest.json`.
The feed uses a stable `tag_name` and six mirror asset URLs; the installer
constructs binary/manifest paths from the selected base and tag.

`internal/downloads/base.txt` is the shared default download base. After changing
it, run `make generate-installer` to regenerate the root installer. The relay
renders the same template. `TUNN_DOWNLOAD_BASE` can override the absolute HTTPS
base on the relay or installer invocation; credentials, query strings and shell
metacharacters are not accepted in the server's base.

The installer uses only `https://tunn.to/dl` by default and verifies SHA256SUMS.
Failed downloads, missing manifests and checksum mismatches cannot overwrite an
existing install. Downloads use the configured HTTPS mirror. The installer uses a temporary
file and atomic rename and accepts a writable `TUNN_INSTALL_DIR`
(default `$HOME/.local/bin`), without automatically using sudo.
There is no tunn self-update command; rerun the installer to update.

Production `make fly-deploy` refuses before Fly runs unless `downloads/` has a
stable `latest.json`, four nonempty binaries per staged tag, matching SHA256SUMS
and its identical `checksums.txt` alias. Stage with
`cp -R /path/to/verified/downloads/. downloads/` and run `make check-downloads`.
Tags come from the staged tree; new CLI releases require no validator change.
Production Fly configuration must set `[build.args] REQUIRE_DOWNLOADS = "1"`
to enforce the same check on direct `fly deploy`. A plain Docker build and the
self-host `fly.toml.dist` leave this argument off.

For manual downloads, see [GitLab releases](https://gitlab.com/ehrlich-b/tunn/-/releases).

## Prepare a GitLab release locally

`scripts/stage-release.py` builds from an exact local tag/commit in an isolated
clean checkout. It never uploads, creates a remote tag, or contacts GitHub.
Populate the Go module cache first; use `GOPROXY=off GOSUMDB=off` to build offline.
The draft Homebrew source is `v0.1.4` at
`b2d0525df62c517ce7005977505c7af05d4033d3`; this is a prepared candidate,
not a claim that the tag exists remotely. Choose and review the tag before
publication. For that candidate, create the tag locally and prepare a new directory:

```sh
git tag v0.1.4 b2d0525df62c517ce7005977505c7af05d4033d3
GOPROXY=off GOSUMDB=off python3 scripts/stage-release.py \
  --tag v0.1.4 --source b2d0525df62c517ce7005977505c7af05d4033d3 \
  --output ../release-stage
cp -R ../release-stage/downloads/. downloads/
make check-downloads
python3 scripts/test_stage_release.py
python3 scripts/integration-tests/installer-offline.py \
  --release-tree ../release-stage/downloads --tag v0.1.4
```

The destination must be new: an existing tag tree is never overwritten.
All four binaries embed the version and Go VCS source revision; `*.build.txt`
records that provenance. `manifest.json` records sizes, SHA256 hashes, source
and builder commits, and unresolved publication prerequisites. `SHA256SUMS`
and `checksums.txt` are byte-identical. `latest.json` is written last.
Only stable `vMAJOR.MINOR.PATCH` tags are accepted; preview/draft tags cannot
change the stable feed. `.gitlab-ci.yml` runs the same preparation for stable
tags. Its temporary job artifacts are a handoff, never installer URLs.

Publication remains a separate owner action. Supply approved distribution rights
and full license text first; the manifest's file-presence flag alone is not legal
approval. Review the exact source/tag, native platform results and staged hashes.
Disable duplicate generic package uploads, protect release tags, and keep
versioned packages out of cleanup policies. With owner credentials, upload the
six files under `downloads/<tag>/` to the durable versioned package URLs in
`gitlab-release.json`; create the release with that request only after every
upload succeeds. No credential belongs in the manifest or a download URL.
Check each package and release link while logged out, comparing all bytes to
`manifest.json`. Stage and verify the immutable hosted `/dl/<tag>/` files before
replacing the hosted `latest.json` atomically. Keep previous version directories
for rollback and never replace their contents. The default installer uses this
hosted mirror, with no GitHub fallback. Native macOS/Linux Homebrew qualification
and public tag/package reachability remain owner checks.

GitLab contracts: [generic packages](https://docs.gitlab.com/user/packages/generic_packages/)
and [release links](https://docs.gitlab.com/user/project/releases/release_fields/).
