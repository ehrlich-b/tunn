# Release download mirror

Set `TUNN_DOWNLOAD_DIR` to a staged release tree to serve `/dl/` from the relay.
An unset directory disables downloads. The Docker image copies its ignored
`downloads/` directory to `/app/downloads`. Only recognized release assets and
feed files can be served; symlinks and directory listings are refused.

Use immutable `<tag>/tunn-{linux,darwin}-{amd64,arm64}` paths, with `checksums.txt`
and the equivalent `SHA256SUMS`. Stage all files before replacing `latest.json`.
The feed uses the GitHub release shape with a stable `tag_name`; the installer
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
