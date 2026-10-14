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

The installer tries a verified mirror bundle, then a complete GitHub bundle.
Failed downloads, missing manifests and checksum mismatches cannot overwrite an
existing install. Both sources unavailable produce one plain sentence. The
installer uses a temporary file and atomic rename and accepts a writable
`TUNN_INSTALL_DIR` (default `$HOME/.local/bin`), without automatically using sudo.
There is no tunn self-update command; rerun the installer to update.
