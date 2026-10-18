# Installation assets — operator release actions required

After the approved CLI release is public and `/install.sh` downloads that
release, promote this macOS/Linux command:

```bash
curl -fsSL https://tunn.to/install.sh | sh
```

Then `tunn login`. If needed: `export PATH="$HOME/.local/bin:$PATH"`.
The downloader verifies SHA256SUMS and atomically replaces an installed binary. Use the [install/recovery path](../install-recovery.md) when
checked artifacts and rollback matter. A website deploy alone does not publish
a CLI release. Do not market the new `http` alias through an old binary.

From the reviewed checkout, prepare a **local** Homebrew tap on macOS/Linux:

```bash
brew tap-new tunn/revenue-local
cp packaging/homebrew/tunn.rb "$(brew --repository tunn/revenue-local)/Formula/tunn.rb"
brew install --build-from-source tunn/revenue-local/tunn
```

The draft formula pins GitLab tag `v0.1.4` and its exact reviewed source revision
`b2d0525df62c517ce7005977505c7af05d4033d3`. Install only after that tag and
revision are public on GitLab and distribution is approved. The release staging
script generates a matching formula for any subsequently selected tag. See
[release preparation](../download-mirror.md).
This creates a local tap, without publishing a repository or creating an
account. Current Homebrew requires a formula to live in a tap; a bare .rb path
is not a reliable install command. It does not claim an existing public tap or
Homebrew/core package. operator must run
`brew test tunn/revenue-local/tunn` and validate `tunn http --help` and `tunn mcp --help` on native
macOS and Linux. An approved license text is missing from the baseline; don't
invent an MIT SPDX label or submit to core before the maintainer resolves packaging.

Build locally without a published Git ref:

```bash
go build -trimpath -o /tmp/tunn-revenue-cli . && /tmp/tunn-revenue-cli --help
```

For the actual service install and recovery flow use the linked guide, not an
unpublished `brew install tunn` or nonexistent tap. The formula's explicit Git
revision follows [Homebrew's cookbook](https://docs.brew.sh/Formula-Cookbook)
and [tap instructions](https://docs.brew.sh/How-to-Create-and-Maintain-a-Tap)
(fetched 2026-10-11); native Homebrew acceptance is still operator work.
