# Client Docker image

`Dockerfile.client` packages the CLI for `linux/amd64` and `linux/arm64`, using a
native build stage and Go cross-compilation. It is separate from the existing
relay `Dockerfile`. The runtime contains CA certificates and the tunn executable,
runs as UID/GID 10001, and stores login state in `/home/tunn/.tunn`. It starts the
executable directly so container stop signals reach tunn. The default command
is `--help`; it does not start a tunnel or sign in automatically.

## Local build

```sh
nice -n 10 docker buildx build --file Dockerfile.client --platform linux/amd64 --load -t tunn-client:local .
# Both architectures as a local OCI archive, without registry publication:
mkdir -p bin
nice -n 10 make client-image-local
```

A builder with the `docker-container` driver is needed if the local engine cannot
export OCI archives or build multi-platform images. Use the existing configured
builder, or create a dedicated local builder. This is not a cloud build.

## One-line quickstart

The registry image is a **publication candidate** until an operator publishes
and verifies it. There is no assumed `latest` image. For a local build set
`TUNN_IMAGE=tunn-client:local`; after publication use the immutable commit tag:

```sh
export TUNN_IMAGE='ghcr.io/ehrlich-b/tunn-client:sha-<published-full-commit-sha>'
```

First sign in with your own account using a Docker volume. Follow the browser
link printed by the CLI. Do not copy host credentials or embed a token in an
image. Keep this volume private; it contains the container's login credentials.

```sh
docker run --rm -it -v tunn-client-home:/home/tunn "$TUNN_IMAGE" login
```

Then, on **Linux**, for an application listening on host port 8080:

```sh
docker run --rm --init --network host -v tunn-client-home:/home/tunn "$TUNN_IMAGE" http 8080
```

The tunnel is private by default. Use `--allow=friend@example.com` for selected
browser access. Only add `--public` deliberately, such as for webhook callbacks;
keep application signature/auth checks enabled. No inbound port mapping is
required. Host networking gives the client access to host services.

Docker Desktop can instead reach a host application with this target:

```sh
docker run --rm --init -v tunn-client-home:/home/tunn "$TUNN_IMAGE" http http://host.docker.internal:8080
```

On Linux without host networking, add
`--add-host=host.docker.internal:host-gateway` and ensure the application listens
on an address reachable from the container bridge. For an application in
another container, join its user-defined network and target its service name.
`localhost` inside a bridged container refers to that container, not your laptop.

The scratch image has no shell, browser, Node or Python runtime. For stdio MCP
commands, build a derived image containing the required runtime/server, or run
MCP tooling outside this image. Browser login uses the printed URL. Don't use
`--insecure` for hosted relays. `docker stop` sends SIGTERM; tunn shuts down its
stream and exits. Reuse the volume on restart. Non-Docker mounted directories
must be private and writable by UID 10001; arbitrary `--user` overrides may fail.

## Prepared publication workflow

`.github/workflows/client-image.yml` runs only on manual `workflow_dispatch`.
It requires `make check`, `make vet` and a clean generated diff before publishing
both architectures to `ghcr.io/<repository>-client:sha-<full-commit-sha>`. It
requests registry write permission only in the publish job. Configure the
`client-image-release` environment with required reviewers, then an authorized
operator can dispatch the reviewed revision. The workflow includes provenance
and an SBOM. Make the package public and verify anonymous pulling and the two
architecture manifests before distributing the command. No workflow run,
registry login, upload or publication is implied by adding this file.

Multi-platform packaging follows [Docker's Go cross-compilation guide](https://docs.docker.com/build/building/multi-platform/)
and [GitHub Actions guide](https://docs.docker.com/build/ci/github-actions/multi-platform/).
Native ARM execution and hosted sign-in/tunnel acceptance still require an
operator with the relevant machine and account.
