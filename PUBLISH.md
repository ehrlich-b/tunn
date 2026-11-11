# Publish tunn v0.1.6 and qualify round r18

These are operator steps. Local preparation does not publish the client or
change the relay. Keep the existing v0.1.5 assets for rollback.

1. From the directory containing `release-stage/`, check all four binaries
   against the staged SHA256SUMS. From the source repository verify the tagged
   source bundle with `git bundle verify ../release-stage/tunn-v0.1.6.bundle`.
2. Copy the immutable version directory and the prepared feed to the mirror:
   ```sh
   scp -r release-stage/downloads/v0.1.6 forge:/work/lanes/release-mirror/tunn/downloads/
   scp release-stage/downloads/latest.v0.1.6.json forge:/work/lanes/release-mirror/tunn/downloads/
   ```
3. On forge, before selecting the new feed, verify the copied version directory:
   ```sh
   cd /work/lanes/release-mirror/tunn/downloads/v0.1.6
   sha256sum --check SHA256SUMS
   cmp SHA256SUMS checksums.txt
   ```
   Compare all four hashes with the prepared manifest. Preserve the current
   `downloads/latest.json` as the rollback feed, then atomically select the
   copied `latest.v0.1.6.json` as `downloads/latest.json`.
4. Round r18 must use this mirror as its download input, run the download-tree
   validator before publication, and preserve the current relay configuration.
   Publish the immutable v0.1.6 assets before switching the public latest feed.
5. Round r18 must verify `downloads/v0.1.6/SHA256SUMS` against all four published
   binaries, confirm `checksums.txt` is identical, and confirm `latest.json`
   says `v0.1.6` with the four binary URLs and both checksum URLs.
   From an empty HOME, run the public installer and confirm `tunn version`
   prints `tunn v0.1.6`. With a Free account already keeping one name, start a
   second name: it must run and show the Pro $5 notice and monthly checkout link.
   Record the published feed, hashes, installed version and notice transcript.
6. If any published check fails, restore the saved latest feed, verify a fresh
   installation selects its prior version, and retain both version directories.
   No price, plan, limit or legal-copy changes are part of this publication.
