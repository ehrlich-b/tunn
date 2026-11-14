# Sales release handoff

Bryan: review and land product changes on main before selecting a release. This
checkout is preparation, not a deployment receipt. The actual private round-script
path is unavailable and its interface is UNVERIFIED. Supply its real executable
path explicitly; no private machine path is inferred. Do not apply until its
interface below has been confirmed locally. No Windows or herder preset is needed.

For a relay-only documentation release, first obtain independent source approval
and land the selected source through the existing Desk integration route. That
route's actual land/deploy command and implementation are **UNVERIFIED** here,
as are the real round-script path and interface. The forge owner must supply a
hash-bound capture of the actual Desk project JSON, source and command route,
and the operator's prior immutable image/feed/tag receipts. Desk comparison,
`INSTALL.json` and one-click deployment remain blocked until those inputs exist.
Source preparation can finish before them; this handoff creates no ready
publishing control and makes no live-update claim. Do not bundle a new CLI
release with this copy change.

From the clean selected landed commit, retain outside the checkout:

- The prior immutable relay image (`registry/name@sha256:…`), prior feed JSON and
  its tag, observed by the operator. Keep the old image and immutable assets.
- Actual focused test receipts, JSON objects with `source` (full selected SHA),
  `command`, `selected_tests` (>0) and `exit_code` (0), plus original execution
  logs. Receipts are operator attestations, not signatures or automatic proof.
- Configuration **names only**, for example `TUNN_DOWNLOAD_DIR`. Never supply
  environment files or secret values to these tools.

```sh
python3 -B scripts/sales-release.py generate \
  --source "$(git rev-parse HEAD)" --main-ref refs/remotes/origin/main \
  --previous-image "$PRIOR_IMMUTABLE_IMAGE" --previous-tag "$PRIOR_TAG" \
  --previous-feed "$PRIOR_FEED_JSON" --config-name TUNN_DOWNLOAD_DIR \
  --receipt "$FRAGMENT_RECEIPT_JSON" --output "$NEW_MANIFEST_JSON"
```

Relay-only copy changes reuse the existing CLI feed/assets; omit `--client-stage`.
The prior feed digest must remain unchanged in this case. For an optional new
CLI, use [release staging and reproducibility](docs/release-qualification.md) first:
`stage-release.py` followed by `check-release-contract.py` for the selected source.
Pass `--client-stage "$VERIFIED_STAGE"` to capture the stage manifest, four assets,
checksum aliases and feed. The mirror validator runs locally. This generator
neither builds a new CLI nor copies anything into `downloads/`. Existing
[deploy integration](docs/download-mirror.md) still requires a valid download tree
at `make fly-deploy` and `REQUIRE_DOWNLOADS=1` in production. Publication of a new
CLI remains a separate approved operator action; retain the previous feed/tree.

Ready dry-run command (the required argument is the **actual** executable path):

```sh
python3 -B scripts/sales-release.py operate --round-script "${ROUND_SCRIPT:?set actual existing round-script path}" --manifest "${NEW_MANIFEST_JSON:?set selected manifest path}"
```

It validates local files and prints ordered commands with zero round-script calls.
After review, Bryan alone may repeat this command with `--operator-apply`.
The existing script must support this explicit interface, or be adapted and
reviewed by Bryan before use:

1. `ROUND_SCRIPT --check --manifest ABSOLUTE_JSON` is read-only, exits nonzero on
   failure and prints **only** JSON with `previous_image` and
   `previous_feed_sha256`. It must verify the current hosted image/feed against
   the prior state and the deployment inputs against the selected manifest.
2. `ROUND_SCRIPT --apply --manifest ABSOLUTE_JSON` deploys that exact relay SHA
   and optional staged client; it must recheck prior state immediately before
   mutating, retain rollback inputs and fail on drift. For relay-only releases it
   must preserve the feed and assets. Local checks run again after check mode.
3. `ROUND_SCRIPT --rollback --manifest ABSOLUTE_JSON` restores the recorded prior
   image and feed atomically, retaining all immutable versioned assets. The
   wrapper prints this command; it never invokes rollback automatically.

Do not log secret-bearing stdout/stderr. The wrapper suppresses check output and
verifies its two metadata fields before invoking apply. Pin and review the local
round script and protect all manifest/input files from concurrent writers; this
wrapper is an operator guard, not a sandbox for an untrusted executable.

After deployment, retain timestamped read-only results, observed source/image
and feed SHA256, not just this checklist. These checks are **UNVERIFIED** here:

```sh
scripts/smoke-prod.sh https://tunn.to
curl --disable --fail --silent --show-error https://tunn.to/ -o "$HOMEPAGE_RECEIPT"
curl --disable --fail --silent --show-error https://tunn.to/dl/latest.json -o "$FEED_RECEIPT"
curl --disable --fail --silent --show-error https://tunn.to/pricing -o "$PRICING_RECEIPT"
curl --disable --fail --silent --show-error https://tunn.to/status -o "$STATUS_RECEIPT"
sha256sum "$FEED_RECEIPT"
```

Compare homepage copy and pricing to the selected source without changing plans,
prices or limits. Compare the feed to the new staged digest, or recorded prior
digest for relay-only. Status must render and health/ready checks must pass;
unknown monitoring remains unknown. On mismatch, Bryan runs the printed rollback
command, confirms prior image/feed and repeats the read-only checks. A successful
local test or checklist does not establish hosted deployment success.
