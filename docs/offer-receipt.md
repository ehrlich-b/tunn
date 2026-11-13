# Authenticated offer observation

`scripts/verify-live-offer.py` reads public pages and downloads, then checks the
signed-out monthly link's login redirect. Its five `PASS:` lines establish no
authenticated second-name behavior, merchant identity, payment, or activation.
The public checker is unchanged. `scripts/check-offer-receipt.py` imports a
separate operator observation offline; it has no network or browser operation.

Copy `scripts/offer-receipt.template.json` outside the checkout. Empty fields
stay empty until observed. Record UTC `observed_at` as `YYYY-MM-DDTHH:MM:SSZ`,
the full deployed source head, client release `version`, and the SHA-256 of the
client actually used. Confirm those against independently retained release
records, not just this JSON. `public_report_sha256` is the digest of the exact
stdout from that public check for the same checkpoint (`--expect-version`
selects its release); retain its command, origin, UTC time and stdout separately.
The importer requires exactly the public checker's five successful lines.

Record an existing account's `Free` plan, an actually displayed second-name Pro
offer, `monthly` period, observed integer `amount_minor` in the currency's minor
unit, and uppercase three-letter currency. This is an observation, not a price
configuration change. Offer provenance is `private_window_and_client` plus the
SHA-256 of a retained redacted note/capture. The merchant must be confirmed by
comparing its displayed name to the existing merchant dashboard or an existing
redacted receipt. Record that business display name, `confirmed:true`, and
provenance source `existing_merchant_dashboard` or `existing_redacted_receipt`
with the SHA-256 of that separate redacted evidence. A public `/about` name,
login redirect, historical anecdote or synthetic fixture cannot supply this.
Never store account identifiers, session URLs, cookies, payment details or
credentials in the observation or its redacted evidence.

The importer requires HMAC-SHA256 operator sign-off over the whole observation,
including provenance hashes and public report digest. Use an independently
trusted, protected local key of at least 32 random bytes, supplied by file via
`--operator-key`; never include the key in JSON, source control or evidence.
Establish its trust outside the receipt. Do not use a key supplied by an
untrusted receipt sender. HMAC proves sign-off by a holder of that local key;
it cannot independently prove the truth of their observation. Only sign after
reviewing the redacted evidence and release records. Given an existing trusted
key, this local stdlib recipe signs a reviewed copy without printing the key:

```sh
python3 -B - /private/observation.json /private/operator-key <<'PY'
import importlib.util, json, pathlib, sys
spec = importlib.util.spec_from_file_location('receipt', 'scripts/check-offer-receipt.py')
receipt = importlib.util.module_from_spec(spec)
spec.loader.exec_module(receipt)
path = pathlib.Path(sys.argv[1])
data = json.loads(path.read_text(), object_pairs_hook=receipt.unique_object)
key = pathlib.Path(sys.argv[2]).read_bytes()
assert len(key) >= 32 and key != receipt.FIXTURE_KEY
data['signature'] = receipt.signature(data, key)
path.write_text(json.dumps(data, indent=2) + '\n')
PY
python3 -B scripts/check-offer-receipt.py \
  --observation /private/observation.json --public-report /private/public.txt \
  --expect-source-head "$DEPLOYED_HEAD" --expect-version "$CLIENT_VERSION" \
  --expect-client-sha256 "$CLIENT_SHA256" --operator-key /private/operator-key
```

Canonical signing bytes are `tunn-offer-observation-v1` followed by a NUL byte
and ASCII JSON with sorted keys, separators `(',', ':')`, `ensure_ascii=True`,
`allow_nan=False`, excluding only the top-level `signature`. The signature is
lowercase hex. An absent or wrong key, unsigned observation, missing field,
failed public check, or mismatched head/version/digest returns exit 1 and
`complete:false` with named `missing_fields`. Output contains status and field
names only; it does not copy input values. Exit 0 means a matching, signed
operator attestation for this limited scope, never a paid lifecycle receipt.
Retain the redacted inputs and evidence privately for later review.

`python3 -B scripts/check-offer-receipt.py --self-test` runs stdlib fixtures and
one loopback public-contract check. Every printed synthetic receipt retains
`SYNTHETIC_FIXTURE_ONLY` and `complete:false`, even with all fields and a valid
fixture signature. The built-in fixture key cannot certify a real observation,
even if its fixture label is removed. Tests never use operator credentials.

## Bryan's exact one-minute private-window checklist

Prepare beforehand: the already authorized Free account, an already signed-in
client with one kept name, a local app, independently checked release/digest
records, a blank observation copy, and existing redacted merchant evidence.
Do not create an account or purchase anything. This is a future manual check;
the offline tests make zero production requests.

1. **00–10 seconds:** open a private window and sign in to the existing Free
   account; confirm Free on Account. If sign-in takes longer, stop at 60 seconds
   and leave unobserved fields empty.
2. **10–25 seconds:** using that account's client and local app, run a second,
   distinct named preview. Observe the actual Pro offer and its monthly link;
   retain a redacted note with no account or preview identifiers.
3. **25–40 seconds:** open that offer link in the private window; inspect the
   displayed monthly amount and currency and merchant display. Do not enter
   payment details or click Pay/Subscribe. An error or login redirect leaves
   these observations missing.
4. **40–50 seconds:** compare the merchant display with the prepared existing
   dashboard/receipt evidence; confirm only an exact observed match. Record its
   redacted provenance digest; otherwise leave merchant confirmation empty.
5. **50–60 seconds:** close checkout without paying, stop the extra preview,
   and note UTC time and observed facts. At exactly 60 seconds stop. Later,
   hash the redacted notes, review and sign the JSON offline; import it with
   the independently checked head/version/client digest and public stdout.

If any step cannot finish within its slot, record only what was actually
observed. Missing observations remain incomplete. Existing prices, plans,
limits and legal text are unaffected. Real authenticated and merchant evidence
is still pending until Bryan performs and signs that observation.
