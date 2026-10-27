# Recipient journey qualification

The question is whether the person opening a shared link can reach the app,
receive live updates, and lose access when the owner removes them. The local
journey extends the clean-browser sharing fixture to the staged release artifact.
It does not qualify a real phone, real recipient or app integration.

Build the selected committed source with `scripts/stage-release.py` into a fresh
external directory. Use a local stable-format fixture tag pointing at that exact
commit; never publish that tag or its feed. Install Python Playwright and its
Chromium runtime separately. Then, from the repository root:

```sh
nice -n 10 python3 scripts/stage-release.py --tag "$TAG" \
  --source "$(git rev-parse HEAD)" --output "$RELEASE"
nice -n 10 python3 scripts/integration-tests/recipient-journey.py \
  --release "$RELEASE" --output "$EVIDENCE"
nice -n 10 python3 scripts/integration-tests/recipient-journey.py \
  --verify "$EVIDENCE/report.json"
```

`RELEASE` and `EVIDENCE` must be outside the checkout; both destinations are fresh.
Use the Python environment containing Playwright; `--chromium` optionally pins
an installed executable. All listeners bind loopback. The relay and publisher
use production authentication/TLS configuration with a disposable trusted
certificate. Chromium pins that certificate's public key. Google consent,
token exchange and verified userinfo are mocked; PKCE and redirect binding are
checked by the external fixture. Browser contexts are empty, acquire ordinary
cookies, and receive no authorization bypass. This is Chromium viewport
emulation at 390 and 1440 pixels in light and dark color schemes, not iOS Safari or Android Chrome.

The report binds the source commit, binary checksum and screenshots. Required
cases cover owner-only default, anonymous return URL, uninvited and wrong-person
denials without origin requests, invitation through Share access, WebSocket
updates, revocation and stream cutoff within five seconds, denied fresh
upgrades, named reconnect preserving both revocation and active grants, and
publisher stop returning 503 and closing the stream. Captures include sharing
with 0, 1, 8 long email addresses and the existing 64-person resource bound.
The validator refuses missing, skipped or failed cases and changed artifacts.
Inspect both widths for readable sign-in, denial, sharing and offline states;
the validator rejects horizontal overflow as well as presentation evidence changes.
Private logs and the temporary account database contain fixture credentials.

## Physical owner checklist — pending

No participant contact is authorized by this checklist. An owner must perform
and record these checks before claiming real phone/recipient compatibility.
Record release commit/checksum, OS/browser/app versions, exact printed HTTPS
origin, identity, timestamps, outcome and redacted captures. Never record tokens.

| Client | Required owner-run checks | Evidence |
| --- | --- | --- |
| Physical iOS Safari | Open owner-only link signed out, sign in with exact invited identity, verify return URL, reload and live updates over cellular with Wi-Fi off; try a separate uninvited identity; revoke while connected and time closure ≤5s; retry HTTP and WebSocket after revocation; stop publisher and confirm offline. | PENDING |
| Physical Android Chrome | Repeat the same recipient journey on cellular with a separate browser identity; verify explicit sign-in/denial and no app content for the wrong person. | PENDING |
| Both physical phones | Keep live updates idle for 30 minutes, then interact; background/lock, sleep/wake and reconnect; restart the same named publisher and verify current grants/revocations; record disconnect and recovery times. | PENDING |
| Native Mac and Linux publisher/client | Install the exact staged architecture binary; verify login persistence, same named origin after reconnect, 30-minute idle and OS sleep/wake; repeat publisher-stop and credential rotation/revocation. | PENDING |
| Actual app on every claimed client | Configure its exact public origin allowlist, retain its own origin/token authentication, enter the actual app token privately and complete its normal pairing approval; verify live app interaction. For native WSS, confirm supported scoped edge headers separately from app credentials; rotate edge token and deny old HTTP/upgrades. | PENDING |

A localhost fixture does not prove cellular routing, Safari behavior, native
service management, long idle, real IdP mail ownership or actual app pairing.
The real-recipient owner gate remains open even when every automated case passes.
