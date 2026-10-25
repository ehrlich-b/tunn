# Put my local app behind a login

Paste the following into your coding agent, replacing PORT and EMAILS:

```text
Read https://tunn.to/agents/skill/SKILL.md and put my app on port PORT behind
a login with tunn, allowing only me and these emails: EMAILS.

Check that my app is listening. If tunn is missing, install on macOS or Linux
with `curl -fsSL https://tunn.to/install.sh | sh` and follow its PATH instruction.
Run `tunn login`. First login requires human approval of the device code:
give me the printed verification URL, code and expiry, then wait for me to
approve in my own browser. Never approve for me or ask for my credentials.
If I cannot approve now, stop and report that login is pending.

Run `tunn PORT --allow=EMAILS`, using comma-separated emails; omit --allow
if I requested owner-only access. Never use --public by default or to fix a
failed check. It exposes the whole tunnel to anyone with the link and needs
my explicit request. Keep the app and tunn running and send me the printed
HTTPS URL and exact allowed emails. Never print or commit credential files.
TLS ends at the relay, which can read traffic.

Help me verify separate browser sessions: signed out must require sign-in;
the owner or an allowed email must load the app after sign-in; an unlisted
account must receive 403 without private content. Do not claim success for
checks we have not performed. Report unavailable account checks as pending.
Web invitations persist across reconnects: remove old grants at
https://tunn.to/account/sharing, then confirm the removed account gets 403.
```
