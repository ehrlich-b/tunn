---
name: tunn
description: Share a preview, expose a port privately, or put a login on localhost with tunn and allow access by email.
---

# tunn

Publish a local HTTP app at an HTTPS URL with account login. Access is
owner-only by default. Keep the app and publisher running. TLS ends at the
relay, which can read traffic.

## Install this skill

From the project root, choose the directory for your coding agent:

| Agent | Project directory |
| --- | --- |
| [Claude Code](https://code.claude.com/docs/en/skills) | `.claude/skills/tunn` |
| [Codex](https://learn.chatgpt.com/docs/build-skills) | `.agents/skills/tunn` |
| [Cursor](https://cursor.com/docs/skills) | `.cursor/skills/tunn` |

For example, for Codex (substitute the directory above for another agent):

```sh
mkdir -p .agents/skills/tunn
curl -fsSL https://tunn.to/agents/skill/SKILL.md -o .agents/skills/tunn/SKILL.md
```

Alternatively, copy `skills/tunn/SKILL.md` from the tunn repository into the
chosen directory as `SKILL.md`. Start a new agent session and ask it to share
a preview of your app on its actual port with the intended email addresses.

## Install tunn and authorize

Check whether `tunn` is already installed. On macOS or Linux, install if needed:

```sh
curl -fsSL https://tunn.to/install.sh | sh
tunn login
```

First login requires human approval of the device code. Give the person the
printed verification URL, code and expiry; wait for them to approve in their
own browser. Never approve on their behalf or request their credentials.
If no person can approve, stop and report that login is pending.

Use the same OS user and `TUNN_CONFIG_DIR` for login and publishing. Saved
credentials renew without stdin; exit 78 requires a new login. Never print or
commit credential files.

## Publish privately

Use the app's actual listening port and the requested emails. For example:

```sh
tunn 3000 --allow=alex@example.com,sam@example.com
```

Omit `--allow` for owner-only access. Never use `--public` by default or to fix
a failed access check. It makes the whole tunnel accessible to anyone with
the link; use it only when the person explicitly requests public access.

Read the assigned HTTPS URL from output; do not invent a hostname. For
`tunn 3000 --json`, use the `url` field in the `route` event. Send the URL and
exact allowed emails to the person. Recipients install nothing and sign in.
Keep app-level authentication and origin restrictions in place.

Web invitations persist across reconnects. Manage and revoke them at
https://tunn.to/account/sharing; restarting with a shorter `--allow` list does
not remove existing grants.

## Verify access

Ask the person to check separate browser sessions:

1. Signed out: require sign-in before showing the app.
2. Owner or an allowed email: the app loads after sign-in.
3. An unlisted account: expect 403 and no private app content.
4. After removing a web invitation: that account receives 403 on its next request.

Do not claim these checks passed without observing their results. If a test
account is unavailable, report the check as pending. Stop the publisher to end
app access. Report the printed URL, allowed emails, publisher status and checks.

For MCP commands and connector verification, read https://tunn.to/agents/SKILLS.md.
Full reference: https://tunn.to/agents. Plans and limits: https://tunn.to/pricing.
