# tunn v0.1.6

Compared with v0.1.5:

- Starting a second named tunnel on Free now explains that the name will not
  be kept while offline. The tunnel still runs.
- The notice explains that Free keeps 1 name and Pro keeps 10, shows
  $5 a month or $48 a year, and links directly to monthly checkout and pricing.
- Reaching the Free limit of 5 running tunnels now gives plan guidance.
  JSON output includes the name notice and a stable tunnel-limit error code.
- Private web sharing failures give a usable command to grant account access,
  including explicit domain shares and safely quoted command arguments.

This client makes existing relay guidance visible. Prices, plans, limits and
legal wording are unchanged. Rerun install.sh to update an existing installation.
