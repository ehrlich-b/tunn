# Local release qualification

A local proposal does not create or approve a tag. From a clean committed checkout, run `python3 scripts/stage-release.py --proposed --tag v0.1.8 --source "$(git rev-parse HEAD)" --output /path/to/new/stage`, then `python3 scripts/check-release-contract.py /path/to/new/stage "$(git rev-parse HEAD)"`. The checker rebuilds each target from the selected commit and compares its bytes, in addition to checking the staged checksums and feed. Preserve the stage and build records for review.

Publication still requires an approved protected tag, distribution rights and license, native platform qualification, and hosted source and feed concordance. Local Linux execution or emulation does not supply those receipts.


Installed Linux qualification must use an empty local HOME and config directory,
the real install.sh, and an offline transport restricted to the retained download
tree. Install a locally rebuilt baseline, update to the proposed candidate, then
select the baseline by its retained SHA256 and install it again for rollback.
Record every command, exit status, installed digest and --version output. This
baseline is a locally rebuilt rollback fixture, not a historical public package.
Reinstall the candidate before exercising its behavior.

Run the authentic recipient journey with both relay and publisher subprocesses
pointing to the installed candidate. Bind that installed digest to the staged
manifest and retain the command log. Replay owner-only, invitation, stranger,
revocation, active-stream cutoff, named reconnect and publisher-stop assertions,
including zero origin deltas for denied HTTP and upgrade requests. Exercise a
separate named public publisher anonymously as well. Keep mocked identity and
loopback transport explicitly labeled. Native Mac and remaining architectures
still require operator execution receipts.

Acceptance must execute these journeys and provenance checks again, rather than
check for the existence of their logs. The pre-review packet requires a clean
committed candidate, a complete evidence inventory and honest pending operator
receipts. Independent final review is supplied after readiness by the normal
build-review pipeline; it is not a builder readiness prerequisite. No local
qualification authorizes publication, sale or deployment. License, protected tag,
hosted concordance, payment and backup receipts remain pending with the operator.
