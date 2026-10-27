# Local release qualification

A local proposal does not create or approve a tag. From a clean committed checkout, run `python3 scripts/stage-release.py --proposed --tag v0.1.8 --source "$(git rev-parse HEAD)" --output /path/to/new/stage`, then `python3 scripts/check-release-contract.py /path/to/new/stage "$(git rev-parse HEAD)"`. The checker rebuilds each target from the selected commit and compares its bytes, in addition to checking the staged checksums and feed. Preserve the stage and build records for review.

Publication still requires an approved protected tag, distribution rights and license, native platform qualification, and hosted source and feed concordance. Local Linux execution or emulation does not supply those receipts.
