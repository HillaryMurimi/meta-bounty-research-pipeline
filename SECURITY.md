# Security policy and responsible disclosure

## Do not publish real vulnerabilities here

This repository is **public**. Do not create a GitHub issue, discussion, commit or pull request containing live exploit steps, private bounty submissions, access tokens, real user data, passwords, cookie values, personal data, sensitive URLs or unpublished affected code.

Report Meta product vulnerabilities through the [official Meta Bug Bounty programme](https://bugbounty.meta.com/) after verifying current programme policies. For vulnerabilities **in this repository's tool itself**, first contact the repository maintainer privately through a suitable confidential channel; do not post sensitive details in a public issue.

## Supported use

- Offline inspections of your own or explicitly authorised source code.
- Synthetic fixtures and controlled proof-of-concept projects.
- Human-reviewed, non-destructive demonstrations after checking specific authorisation.

## Prohibited assumptions

- A published dataset or public endpoint is **not** blanket permission for scraping, automated scanning or access to users' information.
- Public source code is not automatically eligible for Meta rewards.
- A suspicious static-analysis pattern is **not** proof of a vulnerability.
- Marking a human review checkbox does not create real authorisation.

## Handling evidence

Keep raw evidence and review approvals in secure private storage. Redact personal information; use test accounts if expressly permitted. The `out/` folder and local approval files are ignored by Git; always review `git diff --cached` for accidental secrets before pushing.

## Dependency and workflow principles

The Meta-specific module uses Python's standard library and makes **no network calls**. CI must not request Meta credentials or execute live scans. Contributions that add network-enabled functionality require explicit design review, deny-by-default controls and evidence that testing is authorised.
