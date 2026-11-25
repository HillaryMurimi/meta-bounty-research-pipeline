# Contributing

Thank you for improving responsible, evidence-driven security research.

## Maintainer policy

The public repository is maintained on **`main` only**. This setup does not create or push feature branches. Keep commits focused, verify tests before pushing, and never commit secrets, credentials, raw private reports or unredacted evidence.

## Requirements

1. Add a deterministic local fixture for new detection patterns.
2. Keep `meta_workflow.py` offline by default; never enable production scans under the sample Meta policy.
3. Do not label findings as confirmed without reproducible validation and programme scope review.
4. Keep `README.md` and safety documentation consistent with the implementation.
5. Run `python -m unittest discover -s tests -v` and verify successful results.
6. Review `git diff --cached` before any public commit.

Please use private communication for genuine undisclosed security vulnerabilities; do not open public GitHub issues with exploit details.
