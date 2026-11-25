#!/usr/bin/env python3
"""Meta-specific OFFLINE research workflow: no network, no code execution, no submission."""
from __future__ import annotations
import argparse
import datetime as dt
import hashlib
import json
import pathlib
import re
import sys
from collections import defaultdict

MAX_FILES = 1500
MAX_FILE_BYTES = 1_000_000
EXCLUDE = {'.git', '.venv', 'venv', 'node_modules', 'dist', 'build', '__pycache__', '.next'}
EXTENSIONS = {'.py', '.js', '.jsx', '.ts', '.tsx'}
# These are investigation leads. None establish exploitability or a payout.
RULES = (
    ('PY-EXEC', 'python_dynamic_execution', '.py', re.compile(r'\b(?:eval|exec)\s*\('), 'Investigate whether untrusted input can reach dynamic execution.'),
    ('PY-SHELL', 'python_shell_true', '.py', re.compile(r'\b(?:subprocess\.(?:run|Popen|call|check_output)|os\.system)\s*\([^\n]*\bshell\s*=\s*True'), 'Investigate whether a command is affected by untrusted input.'),
    ('PY-TLS', 'python_tls_verification_disabled', '.py', re.compile(r'\bverify\s*=\s*False\b'), 'Check whether a network request disables TLS validation.'),
    ('PY-PICKLE', 'python_pickle_deserialisation', '.py', re.compile(r'\bpickle\.loads?\s*\('), 'Review provenance and trust boundary of deserialised data.'),
    ('JS-EVAL', 'javascript_dynamic_execution', '.js,.jsx,.ts,.tsx', re.compile(r'\b(?:eval|new\s+Function)\s*\('), 'Review input reachability and the call context.'),
    ('JS-HTML', 'html_sink', '.js,.jsx,.ts,.tsx', re.compile(r'\b(?:innerHTML\s*=|dangerouslySetInnerHTML\s*[:=])'), 'Review sanitisation and context for an HTML insertion sink.'),
)


def timestamp():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_workspace(path: pathlib.Path):
    root = path.expanduser().resolve(strict=True)
    if not root.is_dir():
        raise ValueError('workspace must be an existing local directory')
    return root


def load_meta_policy(path: pathlib.Path):
    obj = json.loads(path.read_text(encoding='utf-8'))
    if obj.get('programme') != 'Meta Bug Bounty':
        raise ValueError('programme must be Meta Bug Bounty')
    if obj.get('live_testing_approved') is not False:
        raise ValueError('Meta workflow must explicitly disable live testing')
    if obj.get('network_access') is not False:
        raise ValueError('Meta workflow must explicitly disable network access')
    if obj.get('auto_submit') is not False:
        raise ValueError('auto_submit must be false')
    if obj.get('scope_status') != 'unverified':
        raise ValueError('starter policy must not pre-certify reward eligibility')
    return obj


def scan(path: pathlib.Path, policy: dict) -> dict:
    root = canonical_workspace(path)
    results, hashes, skipped = [], {}, []
    considered = 0
    for file in sorted(root.rglob('*')):
        if any(part in EXCLUDE for part in file.relative_to(root).parts):
            continue
        if file.is_symlink() or not file.is_file() or file.suffix.lower() not in EXTENSIONS:
            continue
        considered += 1
        if considered > MAX_FILES:
            raise ValueError('file limit reached; narrow your local source-code workspace')
        rel = file.relative_to(root).as_posix()
        if file.stat().st_size > MAX_FILE_BYTES:
            skipped.append({'path': rel, 'reason': 'file_size_limit'})
            continue
        raw = file.read_bytes()
        hashes[rel] = sha256(raw)
        lines = raw.decode('utf-8', errors='replace').splitlines()
        for line_no, line in enumerate(lines, start=1):
            if len(line) > 6000:  # never parse unbounded minified lines
                continue
            for rid, kind, ext, pattern, reason in RULES:
                if file.suffix.lower() not in ext.split(','):
                    continue
                if pattern.search(line):
                    # Do not embed source lines in evidence: source may contain secrets.
                    results.append({
                        'finding_id': f'R{len(results)+1:04d}',
                        'rule_id': rid, 'kind': kind, 'path': rel, 'line': line_no,
                        'file_sha256': hashes[rel], 'line_sha256': sha256(line.encode()),
                        'reason_for_review': reason,
                        'status': 'needs_manual_validation', 'confirmed_vulnerability': False,
                        'evidence_type': 'local_source_code_pattern',
                    })
    return {
        'schema_version': 2, 'generated_utc': timestamp(),
        'programme': 'Meta Bug Bounty', 'scope_status': policy['scope_status'],
        'analysis': 'local_static_source_inspection_only', 'network_requests': 0,
        'source_root_name': root.name, 'files_considered': considered,
        'files_hashed': len(hashes), 'source_hashes': hashes,
        'candidates': results, 'skipped_files': skipped,
        'disclaimer': 'Matches are not verified vulnerabilities, programme eligibility, severity or bounty awards.'
    }


def save_scan(scan_data: dict, path: pathlib.Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(scan_data, indent=2) + '\n', encoding='utf-8')
    return path


def prepare_report(evidence: dict, review: dict, finding_id: str) -> str:
    found = next((f for f in evidence.get('candidates', []) if f['finding_id'] == finding_id), None)
    if found is None:
        raise ValueError('finding ID not in evidence')
    if evidence.get('programme') != 'Meta Bug Bounty' or evidence.get('network_requests') != 0:
        raise ValueError('expected offline Meta research evidence')
    gate = ('meta_scope_verified', 'explicit_test_authorisation_verified',
            'manual_reproduction_confirmed', 'real_security_impact_confirmed',
            'nonduplicate_reviewed', 'operator_approved_report')
    if any(review.get(x) is not True for x in gate):
        missing = [x for x in gate if review.get(x) is not True]
        raise ValueError('human approval gate incomplete: ' + ', '.join(missing))
    for key in ('scope_policy_url', 'scope_evidence', 'reproduction_steps',
                'observed_result', 'expected_result', 'impact_statement', 'reviewer'):
        if not isinstance(review.get(key), str) or len(review[key].strip()) < 12:
            raise ValueError(f'missing substantive human review field: {key}')
    # Escaping any HTML embedded in the report reduces accidental rendering of supplied evidence.
    def plain(value):
        return str(value).replace('<', '&lt;').replace('>', '&gt;')
    lines = [
        '# Meta Bug Bounty — Human-Reviewed Draft', '',
        '**Not submitted. Eligibility and payout are determined by Meta.**', '',
        f'## Finding {finding_id} — {plain(found["kind"])}', '',
        f'- Source: `{plain(found["path"])}:{found["line"]}`',
        f'- Source file SHA-256: `{found["file_sha256"]}`',
        f'- Evidence line SHA-256: `{found["line_sha256"]}`',
        f'- Review candidate: {plain(found["reason_for_review"])}', '',
        '## Verified Scope', '',
        f'- Programme policy: {plain(review["scope_policy_url"])}',
        f'- Scope evidence: {plain(review["scope_evidence"])}', '',
        '## Minimal Reproduction (human verified)', '',
        plain(review['reproduction_steps']), '',
        '## Observed vs Expected', '',
        f'Observed: {plain(review["observed_result"])}', '',
        f'Expected: {plain(review["expected_result"])}', '',
        '## Demonstrated Security Impact', '',
        plain(review['impact_statement']), '',
        f'Human reviewer: {plain(review["reviewer"])}', '',
        '## Final operator check', '',
        '- [ ] Confirm all statements and remove credentials or personal data.',
        '- [ ] Ensure current Meta programme scope, exclusions and severity criteria match this issue.',
        '- [ ] Submit manually through the official Meta Bug Bounty portal.', '',
    ]
    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(description='OFFLINE Meta Bug Bounty research organiser')
    sub = parser.add_subparsers(dest='action', required=True)
    inspect = sub.add_parser('inspect', help='static scan local files; no network or execution')
    inspect.add_argument('--policy', type=pathlib.Path, required=True)
    inspect.add_argument('--workspace', type=pathlib.Path, required=True)
    inspect.add_argument('--output', type=pathlib.Path, required=True)
    report = sub.add_parser('draft', help='requires explicit signed human validation')
    report.add_argument('--evidence', type=pathlib.Path, required=True)
    report.add_argument('--review', type=pathlib.Path, required=True)
    report.add_argument('--finding', required=True)
    report.add_argument('--output', type=pathlib.Path, required=True)
    args = parser.parse_args()
    try:
        if args.action == 'inspect':
            policy = load_meta_policy(args.policy)
            output = save_scan(scan(args.workspace, policy), args.output)
            print('OFFLINE: no external targets were contacted. Candidate results: ' + str(len(json.loads(output.read_text())['candidates'])))
            print('Evidence: ' + str(output))
        else:
            evidence = json.loads(args.evidence.read_text(encoding='utf-8'))
            review = json.loads(args.review.read_text(encoding='utf-8'))
            rendered = prepare_report(evidence, review, args.finding)
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(rendered, encoding='utf-8')
            print('Human-reviewed report draft: ' + str(args.output))
            print('Manual submission only; no report was sent.')
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        parser.error(str(exc))

if __name__ == '__main__':
    main()
