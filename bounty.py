#!/usr/bin/env python3
"""Low-impact, explicit-authorisation-only web review automation.

Deliberately does not exploit, brute force, enumerate hidden paths, or submit reports.
"""
from __future__ import annotations
import argparse, datetime as dt, hashlib, json, pathlib, re, ssl, sys, time
from dataclasses import asdict, dataclass
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

AGENT = 'ScopedSecurityReview/0.1 (authorised passive review; contact in programme policy)'

@dataclass
class Observation:
    url: str
    status: int | None
    headers: dict
    accessed_utc: str
    sha256: str | None
    note: str
    evidence: list


def load_policy(path: pathlib.Path) -> dict:
    p = json.loads(path.read_text(encoding='utf-8'))
    if not p.get('program_name') or not p.get('authorisation_reference'):
        raise ValueError('Programme identity and authorisation reference are required')
    allowed = p.get('allowed_urls', [])
    if not allowed or len(allowed) > 25:
        raise ValueError('Provide 1–25 explicit, authorised HTTPS URLs')
    if p.get('max_requests_per_run', 0) < 1 or p['max_requests_per_run'] > 25:
        raise ValueError('Request cap must be 1–25')
    if p.get('min_delay_seconds', 0) < 2:
        raise ValueError('Minimum 2 seconds between requests required')
    for raw in allowed:
        parts = urlsplit(raw)
        if parts.scheme != 'https' or not parts.hostname or parts.username or parts.password or parts.fragment:
            raise ValueError('All allowlisted URLs must be explicit HTTPS addresses without credentials or fragments')
        if parts.hostname in {'localhost', '127.0.0.1', '::1'}: # localhost fixtures use tests, not live run
            raise ValueError('Loopback targets not permitted in live scanner')
    return p


def observations_for_response(url: str, status: int, headers: dict) -> list[dict]:
    """Configuration *review candidates*, not proven vulnerabilities."""
    found = []
    items = {k.lower(): v for k, v in headers.items()}
    if 'strict-transport-security' not in items:
        found.append({'kind': 'review.header.hsts_absent', 'detail': 'HSTS header not observed', 'severity': 'informational', 'confirmed_vulnerability': False})
    if 'content-security-policy' not in items:
        found.append({'kind': 'review.header.csp_absent', 'detail': 'CSP header not observed; may be intentional', 'severity': 'informational', 'confirmed_vulnerability': False})
    if 'x-content-type-options' not in items:
        found.append({'kind': 'review.header.nosniff_absent', 'detail': 'X-Content-Type-Options not observed', 'severity': 'informational', 'confirmed_vulnerability': False})
    return found


def assess_one(url: str, timeout: float = 12.0) -> Observation:
    """One HEAD, no redirects or body downloads. HTTP redirects are intentionally not followed."""
    from urllib.request import build_opener, HTTPHandler, HTTPSHandler, HTTPRedirectHandler
    from urllib.error import HTTPError

    class NoRedirect(HTTPRedirectHandler):
        def redirect_request(self, request, fp, code, msg, hdrs, newurl):
            return None

    opener = build_opener(HTTPHandler(), HTTPSHandler(), NoRedirect())
    now = dt.datetime.now(dt.timezone.utc).isoformat()
    request = Request(url, method='HEAD', headers={'User-Agent': AGENT, 'Accept': '*/*'})
    try:
        response = opener.open(request, timeout=timeout)
    except HTTPError as exc:
        response = exc
    except Exception as exc:
        return Observation(url, None, {}, now, None, 'Connection failed: ' + type(exc).__name__, [])
    with response:
        status = response.status
        headers = {k: v for k, v in response.headers.items() if k.lower() in {
            'content-security-policy', 'strict-transport-security', 'x-content-type-options',
            'x-frame-options', 'referrer-policy', 'cache-control', 'location', 'content-type'}}
    evidence = observations_for_response(url, status, headers) if 200 <= status < 400 else []
    digest = hashlib.sha256(json.dumps({'url': url, 'status': status, 'headers': headers}, sort_keys=True).encode()).hexdigest()
    return Observation(url, status, headers, now, digest, 'Headers-only review; no vulnerability exploitation', evidence)


def run(policy_path: pathlib.Path, output_dir: pathlib.Path, execute: bool):
    policy = load_policy(policy_path)
    urls = policy['allowed_urls'][:policy['max_requests_per_run']]
    if not execute:
        print('DRY RUN — no network traffic generated.')
        print(json.dumps({'program_name': policy['program_name'], 'authorisation_reference': policy['authorisation_reference'],
             'requests_planned': len(urls), 'request_method': 'HEAD', 'url_list': urls}, indent=2))
        return
    confirmation = policy.get('operator_approved_for_live_requests')
    if confirmation is not True:
        raise ValueError('Live requests require operator_approved_for_live_requests: true in the policy')
    output_dir.mkdir(parents=True, exist_ok=True)
    observations = []
    for i, url in enumerate(urls):
        if i: time.sleep(policy['min_delay_seconds'])
        observations.append(asdict(assess_one(url)))
    stamp = dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    path = output_dir / f'observations-{stamp}.json'
    path.write_text(json.dumps({'policy_name': policy['program_name'], 'scope_reference': policy['authorisation_reference'],
                                'observations': observations}, indent=2), encoding='utf-8')
    report = output_dir / f'review-{stamp}.md'
    lines = [f'# Preliminary review — {policy["program_name"]}', '',
        '**Status: Internal review only. No vulnerability has been validated. Do not submit as a bounty report.**', '',
        f'Programme authorisation: `{policy["authorisation_reference"]}`', '',
        '## Observations', '']
    for obs in observations:
        lines += [f'### {obs["url"]}', '', f'- HTTP status: {obs["status"]}',
                  f'- Observation time (UTC): {obs["accessed_utc"]}', f'- Evidence hash: `{obs["sha256"]}`',
                  f'- Header review candidates: {len(obs["evidence"])}', '']
        for e in obs['evidence']:
            lines.append(f'  - {e["kind"]}: {e["detail"]} (informational; not confirmed)')
        lines.append('')
    lines += ['## Human review gate', '', '- Confirm programme eligibility and scope.',
              '- Reproduce any actual security impact with authorisation and minimal interaction.',
              '- Ensure the report is not a duplicate and contains safe reproduction evidence.',
              '- Submit only through the programme’s official reporting channel.',
              '- A bounty payment is determined by the programme; no payout is guaranteed.', '']
    report.write_text('\n'.join(lines), encoding='utf-8')
    print(f'Wrote {path}\nWrote {report}\nNo findings were automatically labelled as vulnerabilities.')

if __name__ == '__main__':
    ap = argparse.ArgumentParser(description='Explicit-scope, headers-only bounty research organiser')
    ap.add_argument('--policy', type=pathlib.Path, required=True)
    ap.add_argument('--output', type=pathlib.Path, default=pathlib.Path('out'))
    ap.add_argument('--execute', action='store_true', help='Enable authorised, rate-limited HEAD requests')
    args = ap.parse_args()
    try: run(args.policy, args.output, args.execute)
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        ap.error(str(exc))
