#!/usr/bin/env python3
"""Autonomous OFFLINE research pipeline for owned/authorised source workspaces.

Autonomy means deterministic local inspection, multi-stage triage, evidence integrity,
reproducible queues, and zero target-network interactions. It does NOT confirm bugs,
execute third-party code, exploit services, or submit reports.
"""
from __future__ import annotations
import argparse
import ast
import datetime as dt
import hashlib
import json
import pathlib
import re
import sys
from collections import Counter
from meta_workflow import load_meta_policy, scan, canonical_workspace, EXCLUDE, MAX_FILE_BYTES

SCHEMA = 1
DEFAULT_RULE_WEIGHTS = {
    "PY-EXEC": 75, "PY-SHELL": 78, "PY-TLS": 45, "PY-PICKLE": 67,
    "JS-EVAL": 75, "JS-HTML": 59,
}
REVIEW_ADVICE = {
    "PY-EXEC": "Trace whether user-controlled data can reach this sink; validate with harmless local fixtures only.",
    "PY-SHELL": "Review command construction, escaping and whether untrusted data reaches the shell.",
    "PY-TLS": "Check whether TLS verification is disabled on security-sensitive requests.",
    "PY-PICKLE": "Establish whether bytes originate outside a trusted boundary.",
    "JS-EVAL": "Examine whether untrusted data can influence dynamic JavaScript evaluation.",
    "JS-HTML": "Establish whether data is HTML-escaped or sanitised before rendering.",
}
CANDIDATE_ONLY = "investigation_candidate_not_proven"

def sha256(text: bytes) -> str:
    return hashlib.sha256(text).hexdigest()

def ast_context(path: pathlib.Path, line_no: int, rule: str) -> dict:
    """Structural triage only. No imported source is executed."""
    try:
        source = path.read_text(encoding="utf-8")
        parsed = ast.parse(source)
    except (UnicodeError, OSError, SyntaxError):
        return {"analysis": "unavailable", "scope": None, "parameters": [], "taint_proof": False}
    containing = []
    for node in ast.walk(parsed):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.lineno <= line_no <= getattr(node, "end_lineno", node.lineno):
            containing.append(node)
    if not containing:
        return {"analysis": "python_ast", "scope": "module", "parameters": [], "taint_proof": False}
    func = sorted(containing, key=lambda n:n.lineno)[-1]
    names = [a.arg for a in func.args.posonlyargs + func.args.args + func.args.kwonlyargs]
    # Parameter presence is structural context, NOT proof that arguments reach the sink.
    return {"analysis": "python_ast", "scope": "function", "parameters": names[:12],
            "taint_proof": False}

def analyse(workspace: pathlib.Path, policy: dict, previous: dict | None = None) -> dict:
    if policy.get("programme") != "Meta Bug Bounty" or policy.get("scope_status") != "unverified" or policy.get("network_access") is not False or policy.get("live_testing_approved") is not False or policy.get("auto_submit") is not False:
        raise ValueError("Autonomous hunter requires the locked-down Meta offline policy")
    base = scan(workspace, policy)
    root = canonical_workspace(workspace)
    previous = previous or {}
    historic_ids = {c.get("fingerprint") for c in previous.get("queue", []) if c.get("fingerprint")}
    # Fingerprints are rule+relative source path+hashed evidence line, rather than unstable candidate index.
    queue = []
    for c in base["candidates"]:
        fingerprint = sha256((c["rule_id"] + "\0" + c["path"] + "\0" + c["line_sha256"]).encode())[:24]
        detail = {"analysis": "textual_pattern", "scope": "unknown", "parameters": [], "taint_proof": False}
        if c["path"].endswith(".py"):
            detail = ast_context(root / c["path"], c["line"], c["rule_id"])
        score = DEFAULT_RULE_WEIGHTS.get(c["rule_id"], 40)
        # Presence of a pattern is not severity. Score only orders human review.
        queue.append({
            "fingerprint": fingerprint,
            "finding_id": c["finding_id"],
            "rule_id": c["rule_id"],
            "path": c["path"], "line": c["line"],
            "line_sha256": c["line_sha256"],
            "file_sha256": c["file_sha256"],
            "review_priority": score,
            "priority_definition": "heuristic_review_order_not_severity_or_exploitability",
            "classification": CANDIDATE_ONLY,
            "evidence": {"type": c["evidence_type"], "reproducibility": "source_hash_only"},
            "context": detail,
            "review_question": REVIEW_ADVICE.get(c["rule_id"], "Determine whether this is an actual security boundary failure."),
            "seen_in_previous_run": fingerprint in historic_ids,
            "requires_human_reproduction": True,
            "confirmed_vulnerability": False,
        })
    queue.sort(key=lambda c:(-c["review_priority"],c["path"],c["line"],c["fingerprint"]))
    current_ids = {x["fingerprint"] for x in queue}
    return {
        "schema_version": SCHEMA,
        "engine": "autonomous_offline_static_triage",
        "generated_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "programme": "Meta Bug Bounty",
        "meta_scope_verified": False,
        "live_target_access": False,
        "network_requests": 0,
        "code_execution": False,
        "automatic_submission": False,
        "files_considered": base["files_considered"],
        "files_hashed": base["files_hashed"],
        "source_hashes": base["source_hashes"],
        "skipped_files": base["skipped_files"],
        "queue": queue,
        "summary": {
            "candidate_count": len(queue),
            "rules": dict(sorted(Counter(x["rule_id"] for x in queue).items())),
            "new_fingerprints": len(current_ids - historic_ids),
            "unchanged_fingerprints": len(current_ids & historic_ids),
            "resolved_or_moved_fingerprints": len(historic_ids-current_ids),
            "confirmed_vulnerabilities": 0,
            "submission_ready_reports": 0,
        },
        "disclaimer": "No confirmed vulnerabilities, scope eligibility, payout estimate or authorisation to test live Meta systems."
    }

def export_sarif(result: dict) -> dict:
    rule_ids = sorted({f["rule_id"] for f in result["queue"]})
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {
                "name": "Meta Offline Hunter",
                "version": "0.1.0",
                "informationUri": "https://github.com/HillaryMurimi/meta-bounty-research-pipeline",
                "rules": [{"id": r, "shortDescription": {"text": "Local source pattern requiring manual review"}} for r in rule_ids]}},
            "results": [{
                "ruleId": f["rule_id"],
                "level": "note",
                "message": {"text": f["review_question"] + " This is NOT a confirmed vulnerability."},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": f["path"]},
                              "region": {"startLine": f["line"]}}}],
                "partialFingerprints": {"primaryLocationLineHash":f["fingerprint"]}
            } for f in result["queue"]]
        }]
    }

def render_summary(result: dict) -> str:
    s = result["summary"]
    rows = [
        "# Offline autonomous research — investigation queue",
        "",
        "**No live Meta testing, no confirmed vulnerabilities, and no bounty submission.**",
        "",
        f"- Files inspected: {result['files_considered']}",
        f"- Review candidates: {s['candidate_count']}",
        f"- New candidates: {s['new_fingerprints']}",
        f"- Previously seen candidates: {s['unchanged_fingerprints']}",
        f"- Potentially resolved/moved: {s['resolved_or_moved_fingerprints']}",
        "",
        "| Priority | Rule | Location | Evidence ID | Status |",
        "| ---: | --- | --- | --- | --- |"
    ]
    for f in result["queue"]:
        rows.append(f"| {f['review_priority']} | {f['rule_id']} | `{f['path']}:{f['line']}` | `{f['fingerprint']}` | needs verification |")
    rows.extend(["", "## Review criteria", "",
        "1. Confirm current official Meta scope and written authorisation for the proposed technique.",
        "2. Establish actual untrusted input reachability using a harmless local reproduction.",
        "3. Demonstrate concrete impact with no third-party user data or production disruption.",
        "4. Check duplicates and exclusions; redact any sensitive evidence.",
        "5. Require researcher approval before drafting; submit only using Meta's official portal.",
        "", "Review priority is not a CVSS score, exploit confidence or payout prediction.", ""])
    return "\n".join(rows)

def main() -> None:
    parser = argparse.ArgumentParser(description="Autonomous OFFLINE source research; no Meta network access")
    parser.add_argument("--policy",type=pathlib.Path,required=True)
    parser.add_argument("--workspace",type=pathlib.Path,required=True)
    parser.add_argument("--output",type=pathlib.Path,default=pathlib.Path("out/research"))
    parser.add_argument("--previous",type=pathlib.Path,default=None)
    args=parser.parse_args()
    policy=load_meta_policy(args.policy)
    previous=None
    if args.previous:
        previous=json.loads(args.previous.read_text(encoding="utf-8"))
    result=analyse(args.workspace,policy,previous)
    args.output.mkdir(parents=True,exist_ok=True)
    files={
        "queue.json": json.dumps(result,indent=2)+"\n",
        "findings.sarif": json.dumps(export_sarif(result),indent=2)+"\n",
        "REVIEW_QUEUE.md": render_summary(result)+"\n",
    }
    for filename,content in files.items():
        (args.output/filename).write_text(content,encoding="utf-8")
        print("WROTE",args.output/filename)
    print("OFFLINE COMPLETE:",result["summary"]["candidate_count"],"investigation candidates; 0 confirmed vulnerabilities; 0 network requests")

if __name__ == "__main__":
    try:main()
    except (OSError,ValueError,UnicodeError,json.JSONDecodeError) as exc:
        print(f"Research stopped: {exc}",file=sys.stderr)
        sys.exit(2)
