import json
import pathlib
import tempfile
import unittest
from meta_workflow import load_meta_policy, scan, prepare_report

ROOT = pathlib.Path(__file__).resolve().parents[1]
POLICY = ROOT / 'examples/meta-policy.json'

class MetaWorkflowTests(unittest.TestCase):
    def test_no_live_testing_policy(self):
        obj = load_meta_policy(POLICY)
        self.assertFalse(obj['network_access'])
        obj['network_access'] = True
        with tempfile.TemporaryDirectory() as tmp:
            p = pathlib.Path(tmp)/'policy.json'
            p.write_text(json.dumps(obj))
            with self.assertRaises(ValueError): load_meta_policy(p)

    def test_local_scan_finds_candidate_without_false_claim(self):
        report=scan(ROOT/'examples/local-fixture',load_meta_policy(POLICY))
        self.assertEqual(report['network_requests'],0)
        self.assertEqual(len(report['candidates']),1)
        self.assertEqual(report['candidates'][0]['kind'],'python_dynamic_execution')
        self.assertFalse(report['candidates'][0]['confirmed_vulnerability'])
        self.assertEqual(len(report['candidates'][0]['line_sha256']),64)

    def test_report_refuses_unapproved(self):
        evidence=scan(ROOT/'examples/local-fixture',load_meta_policy(POLICY))
        review=json.loads((ROOT/'examples/review.template.json').read_text())
        with self.assertRaisesRegex(ValueError,'human approval gate'):prepare_report(evidence,review,'R0001')

    def test_report_rejects_inadequate_review_fields(self):
        evidence=scan(ROOT/'examples/local-fixture',load_meta_policy(POLICY))
        review=json.loads((ROOT/'examples/review.template.json').read_text())
        for k in ('meta_scope_verified','explicit_test_authorisation_verified','manual_reproduction_confirmed',
                  'real_security_impact_confirmed','nonduplicate_reviewed','operator_approved_report'):
            review[k]=True
        with self.assertRaisesRegex(ValueError,'missing substantive'):prepare_report(evidence,review,'R0001')

    def test_report_requires_existing_candidate(self):
        evidence=scan(ROOT/'examples/local-fixture',load_meta_policy(POLICY))
        with self.assertRaises(ValueError):prepare_report(evidence,{},'R9000')

    def test_symlink_outside_source_not_followed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp)/'root';root.mkdir()
            (root/'safe.py').write_text('print(1)')
            link=root/'not-owned.py'
            try:link.symlink_to(ROOT/'examples/local-fixture/demo.py')
            except (OSError,NotImplementedError):self.skipTest('symlinks unsupported here')
            evidence=scan(root,load_meta_policy(POLICY))
            self.assertEqual(evidence['files_hashed'],1)

if __name__=='__main__':unittest.main()
