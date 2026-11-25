import pathlib, sys, unittest
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from bounty import load_policy, observations_for_response, run

class PipelineTests(unittest.TestCase):
    def test_missing_headers_are_not_called_vulnerabilities(self):
        checks = observations_for_response('https://example.com', 200, {})
        self.assertTrue(checks)
        self.assertTrue(all(not e['confirmed_vulnerability'] for e in checks))
    def test_scope_gate_rejects_insecure_url(self):
        import tempfile, json
        with tempfile.TemporaryDirectory() as td:
            p = pathlib.Path(td) / 'policy.json'
            p.write_text(json.dumps({'program_name': 'Lab', 'authorisation_reference': 'written',
                'allowed_urls': ['http://example.com'], 'max_requests_per_run':1, 'min_delay_seconds':3}))
            with self.assertRaises(ValueError):load_policy(p)
    def test_dry_run_makes_no_outputs(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            p = pathlib.Path(__file__).resolve().parents[1] / 'examples' / 'program.template.json'
            out=pathlib.Path(td)/'out'
            run(p, out, False)
            self.assertFalse(out.exists())
if __name__ == '__main__': unittest.main()
