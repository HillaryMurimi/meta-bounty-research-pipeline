"""Offline autonomous hunter contract tests. No network, no exploitation."""
import json
import pathlib
import tempfile
import unittest
from autonomous_hunter import analyse, export_sarif, render_summary
from meta_workflow import load_meta_policy

POLICY = pathlib.Path(__file__).resolve().parents[1] / "examples" / "meta-policy.json"

class AutonomousHunterTests(unittest.TestCase):
    def setUp(self):
        self.policy = load_meta_policy(POLICY)
    def test_autonomous_triage_and_sarif(self):
        with tempfile.TemporaryDirectory() as temp:
            root=pathlib.Path(temp)
            (root/"demo.py").write_text(
                "def f(user_input):\n"
                "    return eval(user_input)\n"
                "def safe(value):\n"
                "    return value + 1\n", encoding="utf-8")
            result=analyse(root,self.policy)
            self.assertEqual(result["network_requests"],0)
            self.assertEqual(result["summary"]["candidate_count"],1)
            self.assertEqual(result["summary"]["confirmed_vulnerabilities"],0)
            self.assertFalse(result["meta_scope_verified"])
            c=result["queue"][0]
            self.assertEqual(c["rule_id"],"PY-EXEC")
            self.assertEqual(c["context"]["scope"],"function")
            self.assertFalse(c["context"]["taint_proof"])
            self.assertFalse(c["confirmed_vulnerability"])
            self.assertEqual(export_sarif(result)["version"],"2.1.0")
            self.assertIn("not a CVSS score",render_summary(result))
            second=analyse(root,self.policy,result)
            self.assertEqual(second["summary"]["new_fingerprints"],0)
            self.assertEqual(second["summary"]["unchanged_fingerprints"],1)
            self.assertEqual(second["queue"][0]["fingerprint"],c["fingerprint"])
            (root/"demo.py").write_text("def f(user_input):\n    return user_input\n",encoding="utf-8")
            fixed=analyse(root,self.policy,second)
            self.assertEqual(fixed["summary"]["candidate_count"],0)
            self.assertEqual(fixed["summary"]["resolved_or_moved_fingerprints"],1)
    def test_missing_policy_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(ValueError):
                analyse(pathlib.Path(temp),{"scope_status":"verified"})
    def test_skips_symlink_and_does_not_execute_code(self):
        with tempfile.TemporaryDirectory() as temp:
            p=pathlib.Path(temp)/"danger.py"
            p.write_text('raise RuntimeError("should never execute")\neval("x")\n',encoding="utf-8")
            result=analyse(pathlib.Path(temp),self.policy)
            self.assertEqual(result["summary"]["candidate_count"],1)

if __name__=="__main__":unittest.main(verbosity=2)
