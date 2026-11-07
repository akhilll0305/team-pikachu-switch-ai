"""W1: proofs of concept are data. Invalid proofs are rejected before any sandbox run."""

import unittest
from unittest import mock

from proveit import poc, reports, sandbox
from proveit.config import PAYLOAD_MAX_BYTES
from tests.helpers import WorkDirTest, replay


class EntryPoints(unittest.TestCase):
    def test_allowlisted(self):
        cases = {"yaml.safe_load": "safe_load", "yaml.full_load": "full_load", "`yaml.full_load(data)`": "full_load",
                 "yaml.load(data, Loader=yaml.SafeLoader)": "load:SafeLoader",
                 "yaml.load with Loader=yaml.FullLoader": "load:FullLoader", "load:FullLoader": "load:FullLoader"}
        for text, key in cases.items():
            self.assertEqual(poc.parse_entry_point(text), (key, None), text)

    def test_unsafe_by_design(self):
        for text in ("yaml.unsafe_load", "yaml.unsafe_load_all", "yaml.load(data, Loader=yaml.UnsafeLoader)",
                     "yaml.load(data, Loader=yaml.Loader)", "yaml.load with yaml.Loader"):
            self.assertEqual(poc.parse_entry_point(text), (None, "unsafe_loader"), text)

    def test_other_rejections(self):
        self.assertEqual(poc.parse_entry_point("yaml.load(data, Loader=yaml.CSafeLoader)"), (None, "c_loader"))
        self.assertEqual(poc.parse_entry_point("yaml.safe_load_all"), (None, "unknown_entry_point"))
        self.assertEqual(poc.parse_entry_point("yaml.load(data)"), (None, "unknown_entry_point"))
        self.assertEqual(poc.parse_entry_point(""), (None, "no_entry_point"))


class Validate(unittest.TestCase):
    def test_valid(self):
        self.assertIsNone(poc.validate("safe_load", "a: 1\n"))

    def test_problems(self):
        self.assertEqual(poc.validate("unsafe_load", "a: 1"), "unknown_entry_point")
        self.assertEqual(poc.validate("safe_load", "a" * (PAYLOAD_MAX_BYTES + 1)), "too_large")
        self.assertEqual(poc.validate("safe_load", b"\xff\xfe a: 1"), "not_utf8")
        self.assertEqual(poc.validate("safe_load", "import os\nos.system('id')\n"), "python_code")
        self.assertEqual(poc.validate("safe_load", "   \n"), "empty_payload")


def report(entry, block, lang="yaml"):
    return ("Title: test\nSeverity: critical\nAffected version: 5.3.1\nEntry point: %s\nClaimed impact: arbitrary code execution\n\n"
            "```%s\n%s\n```\n" % (entry, lang, block))


class RejectedBeforeAnyRun(WorkDirTest):
    """Every invalid proof becomes INVALID_PROOF, and Docker is never called."""

    CASES = {
        "python_code": report("yaml.safe_load", "import yaml, time\ntime.sleep(60)\nyaml.safe_load('a: 1')", "python"),
        "ctypes_python": report("yaml.safe_load", "import ctypes\nctypes.string_at(0)", "python"),
        "python_in_yaml_fence": report("yaml.safe_load", "import os\nwith open('/tmp/proveit/marker','w') as f: f.write('x')"),
        "unsafe_load": report("yaml.unsafe_load", "!!python/object/apply:builtins.open ['/tmp/proveit/marker', 'w']"),
        "unsafe_loader": report("yaml.load(data, Loader=yaml.UnsafeLoader)", "a: 1"),
        "plain_loader": report("yaml.load(data, Loader=yaml.Loader)", "a: 1"),
        "not_allowlisted": report("yaml.safe_load_all", "a: 1"),
        "too_large": report("yaml.safe_load", "a: '%s'" % ("x" * PAYLOAD_MAX_BYTES)),
    }

    def test_rejected_at_intake_without_docker(self):
        with mock.patch("proveit.sandbox.subprocess.run", side_effect=AssertionError("docker must not run")):
            for name, text in self.CASES.items():
                with self.subTest(name):
                    agent = self.make_intake()
                    # One reporter per case: rejections count against a reporter (D-018), tested in test_reputation.
                    self.report(agent, text, sender="reporter-" + name)
                    from proveit import store
                    record = store.all_tickets()[-1]
                    self.assertEqual(record["status"], "invalid_proof", record)
                    self.assertTrue(record["poc_problem"])
                    self.assertEqual(agent.triage.posts, [], "an invalid proof must never reach triage")
                    self.assertIn("the proof was not run", agent.intake.text())

    def test_sandbox_refuses_invalid_input_itself(self):
        with mock.patch("proveit.sandbox.subprocess.run", side_effect=AssertionError("docker must not run")):
            for entry, payload in (("unsafe_load", "a: 1"), ("not-a-loader", "a: 1"),
                                   ("safe_load", "import os\nos.system('id')"),
                                   ("safe_load", "x" * (PAYLOAD_MAX_BYTES + 1)), ("safe_load", b"\xff\xfe")):
                record = sandbox.run_poc(entry, payload, "vulnerable")
                self.assertEqual(record["outcome"], "INVALID_PROOF", (entry, record))
                self.assertFalse(record["ran"])


class Fixtures(unittest.TestCase):
    def test_real_cve(self):
        t = reports.parse(replay("01-real-cve-2020-14343.md"))
        self.assertEqual((t.claim, t.entry_point, t.poc_problem, t.missing), ("code_execution", "full_load", "", []))
        self.assertIn("python/name:eval", t.payload)

    def test_slop_asks_for_poc_then_gets_data(self):
        first = reports.parse(replay("02-slop-safe-load-rce.md"))
        self.assertEqual(first.missing, ["poc"])
        merged = reports.merge(first, replay("02-slop-safe-load-rce.followup.md"))
        self.assertTrue(merged.complete())
        self.assertEqual(merged.entry_point, "safe_load")

    def test_entry_point_only_followup_keeps_the_payload(self):
        first = reports.parse("Affected version: 5.3.1\nClaimed impact: code execution\n\n```yaml\n!!python/object/new:tuple [x]\n```\n")
        self.assertEqual(first.missing, ["entry_point"])
        merged = reports.merge(first, "Entry point: yaml.full_load")
        self.assertEqual((merged.entry_point, merged.missing, merged.poc_problem), ("full_load", [], ""))
        self.assertEqual(merged.payload, first.payload)

    def test_entry_point_only_followup_fixes_an_unknown_entry_point(self):
        first = reports.parse("Affected version: 5.3.1\nEntry point: yaml.whatever\nClaimed impact: code execution\n\n```yaml\na: 1\n```\n")
        self.assertEqual(first.poc_problem, "unknown_entry_point")
        merged = reports.merge(first, "Entry point: yaml.safe_load")
        self.assertTrue(merged.complete())
        self.assertEqual(merged.payload, first.payload)

    def test_followup_with_python_still_replaces_the_proof(self):
        first = reports.parse("Claimed impact: code execution\n\n```yaml\na: 1\n```\n")
        merged = reports.merge(first, "```python\nimport yaml\n```\n")
        self.assertEqual(merged.poc_problem, "python_code")
        self.assertFalse(merged.complete())

    def test_billion_laughs(self):
        t = reports.parse(replay("03-slop-billion-laughs.md"))
        self.assertEqual((t.claim, t.entry_point, t.complete()), ("denial_of_service", "safe_load", True))

    def test_headers_say_real_or_synthetic(self):
        self.assertIn("Source: real.", replay("01-real-cve-2020-14343.md"))
        for name in ("02-slop-safe-load-rce.md", "03-slop-billion-laughs.md", "04-injection-attempt.md"):
            self.assertIn("Source: synthetic", replay(name))
        for name in ("02-slop-safe-load-rce.md", "03-slop-billion-laughs.md"):
            self.assertIn("https://gist.github.com/bagder/07f7581f6e3d78ef37dfbfc81fd1d1cd", replay(name))


class Tags(unittest.TestCase):
    def test_known_and_unknown(self):
        tags = poc.tags("!!python/object/apply:os.system ['x']\n!!python/name:eval\n!evilTag x\n!!python/name:IGNORE_ALL\n")
        self.assertIn("!!python/object/apply:os.system", tags)
        self.assertIn("!!python/name:eval", tags)
        self.assertTrue(any(t.startswith("unknown-tag:") for t in tags))
        self.assertTrue(any("unknown-name:" in t for t in tags))
        self.assertFalse(any("evilTag" in t or "IGNORE_ALL" in t for t in tags))


if __name__ == "__main__":
    unittest.main()
