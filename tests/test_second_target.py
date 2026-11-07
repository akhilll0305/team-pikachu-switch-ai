"""The second target (U4): sqlparse CVE-2023-30608, a ReDoS.

Everything here is verified offline. The Docker tests never build an image:
they skip unless the sqlparse images are already present (built on request with
`python -m proveit build --target sqlparse`).
"""

import os
import unittest

from proveit import poc, reports, sandbox, targets

SQL = targets.get("sqlparse")
# The Gate-0 payload: a quote then 42 backslashes, no closing quote. 43 bytes of text.
REDOS_PAYLOAD = "'" + ("\\" * 42)


def _sqlparse_images_ready():
    if not sandbox.docker_available():
        return False
    try:
        return all(sandbox.image_current(spec["image"], SQL) for spec in SQL.builds.values())
    except sandbox.SandboxError:
        return False


IMAGES = _sqlparse_images_ready()
if os.environ.get("PROVEIT_REQUIRE_SQLPARSE") == "1" and not IMAGES:
    raise RuntimeError("sqlparse images are required here; run python -m proveit build --target sqlparse")


class TargetMetadata(unittest.TestCase):
    def test_registered_and_not_built_by_default(self):
        self.assertIn("sqlparse", targets.TARGETS)
        self.assertIs(targets.get("sqlparse"), SQL)
        self.assertFalse(SQL.build_by_default)   # a bare `proveit build` leaves it alone
        self.assertFalse(SQL.lazy_build)         # a missing image is an error, never an auto-build
        self.assertNotIn(SQL, targets.buildable())

    def test_nothing_is_out_of_scope(self):
        # sqlparse documents nothing as unsafe, so the out-of-scope list is empty.
        self.assertEqual(SQL.out_of_scope_names, ())
        self.assertIsNone(SQL.out_of_scope_name("sqlparse.lexer"))
        self.assertIsNone(SQL.out_of_scope_name("anything"))

    def test_harness_digest_is_stable_and_its_own(self):
        d1 = sandbox.harness_digest(SQL)
        self.assertEqual(d1, sandbox.harness_digest(SQL))
        self.assertNotEqual(d1, sandbox.harness_digest(targets.PYYAML))


class EntryPoints(unittest.TestCase):
    def test_allowlisted_calls_accepted(self):
        for text in ("parse", "sqlparse.parse", "sqlparse.parse(sql)", "format", "sqlparse.format", "split"):
            key, problem = SQL.parse_entry_point(text)
            self.assertIsNone(problem, text)
            self.assertIn(key, SQL.entry_points)

    def test_internal_or_unknown_is_not_on_the_allowlist(self):
        # An internal module is refused as "not an allowed entry point", never "out of scope".
        for text in ("sqlparse.lexer", "sqlparse.lexer.tokenize", "sqlparse.engine.grouping", "tokenize"):
            self.assertEqual(SQL.parse_entry_point(text), (None, "unknown_entry_point"), text)
        self.assertEqual(SQL.parse_entry_point(""), (None, "no_entry_point"))

    def test_validate_uses_the_target_allowlist_and_size(self):
        self.assertIsNone(SQL.validate("parse", REDOS_PAYLOAD))
        self.assertEqual(SQL.validate("unsafe_load", "SELECT 1"), "unknown_entry_point")
        self.assertEqual(SQL.validate("parse", "a" * (SQL.payload_max_bytes + 1)), "too_large")
        self.assertEqual(SQL.validate("parse", "import os\nos.system('id')\n"), "python_code")
        self.assertEqual(SQL.validate("parse", "   \n"), "empty_payload")

    def test_tags_are_empty_for_sql(self):
        self.assertEqual(SQL.tags(REDOS_PAYLOAD), [])


class Parsing(unittest.TestCase):
    def test_four_field_report_parses(self):
        text = ("Claimed impact: denial of service\n"
                "affected_version: 0.4.3\n"
                "entry_point: parse\n"
                "payload: |\n"
                "  %s\n"
                "expected: it should parse quickly\n"
                "actual: it hangs\n" % REDOS_PAYLOAD)
        ticket = reports.parse(text, SQL)
        self.assertEqual(ticket.target, "sqlparse")
        self.assertEqual(ticket.entry_point, "parse")
        self.assertEqual(ticket.affected_version, "0.4.3")
        self.assertEqual(ticket.claim, "denial_of_service")
        self.assertEqual(ticket.payload.strip(), REDOS_PAYLOAD)
        self.assertFalse(ticket.missing)
        self.assertFalse(ticket.poc_problem)

    def test_sql_fence_is_taken_as_the_payload(self):
        text = ("DoS via parse\naffected_version: 0.4.3\nentry_point: parse\n"
                "```sql\n%s\n```\n" % REDOS_PAYLOAD)
        ticket = reports.parse(text, SQL)
        self.assertEqual(ticket.payload.strip(), REDOS_PAYLOAD)
        self.assertEqual(ticket.entry_point, "parse")

    def test_version_is_required(self):
        text = "DoS\nentry_point: parse\n```sql\n%s\n```\n" % REDOS_PAYLOAD
        ticket = reports.parse(text, SQL)
        self.assertIn("affected_version", ticket.missing)

    def test_internal_entry_point_is_refused(self):
        text = ("DoS\naffected_version: 0.4.3\nentry_point: sqlparse.lexer.tokenize\n"
                "```sql\n%s\n```\n" % REDOS_PAYLOAD)
        ticket = reports.parse(text, SQL)
        self.assertEqual(ticket.poc_problem, "unknown_entry_point")

    def test_python_payload_is_refused(self):
        text = ("RCE\naffected_version: 0.4.3\nentry_point: parse\n"
                "```python\nimport os\nos.system('id')\n```\n")
        ticket = reports.parse(text, SQL)
        self.assertEqual(ticket.poc_problem, "python_code")


@unittest.skipUnless(IMAGES, "sqlparse images not built (run `python -m proveit build --target sqlparse`)")
class Reproduces(unittest.TestCase):
    def test_reproduces_on_vulnerable_three_of_three(self):
        rec = sandbox.run_check("parse", REDOS_PAYLOAD, "vulnerable", target=SQL)
        self.assertEqual(rec.get("outcome"), "RESOURCE_EXHAUSTION")
        self.assertEqual(rec.get("agreeing"), rec.get("runs"))
        self.assertEqual(rec.get("runs"), 3)
        self.assertEqual(rec.get("target_name"), "sqlparse")

    def test_not_reproduced_on_patched_three_of_three(self):
        rec = sandbox.run_check("parse", REDOS_PAYLOAD, "patched", target=SQL)
        self.assertEqual(rec.get("outcome"), "NOT_REPRODUCED")
        self.assertEqual(rec.get("agreeing"), rec.get("runs"))
        self.assertEqual(rec.get("runs"), 3)


if __name__ == "__main__":
    unittest.main()
