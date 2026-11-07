"""The four-field proof request (U1d, decision D-016). No Docker."""

from proveit import evidence, messages, reports, store
from proveit.config import POC_FORMAT_HELP
from tests.helpers import WorkDirTest, replay

CANARY = "Jt8CANARYq"
COMPLETE_WITHOUT_VERSION = ("Title: t\nSeverity: high\nEntry point: yaml.full_load\nClaimed impact: code execution\n\n"
                            "```yaml\na: 1\n```\n")


class ProofRequest(WorkDirTest):
    def test_request_lists_four_fields(self):
        agent = self.make_intake()
        self.report(agent, replay("02-slop-safe-load-rce.md"))
        text = agent.intake.text()
        for line in ("affected_version: 5.3.1", "entry_point: full_load", "payload: |", "expected: <what should happen>",
                     "actual: <what happens>"):
            self.assertIn(line, text)
        self.assertIn("`affected_version` is required", text)

    def test_the_example_itself_is_a_valid_proof(self):
        example = POC_FORMAT_HELP.split("```\n")[1]
        ticket = reports.parse(example.replace("<YAML>", "a: 1") + "Claimed impact: code execution\n")
        self.assertEqual((ticket.affected_version, ticket.entry_point, ticket.payload, ticket.missing),
                         ("5.3.1", "full_load", "a: 1\n", []))

    def test_missing_version_is_asked_and_not_forwarded(self):
        agent = self.make_intake()
        self.report(agent, COMPLETE_WITHOUT_VERSION)
        record = store.all_tickets()[0]
        self.assertEqual((record["status"], record["missing"]), ("awaiting_poc", ["affected_version"]))
        self.assertIn("R-001: which PyYAML version is affected? Reply in this thread with a line like "
                      "affected_version: 5.3.1.", agent.intake.text())
        self.assertEqual(agent.triage.posts, [], "no triage ticket until the version is given")

    def test_not_a_version_is_asked_again(self):
        agent = self.make_intake()
        root = self.report(agent, COMPLETE_WITHOUT_VERSION.replace("Severity: high\n", "Severity: high\nAffected version: all of them\n"))
        self.reply(agent, root, "affected_version: every %s release" % CANARY)
        record = store.all_tickets()[0]
        self.assertEqual((record["status"], record["affected_version"]), ("awaiting_poc", ""))
        self.assertEqual(agent.intake.text().count("which PyYAML version is affected?"), 2)
        self.assertNotIn(CANARY, (self.tmp / "work" / record["id"] / "ticket.json").read_text(encoding="utf-8"))

    def test_version_only_followup_merges_with_earlier_proof(self):
        agent = self.make_intake()
        root = self.report(agent, COMPLETE_WITHOUT_VERSION)
        before = store.all_tickets()[0]
        self.reply(agent, root, "affected_version: 5.3.1")
        record = store.load(before["id"])
        self.assertEqual((record["status"], record["affected_version"], record["missing"]), ("in_triage", "5.3.1", []))
        self.assertEqual(record["payload_sha256"], before["payload_sha256"], "the proof already sent is kept")
        self.assertEqual(store.payload(record["id"]), "a: 1\n")
        self.assertIn("**Ticket R-001**", agent.triage.text())

    def test_version_parses(self):
        cases = {"5.3.1": "5.3.1", "PyYAML 5.3.1": "5.3.1", "v5.4": "5.4", "<5.4": "<5.4", "<= 5.3.1": "<=5.3.1",
                 "before 5.4": "before 5.4", "`5.3.1`": "5.3.1", "5": "5", "all versions": "", "latest": "",
                 "5.3.1; rm -rf /": "", "": "", None: ""}
        for text, expected in cases.items():
            self.assertEqual(reports.parse_version(text), expected, text)

    def test_payload_block_and_fence_both_work(self):
        block = reports.parse("affected_version: 5.3.1\nentry_point: safe_load\npayload: |\n  a: 1\n  b:\n    - 2\n"
                              "expected: x\nactual: y\nClaimed impact: denial of service\n")
        self.assertEqual(block.payload, "a: 1\nb:\n  - 2\n")
        fence = reports.parse("Affected version: 5.3.1\nEntry point: yaml.safe_load\nClaimed impact: denial of service\n"
                              "```yaml\na: 1\n```\n")
        self.assertEqual(fence.payload, "a: 1\n")

    def test_reported_vs_tested_shown(self):
        agent = self.make_intake()
        self.report(agent, replay("01-real-cve-2020-14343.md"))
        record = store.all_tickets()[0]
        self.assertEqual((record["affected_version"], record["tested_version"]), ("before 5.4", "5.3.1"))
        self.assertIn("reported: before 5.4, tested: 5.3.1", agent.triage.text())
        self.assertIn("affected version: reported before 5.4, tested 5.3.1", evidence.text(evidence.pack(record)))
        same = dict(record, affected_version="5.3.1")
        self.assertIn("reported version 5.3.1, tested 5.3.1", messages.ticket_posted(same))

    def test_expected_and_actual_never_reach_agents(self):
        agent = self.make_intake()
        self.report(agent, "Affected version: 5.3.1\nEntry point: yaml.safe_load\nClaimed impact: code execution\n"
                           "expected: %s nothing\nactual: %s boom\n\n```yaml\na: 1\n```\n" % (CANARY, CANARY))
        record = store.all_tickets()[0]
        self.assertEqual(record["status"], "in_triage")
        work = "".join(p.read_text(encoding="utf-8") for p in (self.tmp / "work").rglob("*") if p.is_file())
        for where, text in (("work/", work), ("triage", agent.triage.text()),
                            ("evidence", evidence.text(evidence.pack(record)))):
            self.assertNotIn(CANARY, text, where)
        self.assertIn(CANARY, store.private_path(record["id"], "report.md").read_text(encoding="utf-8"))

    def test_replays_carry_the_fields(self):
        for name in ("01-real-cve-2020-14343.md", "02-slop-safe-load-rce.md", "03-slop-billion-laughs.md",
                     "04-injection-attempt.md"):
            text = replay(name)
            self.assertIn("replay", text.lower(), "fixtures stay labelled as replays")
            self.assertTrue(reports.parse(text).affected_version, name)
        self.assertIn("Expected:", replay("02-slop-safe-load-rce.followup.md"))
        self.assertIn("Affected version: before 5.4", replay("01-real-cve-2020-14343.md"), "as the NVD advisory says")
