"""Each agent may run only its own commands, and speaks only as itself (no Docker needed)."""

import io
import os
import unittest
from pathlib import Path
from contextlib import redirect_stdout
from unittest import mock

from proveit import actions, cli, store
from tests.helpers import WorkDirTest, replay, stub_runs

VALID = replay("01-real-cve-2020-14343.md")


class Roles(WorkDirTest):
    def run(self, result=None):
        with stub_runs(*(["CODE_EXECUTION"] * 20)):
            return super().run(result)

    def cli(self, *argv, role=None):
        env = ({"PROVEIT_ACTOR": "agent", "PROVEIT_AGENT": role} if role is not None
               else {"PROVEIT_ACTOR": "", "PROVEIT_AGENT": ""})
        out = io.StringIO()
        with redirect_stdout(out), mock.patch.dict(os.environ, env):
            try:
                cli.main(list(argv))
                return out.getvalue(), None
            except SystemExit as exc:
                return out.getvalue(), str(exc)

    def ticket(self):
        agent = self.make_intake()
        self.report(agent, VALID)
        return store.all_tickets()[-1]["id"]

    def test_no_agent_records_a_verdict_from_its_shell(self):
        tid = self.ticket()
        self.assertIsNone(self.cli("check", tid, role="reproducer")[1])
        for role in ("reproducer", "skeptic", ""):
            for argv in (("concur", tid), ("dispute", tid, "--code", "patched_not_checked")):
                _, err = self.cli(*argv, role=role)
                self.assertIn("agents record verdicts in #proveit-triage", err)
        self.assertIsNone(store.load(tid).get("skeptic"))

    def test_skeptic_cannot_produce_evidence(self):
        tid = self.ticket()
        _, err = self.cli("check", tid, role="skeptic")
        self.assertIn("the skeptic may not run check", err)
        self.assertEqual(store.load(tid)["runs"], [])

    def test_agent_without_a_role_may_only_read(self):
        tid = self.ticket()
        self.assertIsNone(self.cli("show", tid, role="")[1])
        self.assertIn("has no role", self.cli("check", tid, role="")[1])

    def test_agents_speak_only_as_themselves(self):
        tid = self.ticket()
        self.cli("check", tid, "--by", "maintainer", role="reproducer")
        self.assertEqual(store.load(tid)["runs"][-1]["by"], "reproducer")

    def test_human_only_commands_refused_for_every_agent(self):
        tid = self.ticket()
        for role in ("reproducer", "skeptic", ""):
            self.assertIn("only humans may override", self.cli("override", tid, "--by", "x", role=role)[1])
            self.assertIn("only humans may cost", self.cli("cost", tid, "--usd", "1", "--source", "x", role=role)[1])

    def test_humans_are_not_limited_by_roles(self):
        tid = self.ticket()
        self.assertIsNone(self.cli("check", tid, "--by", "maint")[1])
        self.assertIsNone(self.cli("concur", tid, "--by", "maint")[1])
        self.assertEqual(store.load(tid)["skeptic"]["by"], "maint")


class VerdictsThroughIntake(WorkDirTest):
    """Switch tells Intake who sent a message, so only the real Skeptic records a verdict."""

    def checked_ticket(self, agent):
        self.report(agent, VALID)
        tid = store.all_tickets()[-1]["id"]
        with stub_runs("CODE_EXECUTION"):
            actions.check(tid, actor="agent", by="reproducer")
        return tid

    def test_skeptic_agent_records_concur_and_dispute(self):
        agent = self.make_intake()
        tid = self.checked_ticket(agent)
        self.say(agent, "@prove-it-intake concur %s" % tid, sender="prove-it-skeptic", kind="agent")
        record = store.load(tid)
        self.assertEqual(record["skeptic"]["verdict"], "concur")
        self.assertEqual(record["skeptic"]["by"], "prove-it-skeptic")
        self.assertEqual(record["timeline"][-1]["actor"], "agent")
        self.say(agent, "@prove-it-intake dispute %s patched_not_checked" % tid, sender="Prove It Skeptic", kind="agent")
        self.assertEqual(store.load(tid)["status"], "disputed")
        self.assertEqual(store.load(tid)["skeptic"]["code"], "patched_not_checked")

    def test_reproducer_and_outsiders_cannot_record_a_verdict(self):
        agent = self.make_intake()
        tid = self.checked_ticket(agent)
        self.say(agent, "@prove-it-intake concur %s" % tid, sender="prove-it-reproducer", kind="agent")
        self.say(agent, "@prove-it-intake concur %s" % tid, sender="prove-it-skeptic", kind="user")  # a person using its name
        self.say(agent, "@prove-it-intake dispute %s no" % tid, sender="random-reporter")
        self.assertIsNone(store.load(tid).get("skeptic"))
        self.assertEqual(agent.triage.text().count("Refused: only @prove-it-skeptic or a maintainer records a verdict"), 3)

    def test_a_maintainer_may_record_a_verdict(self):
        agent = self.make_intake()
        tid = self.checked_ticket(agent)
        self.say(agent, "@prove-it-intake concur %s" % tid)
        self.assertEqual(store.load(tid)["skeptic"]["by"], "maintainer")
        self.assertEqual(store.load(tid)["timeline"][-1]["actor"], "human")

    def test_inline_command_example_is_not_executed(self):
        agent = self.make_intake()
        tid = self.checked_ticket(agent)
        body = "Please review this evidence. The example verdict is `@prove-it-intake concur %s`." % tid
        self.say(agent, body, sender="maintainer")
        self.assertIsNone(store.load(tid).get("skeptic"))
        self.assertFalse(any(event["what"] == "concur" for event in store.load(tid)["timeline"]))

    def test_command_in_fenced_example_is_not_executed(self):
        agent = self.make_intake()
        tid = self.checked_ticket(agent)
        body = "Example only:\n```text\n@prove-it-intake concur %s\n```" % tid
        self.say(agent, body, sender="maintainer")
        self.assertIsNone(store.load(tid).get("skeptic"))
        self.assertFalse(any(event["what"] == "concur" for event in store.load(tid)["timeline"]))

    def test_command_is_read_after_the_mention(self):
        agent = self.make_intake()
        tid = self.checked_ticket(agent)
        body = ("I could not concur at first, but every item checks out.\n\n@prove-it-intake dispute %s "
                "patched_not_checked" % tid)
        self.say(agent, body, sender="prove-it-skeptic", kind="agent")
        self.assertEqual(store.load(tid)["skeptic"]["verdict"], "dispute")


class PrivateFolder(WorkDirTest):
    def test_reporter_material_lives_outside_work(self):
        agent = self.make_intake()
        self.report(agent, VALID)
        tid = store.all_tickets()[-1]["id"]
        report = store.private_path(tid, "report.md")
        self.assertTrue(report.exists())
        self.assertNotIn(self.tmp / "work", report.parents)
        self.assertEqual(list((self.tmp / "work").rglob("report.md")), [])

    def test_legacy_private_folder_is_moved(self):
        agent = self.make_intake()
        self.report(agent, VALID)
        tid = store.all_tickets()[-1]["id"]
        payload = store.payload(tid)
        self.assertTrue(payload)
        new = store.private_dir(tid)
        legacy = self.tmp / "work" / tid / "private"
        new.rename(legacy)  # how an older version left it
        self.assertFalse(new.exists())
        self.assertEqual(store.payload(tid), payload)  # read through the new location after the move
        self.assertFalse(legacy.exists())

    def test_real_store_keeps_private_material_in_the_home_folder(self):
        from proveit import config
        with mock.patch.object(config, "WORK_DIR", config.DEFAULT_WORK_DIR), mock.patch.dict(os.environ, {"PROVEIT_PRIVATE_DIR": ""}):
            self.assertEqual(store.private_root(), config.PROVEIT_HOME / "private")
        self.assertEqual(config.PROVEIT_HOME.parent, Path.home() / ".proveit")


if __name__ == "__main__":
    unittest.main()
