"""The scope policy (U1c, decision D-015): out-of-scope entry points are refused at Intake, before any sandbox run."""

from unittest import mock

from proveit import actions, messages, poc, states, store
from tests.helpers import WorkDirTest

CANARY = "Wq3CANARYv"


def report(entry):
    return ("Title: t\nSeverity: critical\nAffected version: 5.3.1\nEntry point: %s\nClaimed impact: arbitrary code execution\n\n"
            "```yaml\n!!python/object/apply:os.system [\"true\"]\n```\n" % entry)


OUT_OF_SCOPE = {
    "yaml.unsafe_load": "yaml.unsafe_load",
    "yaml.unsafe_load(data)": "yaml.unsafe_load",
    "yaml.unsafe_load_all": "yaml.unsafe_load_all",
    "yaml.load(data, Loader=yaml.UnsafeLoader)": "yaml.load with Loader=yaml.UnsafeLoader",
    "yaml.load(data, Loader=yaml.Loader)": "yaml.load with Loader=yaml.Loader",
    "yaml.load(data, Loader=Loader)": "yaml.load with Loader=yaml.Loader",
}


class Scope(WorkDirTest):
    def test_allowlist_has_no_out_of_scope_entry_point(self):
        for key in poc.ENTRY_POINTS:
            self.assertIsNone(poc.out_of_scope_name(key), key)

    def test_each_out_of_scope_entry_point_rejected_without_sandbox(self):
        with mock.patch("proveit.sandbox.run_poc") as run_poc, mock.patch("proveit.sandbox.run_check") as run_check:
            for written, canonical in OUT_OF_SCOPE.items():
                with self.subTest(entry=written):
                    agent = self.make_intake()
                    # One reporter per case: rejections count against a reporter (D-018), tested in test_reputation.
                    self.report(agent, report(written), sender="reporter-" + canonical + written)
                    record = store.all_tickets()[-1]
                    self.assertEqual(record["status"], "invalid_proof")
                    self.assertEqual(record["out_of_scope_entry"], canonical)
                    self.assertIn("%s: %s is documented by PyYAML as unsafe for untrusted input, so it is out of "
                                  "scope (see the scope policy). Can you show the issue with safe_load or full_load?"
                                  % (record["id"], canonical), agent.intake.text())
                    self.assertEqual(agent.triage.posts, [], "nothing reaches triage")
                    with self.assertRaises(states.IllegalTransition):
                        actions.check(record["id"], actor="agent", by="reproducer")
            run_poc.assert_not_called()
            run_check.assert_not_called()

    def test_out_of_scope_followup_is_rejected_too(self):
        agent = self.make_intake()
        root = self.report(agent, "Title: t\nClaimed impact: arbitrary code execution\nproof on request\n")
        self.reply(agent, root, "Entry point: yaml.unsafe_load\n\n```yaml\na: 1\n```\n")
        record = store.all_tickets()[-1]
        self.assertEqual((record["status"], record["out_of_scope_entry"]), ("invalid_proof", "yaml.unsafe_load"))

    def test_in_scope_entry_points_still_accepted(self):
        for entry in ("yaml.safe_load", "yaml.full_load", "yaml.load(data, Loader=yaml.SafeLoader)",
                      "yaml.load(data, Loader=yaml.FullLoader)"):
            with self.subTest(entry=entry):
                agent = self.make_intake()
                self.report(agent, report(entry).replace('!!python/object/apply:os.system ["true"]', "a: 1"))
                record = store.all_tickets()[-1]
                self.assertEqual(record["status"], "in_triage")
                self.assertEqual(record["out_of_scope_entry"], "")

    def test_rejection_is_fixed_text(self):
        agent = self.make_intake()
        self.report(agent, report("yaml.unsafe_load(%s_stream)  # %s" % (CANARY, CANARY)))
        record = store.all_tickets()[-1]
        self.assertEqual(record["out_of_scope_entry"], "yaml.unsafe_load")
        self.assertNotIn(CANARY, agent.intake.text())
        self.assertNotIn(CANARY, (self.tmp / "work" / record["id"] / "ticket.json").read_text(encoding="utf-8"))
        # Anything but a canonical name is never echoed.
        self.assertNotIn(CANARY, messages.out_of_scope("R-009", CANARY))
