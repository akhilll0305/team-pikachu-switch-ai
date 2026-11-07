"""Evidence says only what it shows (checkpoint group C). No Docker: sandbox runs are stubbed."""

import unittest

from proveit import actions, evidence, messages, states, store
from tests.helpers import WorkDirTest, fake_run, replay, stub_runs

VALID = replay("01-real-cve-2020-14343.md")


class Base(WorkDirTest):
    def ticket(self, text=VALID):
        self.agent = self.make_intake()
        self.report(self.agent, text)
        return store.all_tickets()[-1]["id"]

    def check(self, tid, outcome, build="vulnerable", entry=None, **extra):
        run = fake_run(outcome, build=build, entry=entry or "full_load", **extra)
        with stub_runs(run):
            return actions.check(tid, build, actor="agent", by="reproducer", entry_point=entry)

    def skeptic(self, tid, verdict="concur", reason=""):
        self.say(self.agent, ("@prove-it-intake %s %s %s" % (verdict, tid, reason)).strip(),
                 sender="prove-it-skeptic", kind="agent")


class PatchedComparison(Base):
    def test_different_loader_is_not_a_comparison(self):
        # The case the assessment found: vulnerable full_load vs patched safe_load was accepted silently.
        tid = self.ticket()
        self.check(tid, "CODE_EXECUTION", entry="full_load")
        self.check(tid, "NOT_REPRODUCED", build="patched", entry="safe_load")
        pack = evidence.pack(store.load(tid))
        self.assertFalse(pack["checklist"]["patched_comparable"])
        self.assertFalse(pack["checklist"]["patched_build_checked"])
        self.assertIsNone(pack["checklist"]["reproduces_on_patched_too"])
        self.assertTrue(any("not a comparison" in n for n in pack["notes"]), pack["notes"])
        line = messages.patched_line(store.load(tid), evidence.latest_run(store.load(tid), "vulnerable"))
        self.assertIn("not a comparison", line)
        self.assertNotIn("outcome was NOT_REPRODUCED", line)

    def test_same_loader_after_a_mismatched_one_counts(self):
        tid = self.ticket()
        self.check(tid, "CODE_EXECUTION", entry="full_load")
        self.check(tid, "NOT_REPRODUCED", build="patched", entry="safe_load")
        self.check(tid, "NOT_REPRODUCED", build="patched", entry="full_load")
        pack = evidence.pack(store.load(tid))
        self.assertTrue(pack["checklist"]["patched_comparable"])
        self.assertTrue(pack["checklist"]["patched_build_checked"])
        self.assertEqual(pack["patched_run"]["entry_point"], "full_load")

    def test_different_payload_is_not_a_comparison(self):
        tid = self.ticket()
        self.check(tid, "CODE_EXECUTION")
        self.check(tid, "NOT_REPRODUCED", build="patched", payload_sha256="1" * 64)
        pack = evidence.pack(store.load(tid))
        self.assertFalse(pack["checklist"]["patched_comparable"])
        self.assertTrue(any("different payload" in n for n in pack["notes"]), pack["notes"])

    def test_inconclusive_patched_run_does_not_count(self):
        tid = self.ticket()
        self.check(tid, "CODE_EXECUTION")
        self.check(tid, "INCONCLUSIVE", build="patched", why="the sandbox timed out")
        pack = evidence.pack(store.load(tid))
        self.assertTrue(pack["checklist"]["patched_comparable"])
        self.assertFalse(pack["checklist"]["patched_build_checked"])
        self.assertTrue(any("does not show whether" in n for n in pack["notes"]), pack["notes"])
        line = messages.patched_line(store.load(tid), evidence.latest_run(store.load(tid), "vulnerable"))
        self.assertIn("does not show whether 5.4 fixed this", line)


class ReviewsReferToEvidence(Base):
    def test_concur_records_its_runs_and_goes_stale(self):
        tid = self.ticket()
        self.check(tid, "CODE_EXECUTION")
        self.skeptic(tid)
        record = store.load(tid)
        self.assertEqual(record["skeptic"]["evidence"]["vulnerable"], record["runs"][0]["file"])
        self.assertTrue(evidence.pack(record)["checklist"]["skeptic_verdict_current"])
        self.check(tid, "NOT_REPRODUCED", entry="safe_load")  # new evidence that changes the result
        record = store.load(tid)
        self.assertTrue(record["skeptic"]["stale"])
        self.assertFalse(evidence.pack(record)["checklist"]["skeptic_verdict_current"])
        self.assertIn("STALE", evidence.text(evidence.pack(record)))
        self.assertIn("skeptic_stale", [e["what"] for e in record["timeline"]])

    def test_escalate_with_a_stale_concur_is_refused_until_reviewed_again(self):
        tid = self.ticket()
        self.check(tid, "CODE_EXECUTION")
        self.skeptic(tid)
        self.check(tid, "CODE_EXECUTION", build="patched")
        with self.assertRaises(states.IllegalTransition) as caught:
            actions.decide(tid, "escalate", "human", "maintainer")
        self.assertIn("earlier evidence", str(caught.exception))
        self.skeptic(tid)
        actions.decide(tid, "escalate", "human", "maintainer")
        self.assertEqual(store.load(tid)["status"], "escalated")


class EscalationNeedsReview(Base):
    def test_escalate_without_any_review_is_refused(self):
        tid = self.ticket()
        self.check(tid, "CODE_EXECUTION")
        self.say(self.agent, "@prove-it-intake escalate %s" % tid)
        self.assertEqual(store.load(tid)["status"], "reproduced")
        self.assertIn("no current Skeptic concur", self.agent.triage.text())

    def test_override_lets_a_maintainer_escalate_without_review_and_is_recorded(self):
        tid = self.ticket()
        self.check(tid, "CODE_EXECUTION")
        self.say(self.agent, "@prove-it-intake override %s urgent, reviewed by hand" % tid)
        self.assertIn("overrode the missing Skeptic review", self.agent.triage.text())
        self.say(self.agent, "@prove-it-intake escalate %s" % tid)
        record = store.load(tid)
        self.assertEqual(record["status"], "escalated")
        self.assertEqual(record["override"]["after"], "no current concur")

    def test_override_goes_stale_with_new_evidence(self):
        tid = self.ticket()
        self.check(tid, "CODE_EXECUTION")
        actions.override(tid, "human", "maintainer", "x")
        self.check(tid, "CODE_EXECUTION", build="patched")
        with self.assertRaises(states.IllegalTransition):
            actions.decide(tid, "escalate", "human", "maintainer")

    def test_dispute_still_blocks_and_close_needs_no_review(self):
        tid = self.ticket()
        self.check(tid, "NOT_REPRODUCED")
        self.skeptic(tid, "dispute", "outcome_mismatch the claim is code execution but nothing ran")
        with self.assertRaises(states.IllegalTransition):
            actions.decide(tid, "escalate", "human", "maintainer")
        actions.decide(tid, "close", "human", "maintainer", "slop")
        self.assertEqual(store.load(tid)["status"], "closed")


class OutcomesThatAreNotEvidence(Base):
    def test_invalid_proof_run_does_not_mark_not_reproduced(self):
        tid = self.ticket()
        self.check(tid, "INVALID_PROOF", ran=False)
        record = store.load(tid)
        self.assertEqual(record["status"], "in_triage")
        self.assertTrue(any("refused the proof as invalid" in n for n in evidence.pack(record)["notes"]))

    def test_inconclusive_vulnerable_run_leaves_the_status(self):
        tid = self.ticket()
        self.check(tid, "INCONCLUSIVE", why="the sandbox timed out")
        record = store.load(tid)
        self.assertEqual(record["status"], "in_triage")
        self.assertTrue(any("inconclusive" in n for n in evidence.pack(record)["notes"]))


class InformationLeaks(Base):
    LEAK = VALID.replace("Claimed impact: arbitrary code execution when untrusted YAML is passed to yaml.full_load / FullLoader",
                         "Claimed impact: information disclosure of environment variables")

    def test_info_leak_is_never_reported_as_not_reproduced(self):
        tid = self.ticket(self.LEAK)
        self.assertEqual(store.load(tid)["claim"], "info_leak")
        self.assertIn("Information-leak claims are not decided by the sandbox", self.agent.intake.text())
        self.check(tid, "NOT_REPRODUCED")
        pack = evidence.pack(store.load(tid))
        self.assertFalse(pack["checklist"]["claim_decidable_by_sandbox"])
        self.say(self.agent, "@prove-it-intake close %s no leak shown" % tid)
        text = self.agent.intake.posts[-1][0]
        self.assertIn("not decided by the sandbox", text)
        self.assertNotIn("did not reproduce", text)


class Scope(Base):
    def test_first_reply_states_the_scope(self):
        self.ticket()
        self.assertIn("Scope: Prove It checks PyYAML only, comparing 5.3.1 (vulnerable) with 5.4 (patched)",
                      self.agent.intake.text())


if __name__ == "__main__":
    unittest.main()
