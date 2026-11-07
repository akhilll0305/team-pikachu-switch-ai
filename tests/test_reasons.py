"""Reason-coded disputes and the reporter's one question (U1b, decisions D-013 and D-014). No Docker."""

from unittest import mock

from proveit import actions, config, reasons, states, store
from tests.helpers import WorkDirTest, stub_each, stub_runs

REPORT = ("Title: test\nSeverity: high\nAffected version: 5.3.1\nEntry point: yaml.full_load\nClaimed impact: arbitrary code execution\n\n"
          "```yaml\na: 1\n```\n")
CANARY = "Kp4CANARYz"


class Base(WorkDirTest):
    def ticket(self, outcome="CODE_EXECUTION", text=REPORT, patched=None):
        self.agent = self.make_intake()
        self.report(self.agent, text)
        tid = store.all_tickets()[-1]["id"]
        if outcome == "split":
            with stub_each("CODE_EXECUTION", "CODE_EXECUTION", "NOT_REPRODUCED"):
                actions.check(tid, actor="agent", by="reproducer")
        elif outcome:
            with stub_runs(outcome):
                actions.check(tid, actor="agent", by="reproducer")
        if patched:
            with stub_runs(patched):
                actions.check(tid, "patched", actor="agent", by="reproducer")
        return tid

    def skeptic(self, text):
        self.say(self.agent, "@prove-it-intake " + text, sender="prove-it-skeptic", kind="agent")

    def maintainer(self, text):
        self.say(self.agent, "@prove-it-intake " + text)

    def reporter_text(self):
        return self.agent.intake.text()

    def last_reporter_post(self):
        return self.agent.intake.posts[-1][0]


class Disputes(Base):
    def test_dispute_without_code_refused(self):
        tid = self.ticket()
        self.skeptic("dispute %s" % tid)
        self.assertEqual(store.load(tid)["status"], "reproduced")
        self.assertIn("Refused dispute for %s: give one reason code: not_reproduced, not_clean_reproducible, "
                      "also_on_patched, out_of_scope_api, outcome_mismatch, severity_overclaimed, version_missing, "
                      "patched_not_checked." % tid, self.agent.triage.text())

    def test_unknown_code_refused(self):
        tid = self.ticket()
        self.skeptic("dispute %s the patched build has not been checked" % tid)  # free text, as the old Skeptic posts
        self.assertEqual(store.load(tid)["status"], "reproduced")
        self.assertIn("Refused dispute for %s: give one reason code" % tid, self.agent.triage.text())

    def refused(self, tid, code):
        before = store.load(tid)["status"]
        self.skeptic("dispute %s %s" % (tid, code))
        self.assertEqual(store.load(tid)["status"], before)
        self.assertIn("Refused dispute for %s: %s contradicts the recorded evidence (" % (tid, code), self.agent.triage.text())

    def accepted(self, tid, code):
        self.skeptic("dispute %s %s" % (tid, code))
        record = store.load(tid)
        self.assertEqual((record["status"], record["skeptic"]["code"]), ("disputed", code))
        self.assertIn("%s: disputed by prove-it-skeptic (%s: %s)" % (tid, code, reasons.meaning(code)), self.agent.triage.text())

    def test_not_reproduced_refused_on_a_reproducing_result(self):
        tid = self.ticket("CODE_EXECUTION")
        self.refused(tid, "not_reproduced")
        self.assertIn("(the vulnerable build recorded CODE_EXECUTION, 3/3 clean runs).", self.agent.triage.text())

    def test_not_reproduced_accepted_on_not_reproduced(self):
        self.accepted(self.ticket("NOT_REPRODUCED"), "not_reproduced")

    def test_not_clean_reproducible_refused_when_runs_agree(self):
        self.refused(self.ticket("CODE_EXECUTION"), "not_clean_reproducible")

    def test_not_clean_reproducible_accepted_when_runs_disagree(self):
        self.accepted(self.ticket("split"), "not_clean_reproducible")

    def test_also_on_patched_refused_without_patched_check(self):
        self.refused(self.ticket("CODE_EXECUTION"), "also_on_patched")
        self.assertIn("(no patched check has run).", self.agent.triage.text())

    def test_also_on_patched_refused_when_patched_did_not_reproduce(self):
        self.refused(self.ticket("CODE_EXECUTION", patched="NOT_REPRODUCED"), "also_on_patched")

    def test_also_on_patched_accepted_and_flagged_for_humans(self):
        tid = self.ticket("CODE_EXECUTION", patched="CODE_EXECUTION")
        self.accepted(tid, "also_on_patched")
        self.assertIn("possible new issue on the patched build: needs human review", self.agent.triage.text())

    def test_patched_not_checked_refused_once_patched_ran(self):
        tid = self.ticket("CODE_EXECUTION", patched="NOT_REPRODUCED")
        self.refused(tid, "patched_not_checked")
        self.assertIn("(a patched check is recorded: NOT_REPRODUCED, 3/3 clean runs).", self.agent.triage.text())

    def test_patched_not_checked_accepted_before_patched_runs(self):
        self.accepted(self.ticket("CODE_EXECUTION"), "patched_not_checked")

    def test_judgement_codes_are_accepted_as_given(self):
        for code in ("out_of_scope_api", "outcome_mismatch", "severity_overclaimed", "version_missing"):
            with self.subTest(code=code):
                self.accepted(self.ticket("CODE_EXECUTION"), code)

    def test_later_dispute_replaces_code_keeps_history(self):
        tid = self.ticket("NOT_REPRODUCED")
        self.skeptic("dispute %s version_missing" % tid)
        self.skeptic("dispute %s not_reproduced" % tid)
        record = store.load(tid)
        self.assertEqual(record["skeptic"]["code"], "not_reproduced")
        self.assertEqual([d["code"] for d in record["disputes"]], ["version_missing", "not_reproduced"])
        self.assertEqual([e.get("code") for e in record["timeline"] if e["what"] == "dispute"],
                         ["version_missing", "not_reproduced"])

    def test_concur_on_a_disputed_ticket_is_still_refused(self):
        tid = self.ticket("NOT_REPRODUCED")
        self.skeptic("dispute %s version_missing" % tid)
        self.skeptic("concur %s" % tid)
        self.assertEqual(store.load(tid)["skeptic"]["verdict"], "dispute")
        self.assertIn("Refused concur for %s" % tid, self.agent.triage.text())

    def test_note_never_reaches_reporter(self):
        tid = self.ticket("NOT_REPRODUCED")
        self.skeptic("dispute %s outcome_mismatch %s internal remark" % (tid, CANARY))
        self.assertIn(CANARY, self.agent.triage.text(), "the note stays in triage")
        self.maintainer("override %s" % tid)
        self.maintainer("close %s not a bug" % tid)
        self.maintainer("notify %s" % tid)
        self.assertNotIn(CANARY, self.reporter_text())


class CloseQuestion(Base):
    def test_close_question_from_reason_arg(self):
        tid = self.ticket("NOT_REPRODUCED")
        self.skeptic("concur %s" % tid)
        self.maintainer("close %s reason=version_missing please say which version" % tid)
        text = self.last_reporter_post()
        self.assertIn("Question from the maintainers: Which PyYAML version is affected?", text)
        self.assertIn("Maintainer's note: please say which version", text)
        self.assertNotIn("reason=", text)
        self.assertEqual(store.load(tid)["decision_question"], "version_missing")

    def test_close_question_from_latest_dispute(self):
        tid = self.ticket("CODE_EXECUTION")
        self.skeptic("dispute %s severity_overclaimed" % tid)
        self.maintainer("close %s overstated" % tid)
        self.assertIn("Question from the maintainers: What makes this high rather than lower?", self.last_reporter_post())

    def test_close_question_derived_after_concur(self):
        # The R-002 case: a concur, not a dispute, so the question comes from the evidence (rule 3).
        tid = self.ticket("NOT_REPRODUCED")
        self.skeptic("concur %s" % tid)
        self.maintainer("close %s safe_load refused the tag; not a vulnerability" % tid)
        text = self.last_reporter_post()
        parts = text.split("\n\n")
        self.assertEqual(parts[0], "**%s closed by a maintainer.**" % tid)
        self.assertEqual(parts[1], "It did not reproduce in the sandbox: NOT_REPRODUCED on PyYAML 5.3.1, 3/3 clean "
                                   "runs (test).")
        self.assertEqual(parts[2], "Question from the maintainers: The sandbox did not reproduce this on PyYAML 5.3.1. "
                                   "Which exact input and entry point trigger it?")
        self.assertEqual(parts[3], "Maintainer's note: safe_load refused the tag; not a vulnerability")

    def test_close_question_derived_when_runs_disagree(self):
        tid = self.ticket("split")
        self.maintainer("close %s flaky" % tid)
        self.assertIn("Question from the maintainers: It reproduced in only 2 of 3 clean runs. What else does it "
                      "need to happen every time?", self.last_reporter_post())

    def test_close_no_question(self):
        tid = self.ticket("CODE_EXECUTION")
        self.skeptic("concur %s" % tid)
        self.maintainer("close %s duplicate" % tid)
        self.assertNotIn("Question from the maintainers", self.last_reporter_post())
        self.assertIsNone(store.load(tid)["decision_question"])

    def test_question_is_never_sent_at_dispute_time(self):
        tid = self.ticket("NOT_REPRODUCED")
        before = len(self.agent.intake.posts)
        self.skeptic("dispute %s not_reproduced" % tid)
        self.assertEqual(len(self.agent.intake.posts), before)

    def test_internal_codes_never_ask_reporter(self):
        for code in ("also_on_patched", "patched_not_checked"):
            self.assertIsNone(reasons.question(code, {"claim": "code_execution", "severity": "high"}, None))
        tid = self.ticket("CODE_EXECUTION")
        self.maintainer("close %s reason=patched_not_checked x" % tid)
        self.assertIn("Refused close for %s: patched_not_checked never gives the reporter a question" % tid,
                      self.agent.triage.text())
        self.skeptic("dispute %s patched_not_checked" % tid)
        self.maintainer("close %s not pursuing" % tid)
        self.assertEqual(store.load(tid)["status"], "closed")
        self.assertNotIn("Question from the maintainers", self.last_reporter_post())

    def test_overridden_dispute_sends_nothing(self):
        tid = self.ticket("CODE_EXECUTION")
        self.skeptic("dispute %s outcome_mismatch" % tid)
        self.maintainer("override %s" % tid)
        self.assertTrue(store.load(tid)["skeptic"]["overridden"])
        self.maintainer("close %s" % tid)
        self.assertNotIn("Question from the maintainers", self.last_reporter_post())

    def test_close_allowed_on_also_on_patched_with_note(self):
        tid = self.ticket("CODE_EXECUTION", patched="CODE_EXECUTION")
        self.skeptic("dispute %s also_on_patched" % tid)
        self.maintainer("close %s the patched hit is a harness artefact, checked by hand" % tid)
        self.assertEqual(store.load(tid)["status"], "closed", "a maintainer may close without an override")

    def test_close_on_also_on_patched_without_note_refused(self):
        tid = self.ticket("CODE_EXECUTION", patched="CODE_EXECUTION")
        self.skeptic("dispute %s also_on_patched" % tid)
        self.maintainer("close %s" % tid)
        self.assertEqual(store.load(tid)["status"], "disputed")
        self.assertIn("Refused close for %s: the patched build also reproduced; add a note saying why you are "
                      "closing." % tid, self.agent.triage.text())

    def test_close_on_also_on_patched_sends_no_question(self):
        tid = self.ticket("CODE_EXECUTION", patched="CODE_EXECUTION")
        self.skeptic("dispute %s also_on_patched" % tid)
        self.maintainer("close %s reason=not_reproduced checked by hand" % tid)
        self.assertEqual(store.load(tid)["status"], "closed")
        self.assertNotIn("Question from the maintainers", self.last_reporter_post())
        self.assertIsNone(store.load(tid)["decision_question"])

    def test_unknown_close_reason_refused(self):
        tid = self.ticket("NOT_REPRODUCED")
        self.maintainer("close %s reason=nonsense x" % tid)
        self.assertEqual(store.load(tid)["status"], "not_reproduced")
        self.assertIn("Refused close for %s: reason= needs one reason code" % tid, self.agent.triage.text())

    def test_info_leak_gets_no_derived_question(self):
        tid = self.ticket("NOT_REPRODUCED", text=REPORT.replace("arbitrary code execution", "information disclosure"))
        self.maintainer("close %s no leak" % tid)
        self.assertNotIn("Question from the maintainers", self.last_reporter_post())

    def test_question_version_comes_from_config(self):
        with mock.patch.dict(config.TARGET["builds"]["vulnerable"], {"version": "9.9.9"}):
            text = reasons.question("not_reproduced", {"claim": "code_execution"}, {"outcome": "NOT_REPRODUCED"})
        self.assertIn("PyYAML 9.9.9", text)
        self.assertNotIn("5.3.1", text)

    def test_question_placeholders_use_enums_only(self):
        report = REPORT.replace("Severity: high", "Severity: high %s" % CANARY).replace(
            "Claimed impact: arbitrary code execution", "Claimed impact: arbitrary code execution %s" % CANARY)
        tid = self.ticket("NOT_REPRODUCED", text=report)
        self.assertEqual((store.load(tid)["severity"], store.load(tid)["claim"]), ("high", "code_execution"))
        for code in ("severity_overclaimed", "outcome_mismatch"):
            text = reasons.question(code, store.load(tid), {"outcome": "NOT_REPRODUCED"})
            self.assertNotIn(CANARY, text)
        self.assertIn("You reported code execution; the sandbox recorded NOT_REPRODUCED. Which input produces "
                      "code execution?", reasons.question("outcome_mismatch", store.load(tid), {"outcome": "NOT_REPRODUCED"}))
        # A value that is not on its closed list yields no question rather than an echo.
        self.assertIsNone(reasons.question("severity_overclaimed", {"severity": CANARY}, None))
        self.assertIsNone(reasons.question("outcome_mismatch", {"claim": CANARY}, {"outcome": CANARY}))
        self.maintainer("close %s reason=severity_overclaimed x" % tid)
        self.assertNotIn(CANARY, self.reporter_text())


class OnlyHumansDecide(Base):
    def test_agents_still_cannot_close_escalate_override(self):
        tid = self.ticket("NOT_REPRODUCED")
        for verb in ("close %s reason=not_reproduced x", "escalate %s", "override %s"):
            self.skeptic(verb % tid)
        self.assertEqual(store.load(tid)["status"], "not_reproduced")
        self.assertEqual(self.agent.triage.text().count("Refused: only maintainers can"), 3)
        for verb in ("close", "escalate"):
            with self.assertRaises(states.IllegalTransition):
                actions.decide(tid, verb, "agent", "skeptic", "x", reason="not_reproduced" if verb == "close" else None)
        with self.assertRaises(states.IllegalTransition):
            actions.override(tid, "agent", "skeptic")
