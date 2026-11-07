"""Failure recovery and evidence races found in the second-library review."""

import io
import subprocess
import sys
import time
from contextlib import redirect_stdout
from unittest import mock

from proveit import actions, advisory, cli, evidence, intake, reasons, reputation, sandbox, states, store, targets
from tests.helpers import FakeRoom, WorkDirTest, fake_run, replay, stub_runs
from tests.test_rooms import SQL_PROOF


class FailsOnce(FakeRoom):
    def __init__(self):
        super().__init__()
        self.failed = False

    def post(self, body, thread_id=None):
        if not self.failed:
            self.failed = True
            raise ConnectionError("offline")
        super().post(body, thread_id)


class Recovery(WorkDirTest):
    def event(self, mid, body, thread=None):
        return {"payload": {"body": body, "message_id": mid, "thread_id": thread,
                            "sender_name": "alice", "sender_kind": "user"}}

    def ticket(self, outcome="NOT_REPRODUCED"):
        agent = self.make_intake()
        self.report(agent, replay("01-real-cve-2020-14343.md"))
        tid = store.all_tickets()[-1]["id"]
        with stub_runs(outcome):
            actions.check(tid)
        return agent, tid

    def test_reporter_failure_does_not_lose_triage_and_restart_finishes_delivery(self):
        agent = self.make_intake()
        agent.intake = FailsOnce()
        event = self.event("r1", replay("01-real-cve-2020-14343.md"))
        with self.assertRaises(ConnectionError):
            agent.on_intake_event(None, "message", event)
        self.assertEqual(len(agent.triage.posts), 1)
        restarted = self.make_intake()
        restarted.intake, restarted.triage = agent.intake, agent.triage
        restarted.resume_pending()
        restarted.on_intake_event(None, "message", event)
        self.assertEqual(len(store.all_tickets()), 1)
        self.assertEqual(len(agent.intake.posts), 1)
        self.assertEqual(len(agent.triage.posts), 1)

    def test_triage_failure_retries_only_triage(self):
        agent = self.make_intake()
        agent.triage = FailsOnce()
        event = self.event("r1", replay("01-real-cve-2020-14343.md"))
        with self.assertRaises(ConnectionError):
            agent.on_intake_event(None, "message", event)
        agent.on_intake_event(None, "message", event)
        self.assertEqual(len(agent.intake.posts), 1)
        self.assertEqual(len(agent.triage.posts), 1)

    def test_restart_recovers_a_ticket_saved_before_initial_routing(self):
        agent = self.make_intake()
        event = self.event("r1", replay("01-real-cve-2020-14343.md"))
        with mock.patch("proveit.intake.fill", side_effect=OSError("interrupted")):
            with self.assertRaises(OSError):
                agent.on_intake_event(None, "message", event)
        self.assertEqual(store.load("R-001")["status"], "new")
        restarted = self.make_intake()
        restarted.resume_pending()
        self.assertEqual(len(store.all_tickets()), 1)
        self.assertEqual(store.load("R-001")["status"], "in_triage")
        self.assertEqual(len(restarted.triage.posts), 1)

    def test_followup_retry_finishes_committed_route(self):
        agent = self.make_intake()
        root = self.event("root", replay("02-slop-safe-load-rce.md"))
        agent.on_intake_event(None, "message", root)
        agent.triage = FailsOnce()
        followup = self.event("reply", replay("02-slop-safe-load-rce.followup.md"), "root")
        with self.assertRaises(ConnectionError):
            agent.on_intake_event(None, "message", followup)
        posts = len(agent.intake.posts)
        agent.on_intake_event(None, "message", followup)
        self.assertEqual(len(agent.intake.posts), posts)
        self.assertEqual(len(agent.triage.posts), 1)
        self.assertEqual(store.load("R-001")["status"], "in_triage")

    def test_ack_failure_still_notifies_and_retry_does_not_decide_twice(self):
        agent, tid = self.ticket()
        agent.triage = FailsOnce()
        with self.assertRaises(ConnectionError):
            self.say(agent, "@prove-it-intake close %s original note" % tid, message_id="c1")
        self.assertTrue(store.load(tid)["notified"])
        before = len(agent.intake.posts)
        self.say(agent, "@prove-it-intake close %s original note" % tid, message_id="c1")
        record = store.load(tid)
        self.assertEqual(len(agent.intake.posts), before)
        self.assertEqual(sum(e["what"] == "close" for e in record["timeline"]), 1)
        self.assertIn("original note", agent.intake.posts[-1][0])

    def test_restart_resends_failed_decision_with_original_note(self):
        agent, tid = self.ticket()
        agent.intake = FailsOnce()
        with self.assertLogs("proveit.intake", "ERROR"):
            self.say(agent, "@prove-it-intake close %s preserve this note" % tid)
        self.assertFalse(store.load(tid)["notified"])
        restarted = self.make_intake()
        restarted.intake, restarted.triage = agent.intake, agent.triage
        restarted.resume_pending()
        self.assertTrue(store.load(tid)["notified"])
        self.assertIn("preserve this note", agent.intake.posts[-1][0])

    def test_advisory_failure_is_pending_and_resumes_without_recounting(self):
        agent, tid = self.ticket("CODE_EXECUTION")
        actions.override(tid, "human", "maintainer")
        key = store.load_private_json(tid, "contact.json")["reporter_key"]
        with mock.patch.object(advisory, "write", side_effect=OSError("disk full")):
            self.say(agent, "@prove-it-intake escalate %s confirmed" % tid)
        record = store.load(tid)
        self.assertEqual(record["status"], "escalated")
        self.assertTrue(record["notified"])
        self.assertTrue(record["decision_effects_pending"])
        self.assertEqual(record["advisory_error"], "OSError")
        agent.resume_pending()
        record = store.load(tid)
        self.assertFalse(record["decision_effects_pending"])
        self.assertNotIn("advisory_error", record)
        self.assertTrue((advisory.folder(tid) / "osv-draft.json").exists())
        self.assertEqual(reputation.get(key)["good"], 1)

    def test_check_finishing_after_close_is_audited_without_changing_decision(self):
        agent, tid = self.ticket()
        before = store.load(tid)["runs"][:]
        def finish(*a, **kw):
            actions.decide(tid, "close", "human", "maintainer")
            return fake_run("CODE_EXECUTION")
        with mock.patch.object(sandbox, "run_check", side_effect=finish):
            record, run, path = actions.check(tid)
        self.assertEqual(record["status"], "closed")
        self.assertEqual(record["runs"], before)
        self.assertEqual(record["late_runs"][0]["file"], path)
        self.assertEqual(store.load_run(path)["outcome"], "CODE_EXECUTION")
        self.assertEqual(actions.tally()["sandbox_runs"], 4)  # three original containers + one late mocked run

    def test_delayed_skeptic_verdict_cannot_review_new_evidence(self):
        agent, tid = self.ticket("CODE_EXECUTION")
        token = evidence.review_token(store.load(tid))
        with stub_runs("NOT_REPRODUCED"):
            actions.check(tid)
        payload = {"body": "@prove-it-intake concur %s review=%s" % (tid, token), "message_id": "s1",
                   "sender_name": "prove-it-skeptic", "sender_kind": "agent"}
        agent.on_triage_event(None, "message", {"payload": payload})
        self.assertNotIn("skeptic", store.load(tid))
        self.assertIn("evidence changed", agent.triage.text())

    def test_missing_token_is_refused_but_current_token_is_accepted(self):
        agent, tid = self.ticket()
        payload = {"body": "@prove-it-intake concur " + tid, "message_id": "s1",
                   "sender_name": "prove-it-skeptic", "sender_kind": "agent"}
        agent.on_triage_event(None, "message", {"payload": payload})
        self.assertNotIn("skeptic", store.load(tid))
        payload.update(body=payload["body"] + " review=" + evidence.review_token(store.load(tid)), message_id="s2")
        agent.on_triage_event(None, "message", {"payload": payload})
        self.assertEqual(store.load(tid)["skeptic"]["verdict"], "concur")


class EvidenceAndLoaders(WorkDirTest):
    def test_inconclusive_and_mismatched_patched_are_not_positive_comparisons(self):
        vulnerable = fake_run("CODE_EXECUTION")
        for patched in (fake_run("INCONCLUSIVE", "patched"), fake_run("CODE_EXECUTION", "patched", entry="safe_load"),
                        fake_run("CODE_EXECUTION", "patched", payload_sha256="f" * 64)):
            self.assertIsNotNone(reasons.contradiction("also_on_patched", vulnerable, patched))
            self.assertIsNone(reasons.contradiction("patched_not_checked", vulnerable, patched))

    def test_loader_choices_are_target_specific_and_rejected_before_any_run(self):
        agent = self.make_intake()
        self.report(agent, replay("01-real-cve-2020-14343.md"))
        agent.on_intake_event(None, "message", {"payload": {"body": SQL_PROOF, "message_id": "sql",
            "sender_name": "bob", "sender_kind": "user"}}, target=targets.SQLPARSE)
        with mock.patch.object(sandbox, "run_check", return_value=fake_run("NOT_REPRODUCED")) as run:
            with redirect_stdout(io.StringIO()):
                cli.main(["check", "R-001", "--loader", "full_load"])
                cli.main(["check", "R-002", "--loader", "format"])
            self.assertEqual([c.args[0] for c in run.call_args_list], ["full_load", "format"])
            before = [len(store.load(t)["runs"]) for t in ("R-001", "R-002")]
            for tid, loader in (("R-001", "parse"), ("R-002", "full_load")):
                with self.assertRaisesRegex(states.IllegalTransition, "not an allowed entry point"):
                    actions.check(tid, entry_point=loader)
            self.assertEqual(run.call_count, 2)
            self.assertEqual(before, [len(store.load(t)["runs"]) for t in ("R-001", "R-002")])


class BuildDeadline(WorkDirTest):
    def test_silent_build_is_killed_before_output_reading(self):
        real_popen = subprocess.Popen
        children = []
        def silent(cmd, **kwargs):
            child = real_popen([sys.executable, "-c", "import time; time.sleep(60)"], **kwargs)
            children.append(child)
            return child
        started = time.monotonic()
        with mock.patch.object(sandbox, "image_current", return_value=False), \
                mock.patch.object(sandbox, "BUILD_TIMEOUT", 0.1), \
                mock.patch.object(sandbox.subprocess, "Popen", side_effect=silent):
            with self.assertRaisesRegex(sandbox.SandboxError, "took longer"):
                sandbox.build("vulnerable")
        self.assertLess(time.monotonic() - started, 5)
        self.assertIsNotNone(children[0].returncode)
