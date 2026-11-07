"""Clean-state repeats (U1a, decisions D-011 and D-012): every check runs the payload
config.CHECK_RUNS times, one after another, each in a new container.

No Docker here: the container itself is replaced by a fake that answers the
harness protocol, so sandbox.run_poc's own code (names, mounts, flags, record
parsing) still runs. tests/test_sandbox.py runs the real containers.
"""

import io
import json
import os
from contextlib import redirect_stdout
from unittest import mock

from proveit import actions, cli, config, evidence, export, judge, sandbox, states, store
from tests.helpers import WorkDirTest, fake_run, replay, stub_each, stub_runs

IMAGE = "sha256:" + "a" * 64


class FakeDocker:
    """Answers `docker run` like the harness's parent would, and records every call."""

    def __init__(self, outcomes=("CODE_EXECUTION",), fail_on=None):
        self.outcomes = list(outcomes)
        self.fail_on = fail_on
        self.calls = []

    def __call__(self, cmd, stdin_text, name):
        self.calls.append({"cmd": cmd, "name": name})
        n = len(self.calls)
        if self.fail_on == n:
            return 125, "", "docker: Error response from daemon: test failure\n", False
        outcome = self.outcomes[(n - 1) % len(self.outcomes)]
        record = {"outcome": outcome, "why": "fake", "entry_point": "full_load", "payload_sha256": "0" * 64,
                  "payload_bytes": 10, "seconds": 0.25, "peak_rss_mb": 12.0, "events": [],
                  "marker_created": outcome == "CODE_EXECUTION"}
        return 0, "@@PROVEIT %s %s\n" % (stdin_text.strip(), json.dumps(record)), "", False


class Base(WorkDirTest):
    def ticket(self):
        self.agent = self.make_intake()
        self.report(self.agent, replay("01-real-cve-2020-14343.md"))
        return store.all_tickets()[-1]["id"]

    def fake_docker(self, docker):
        return mock.patch.multiple(sandbox, _execute=docker, image_current=mock.Mock(return_value=True),
                                   image_id=mock.Mock(return_value=IMAGE))

    def cli(self, *argv):
        out = io.StringIO()
        with redirect_stdout(out), mock.patch.dict(os.environ, {"PROVEIT_ACTOR": "agent", "PROVEIT_AGENT": "reproducer"}):
            try:
                cli.main(list(argv))
            except SystemExit as exc:
                out.write(str(exc))
        return out.getvalue()


class Runs(Base):
    def test_three_runs_three_records_three_names(self):
        docker = FakeDocker()
        mounts = set(sandbox._mount_root().iterdir())
        with self.fake_docker(docker):
            run = sandbox.run_check("full_load", "a: 1\n", "vulnerable")
        self.assertEqual(config.CHECK_RUNS, 3)
        self.assertEqual(len(docker.calls), 3)
        self.assertEqual(len(run["runs_detail"]), 3)
        self.assertEqual([d["run"] for d in run["runs_detail"]], [1, 2, 3])
        names = [c["name"] for c in docker.calls]
        self.assertEqual(len(set(names)), 3, names)
        self.assertEqual([d["container"] for d in run["runs_detail"]], names)
        # Every run gets exactly the same isolation flags, and its own read-only mount.
        flags = [[a for a in c["cmd"] if not a.startswith(("proveit-run-",)) and ":/poc:ro" not in a] for c in docker.calls]
        self.assertEqual(flags[0], flags[1])
        self.assertEqual(flags[1], flags[2])
        for needed in ("--network", "none", "--read-only", "--cap-drop", "ALL", "--pids-limit", "--memory"):
            self.assertIn(needed, flags[0])
        mounts_used = [a for c in docker.calls for a in c["cmd"] if ":/poc:ro" in a]
        self.assertEqual(len(set(mounts_used)), 3, "nothing is shared between runs")
        self.assertEqual(set(sandbox._mount_root().iterdir()), mounts, "every run's staging folder is removed")

    def test_runs_are_sequential(self):
        active, most = [0], [0]

        def docker(cmd, stdin_text, name):
            active[0] += 1
            most[0] = max(most[0], active[0])
            try:
                return FakeDocker()(cmd, stdin_text, name)
            finally:
                active[0] -= 1
        with self.fake_docker(docker):
            sandbox.run_check("full_load", "a: 1\n", "vulnerable")
        self.assertEqual(most[0], 1, "runs never overlap")

    def test_all_agree_is_n_of_n(self):
        tid = self.ticket()
        with stub_runs("CODE_EXECUTION"):
            record, run, path = actions.check(tid, actor="agent", by="reproducer")
        self.assertEqual(record["status"], "reproduced")
        self.assertEqual((run["outcome"], run["runs"], run["agreeing"]), ("CODE_EXECUTION", 3, 3))
        self.assertEqual(judge.repeats(run), "3/3 clean runs")
        self.assertEqual(record["runs"][-1]["container_runs"], 3)
        self.assertIn("R-001 vulnerable build: CODE_EXECUTION on PyYAML 5.3.1, 3/3 clean runs (image sha256:",
                      judge.headline(tid, run))

    def test_mixed_is_not_reliably_reproduced_with_split(self):
        tid = self.ticket()
        with stub_each("CODE_EXECUTION", "CODE_EXECUTION", "NOT_REPRODUCED"):
            record, run, _ = actions.check(tid, actor="agent", by="reproducer")
        self.assertEqual(run["outcome"], judge.NOT_RELIABLY_REPRODUCED)
        self.assertEqual(run["split"], {"CODE_EXECUTION": 2, "NOT_REPRODUCED": 1})
        self.assertEqual((run["agreeing"], run["reproducing"]), (2, 2))
        self.assertEqual(record["status"], states.UNRELIABLE)
        self.assertIn("NOT_RELIABLY_REPRODUCED on PyYAML 5.3.1: CODE_EXECUTION 2/3, NOT_REPRODUCED 1/3",
                      judge.headline(tid, run))
        self.assertNotIn("marker_created", run, "observations of runs that disagree stay per run")
        facts = evidence.pack(record)["checklist"]
        self.assertIsNone(facts["outcome_matches_claim"])
        self.assertFalse(facts["vulnerable_runs_agree"])

    def test_evidence_shows_each_run_when_runs_disagree(self):
        tid = self.ticket()
        with stub_each("CODE_EXECUTION", "NOT_REPRODUCED", "CODE_EXECUTION"):
            actions.check(tid, actor="agent", by="reproducer")
        text = evidence.text(evidence.pack(store.load(tid)))
        self.assertIn("runs disagreed: see each run", text)
        self.assertIn("run 1: CODE_EXECUTION, marker yes, 0.50 s", text)
        self.assertIn("run 2: NOT_REPRODUCED, marker no, 0.50 s", text)
        self.assertIn("did not reproduce reliably", text)
        out = self.cli("evidence", tid)
        self.assertIn("runs disagreed: see each run", out)

    def test_image_id_recorded(self):
        tid = self.ticket()
        store.set_payload(tid, "a: 1\n")
        with self.fake_docker(FakeDocker()):
            record, run, path = actions.check(tid, actor="agent", by="reproducer")
        self.assertEqual(run["image_id"], IMAGE)
        self.assertEqual([d["image_id"] for d in run["runs_detail"]], [IMAGE] * 3)
        self.assertEqual(store.load_run(path)["image_id"], IMAGE)
        self.assertEqual(record["runs"][-1]["image_id"], IMAGE)

    def test_invalid_proof_is_zero_container_runs(self):
        docker = FakeDocker()
        with self.fake_docker(docker):
            run = sandbox.run_check("unsafe_load", "a: 1\n", "vulnerable")
        self.assertEqual(docker.calls, [])
        self.assertEqual((run["outcome"], run["runs"]), ("INVALID_PROOF", 0))
        self.assertEqual(judge.repeats(run), "not run (the proof was refused before the sandbox)")


class InfrastructureErrors(Base):
    def test_docker_start_failure_aborts_and_records_nothing(self):
        tid = self.ticket()
        store.set_payload(tid, "a: 1\n")
        docker = FakeDocker(fail_on=2)
        with self.fake_docker(docker), mock.patch.object(sandbox, "_remove") as remove:
            with self.assertRaises(sandbox.SandboxError) as caught:
                actions.check(tid, actor="agent", by="reproducer")
        self.assertIn("could not start sandbox run 2 of 3", str(caught.exception))
        self.assertIn("test failure", str(caught.exception))
        self.assertIn("No outcome was recorded", str(caught.exception))
        self.assertEqual(len(docker.calls), 2, "the check stops at the failed run")
        remove.assert_called_with(docker.calls[1]["name"])
        record = store.load(tid)
        self.assertEqual(record["runs"], [])
        self.assertEqual(record["status"], "in_triage", "an infrastructure error is never NOT_REPRODUCED")
        self.assertEqual(list((config.WORK_DIR / tid / "runs").glob("*.json")), [])

    def test_cli_reports_the_error(self):
        tid = self.ticket()
        with self.fake_docker(FakeDocker(fail_on=1)), mock.patch.object(sandbox, "_remove"):
            out = self.cli("check", tid)
        self.assertIn("sandbox error: could not start sandbox run 1 of 3", out)


class Blocks(Base):
    def unreliable(self):
        tid = self.ticket()
        with stub_each("CODE_EXECUTION", "CODE_EXECUTION", "NOT_REPRODUCED"):
            actions.check(tid, actor="agent", by="reproducer")
        return tid

    def test_unreliable_blocks_escalate_until_override(self):
        tid = self.unreliable()
        self.say(self.agent, "@prove-it-intake escalate %s" % tid)
        self.assertEqual(store.load(tid)["status"], states.UNRELIABLE)
        self.assertIn("its clean runs disagreed (CODE_EXECUTION 2/3, NOT_REPRODUCED 1/3); a maintainer must "
                      "override first", self.agent.triage.text())
        self.say(self.agent, "@prove-it-intake override %s looked at each run" % tid)
        self.say(self.agent, "@prove-it-intake escalate %s" % tid)
        self.assertEqual(store.load(tid)["status"], "escalated")

    def test_concur_does_not_unblock_unreliable(self):
        tid = self.unreliable()
        self.say(self.agent, "@prove-it-intake concur %s" % tid, sender="prove-it-skeptic", kind="agent")
        self.assertEqual(store.load(tid)["skeptic"]["verdict"], "concur")
        self.say(self.agent, "@prove-it-intake escalate %s" % tid)
        self.assertEqual(store.load(tid)["status"], states.UNRELIABLE)
        self.assertIn("a concur is not enough", self.agent.triage.text())

    def test_one_override_clears_dispute_and_unreliable_and_records_both(self):
        tid = self.unreliable()
        self.say(self.agent, "@prove-it-intake dispute %s not_clean_reproducible" % tid, sender="prove-it-skeptic", kind="agent")
        self.assertEqual(store.load(tid)["status"], "disputed")
        self.say(self.agent, "@prove-it-intake override %s checked each run" % tid)
        record = store.load(tid)
        self.assertEqual(record["status"], states.UNRELIABLE)
        self.assertEqual(record["override"]["cleared"][-1], "not_reliably_reproduced")
        self.assertTrue(record["override"]["cleared"][0].startswith("dispute"))
        self.assertEqual(len(record["override"]["cleared"]), 2)
        self.assertIn("overrode the dispute", self.agent.triage.text())
        self.assertIn("and the runs-disagree block (CODE_EXECUTION 2/3, NOT_REPRODUCED 1/3); it can now be "
                      "escalated or closed.", self.agent.triage.text())
        self.say(self.agent, "@prove-it-intake escalate %s" % tid)  # no second override needed
        self.assertEqual(store.load(tid)["status"], "escalated")

    def test_a_new_check_makes_the_override_stale(self):
        tid = self.unreliable()
        self.say(self.agent, "@prove-it-intake override %s" % tid)
        with stub_each("CODE_EXECUTION", "NOT_REPRODUCED", "NOT_REPRODUCED"):
            actions.check(tid, actor="agent", by="reproducer")
        self.say(self.agent, "@prove-it-intake escalate %s" % tid)
        self.assertEqual(store.load(tid)["status"], states.UNRELIABLE)


class Compatibility(Base):
    def old_ticket(self):
        """A ticket checked before repeats existed: one run, no counts, no image ID."""
        tid = self.ticket()
        old = fake_run("CODE_EXECUTION")
        old.pop("image_id")
        path = store.save_run(tid, old)
        record = store.load(tid)
        record["runs"].append({"build": "vulnerable", "file": path, "at": store.now(), "by": "reproducer",
                               "actor": "agent", "outcome": "CODE_EXECUTION", "seconds": 0.5, "entry_point": "full_load"})
        record["status"] = "reproduced"
        store.save(record)
        return tid, path

    def test_old_single_run_ticket_loads_shows_and_exports(self):
        tid, path = self.old_ticket()
        file = config.WORK_DIR / tid / "runs" / os.path.basename(path)
        before = file.read_bytes()
        text = evidence.text(evidence.pack(store.load(tid)))
        self.assertIn("CODE_EXECUTION, 1/1 (recorded before repeats)", text)
        self.assertIn("1/1 (recorded before repeats)", self.cli("evidence", tid))
        self.assertIn('"status": "reproduced"', self.cli("show", tid))
        folder = export.export(tid, self.tmp / "out")
        self.assertEqual(export.verify(folder), [])
        self.assertEqual(actions.tally()["sandbox_runs"], 1)
        self.assertEqual(file.read_bytes(), before, "old records are never rewritten")

    def test_tally_counts_container_runs(self):
        tid = self.ticket()
        with stub_runs("CODE_EXECUTION", "NOT_REPRODUCED"):
            actions.check(tid, actor="agent", by="reproducer")
            actions.check(tid, "patched", actor="agent", by="reproducer")
        t = actions.tally()
        self.assertEqual(t["sandbox_runs"], 6, "a 3-run check counts 3 sandbox runs")
        self.assertEqual(t["sandbox_seconds"], 3.0, "sandbox seconds add up every run")
        self.assertIn("6 sandbox runs", actions.tally_text(t))
