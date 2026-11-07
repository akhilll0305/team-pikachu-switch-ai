"""Shared test helpers: a temporary work directory and fake Switch rooms."""

import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from proveit import config, intake

REPLAYS = Path(__file__).resolve().parent.parent / "reports" / "replays"


def replay(name):
    return (REPLAYS / name).read_text(encoding="utf-8")


class FakeRoom:
    """Stands in for a Switch connection: records every post."""

    def __init__(self):
        self.posts = []

    def post(self, body, thread_id=None):
        self.posts.append((body, thread_id))

    def text(self):
        return "\n".join(body for body, _ in self.posts)


class WorkDirTest(unittest.TestCase):
    def setUp(self):
        self._old = config.WORK_DIR
        self.tmp = Path(tempfile.mkdtemp(prefix="proveit-test-"))
        config.WORK_DIR = self.tmp / "work"

    def tearDown(self):
        config.WORK_DIR = self._old
        shutil.rmtree(self.tmp, ignore_errors=True)

    def make_intake(self):
        agent = intake.Intake({"agent_name": "prove-it-intake", "maintainers": ["maintainer"]}, source="test")
        agent.intake, agent.triage = FakeRoom(), FakeRoom()
        self._n = getattr(self, "_n", 0)
        return agent

    def report(self, agent, text, sender="reporter", kind="user"):
        self._n = getattr(self, "_n", 0) + 1
        mid = "m%d" % self._n
        agent.on_intake_event(None, "message", {"payload": {"body": text, "message_id": mid, "thread_id": None,
                                                            "sender_name": sender, "sender_kind": kind}})
        return mid

    def reply(self, agent, root, text, sender="reporter"):
        self._n = getattr(self, "_n", 0) + 1
        agent.on_intake_event(None, "message", {"payload": {"body": text, "message_id": "m%d" % self._n,
                                                            "thread_id": root, "sender_name": sender,
                                                            "sender_kind": "user"}})

    def say(self, agent, text, sender="maintainer", kind="user", message_id=None):
        # Simulate the Skeptic carrying the token from the evidence it just read.
        # Race/missing-token tests call on_triage_event directly instead.
        if kind == "agent" and "review=" not in text:
            import re
            from proveit import evidence, store
            match = re.search(r"@prove-it-intake\s+(?:concur|dispute)\s+(R-\d+)", text)
            if match:
                text += " review=" + evidence.review_token(store.load(match.group(1)))
        self._n = getattr(self, "_n", 0) + 1
        payload = {"body": text, "message_id": message_id or "t%d" % self._n, "thread_id": None, "sender_name": sender,
                   "sender_kind": kind}
        if kind == "agent":
            payload["sender"] = "@switch-agent-" + sender
        agent.on_triage_event(None, "message", {"payload": payload})


def fake_run(outcome, build="vulnerable", entry="full_load", **extra):
    """A sandbox record for unit tests that must not need Docker. Never used outside tests."""
    versions = {"vulnerable": "5.3.1", "patched": "5.4"}
    run = {"outcome": outcome, "why": "test", "build": build, "target_version": versions[build],
           "entry_point": entry, "payload_sha256": "0" * 64, "payload_bytes": 10, "seconds": 0.5,
           "peak_rss_mb": 14.0, "marker_created": outcome == "CODE_EXECUTION", "events": [], "ran": True,
           "exception_type": None, "exception_frames": [], "image_id": "sha256:" + "f" * 64}
    run.update(extra)
    return run


def _patch_run_poc(items):
    runs = iter(items)
    counter = iter(range(1, 10 ** 6))

    def run_poc(entry, payload, build, target=None):
        nxt = next(runs)
        run = dict(nxt) if isinstance(nxt, dict) else fake_run(nxt, build=build, entry=entry)
        run.setdefault("container", "proveit-run-fake%06d" % next(counter))
        if target is not None:
            run.setdefault("target", target.key)
            run.setdefault("target_name", target.name)
        return run
    return mock.patch("proveit.actions.sandbox.run_poc", side_effect=run_poc)


def stub_runs(*outcomes):
    """Patch the sandbox so successive *checks* return these outcomes (or run records, for full control).

    Each check runs config.CHECK_RUNS times; every run of one check gets the
    same outcome, so the check's runs agree. Use stub_each for runs that differ.
    """
    return _patch_run_poc([o for o in outcomes for _ in range(config.CHECK_RUNS)])


def stub_each(*outcomes):
    """Patch the sandbox so successive *runs* (not checks) return these outcomes."""
    return _patch_run_poc(list(outcomes))
