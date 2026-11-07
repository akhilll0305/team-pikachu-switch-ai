"""Item 1 of the 2026-11-07 live-trial notes: the agents' `python -m proveit` must work from
their own folders without any environment from their configs.

The Switch-managed Skeptic's first `python -m proveit evidence` failed with
"No module named proveit": its session did not apply PYTHONPATH from
agents/skeptic/.codex/config.toml. These tests run the CLI the way that session
did: from the agent's folder, with PYTHONPATH, PROVEIT_ACTOR and PROVEIT_AGENT
removed, and with the private folder unreachable (Codex denies the Skeptic
~/.proveit).
"""

import os
import subprocess
import sys
import tempfile
from pathlib import Path

from proveit import config, store
from tests.helpers import WorkDirTest, replay

ROOT = Path(__file__).resolve().parent.parent
STRIPPED = ("PYTHONPATH", "PROVEIT_ACTOR", "PROVEIT_AGENT", "PROVEIT_HOME", "PROVEIT_PRIVATE_DIR")


class AgentFolders(WorkDirTest):
    def setUp(self):
        super().setUp()
        agent = self.make_intake()
        self.report(agent, replay("01-real-cve-2020-14343.md"))
        self.tid = store.all_tickets()[-1]["id"]
        # A file where the home folder's Prove It directory would be: any attempt to use it fails.
        self.blocked = Path(tempfile.mkdtemp(prefix="proveit-nohome-")) / "not-a-folder"
        self.blocked.write_text("the agent must not need this", encoding="utf-8")

    def run_cli(self, role, *argv, **extra_env):
        env = {k: v for k, v in os.environ.items() if k not in STRIPPED}
        env.update(PROVEIT_WORK_DIR=str(config.WORK_DIR), PROVEIT_HOME=str(self.blocked), PYTHONDONTWRITEBYTECODE="1")
        env.update(extra_env)
        return subprocess.run([sys.executable, "-m", "proveit"] + list(argv), cwd=ROOT / "agents" / role, env=env,
                              capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60)

    def test_skeptic_reads_evidence_without_environment(self):
        proc = self.run_cli("skeptic", "evidence", self.tid)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("Evidence pack %s" % self.tid, proc.stdout)
        self.assertNotIn("No module named", proc.stderr)

    def test_skeptic_role_is_fixed_by_its_folder(self):
        for argv in (("override", self.tid, "--by", "x"), ("check", self.tid), ("cost", self.tid, "--usd", "1", "--source", "x")):
            with self.subTest(argv[0]):
                proc = self.run_cli("skeptic", *argv)
                self.assertNotEqual(proc.returncode, 0)
                self.assertIn("refused", proc.stdout + proc.stderr)
        # An environment that claims to be a human does not widen the folder's role.
        proc = self.run_cli("skeptic", "override", self.tid, "--by", "x", PROVEIT_ACTOR="human", PROVEIT_AGENT="")
        self.assertIn("only humans may override", proc.stdout + proc.stderr)
        self.assertEqual(store.load(self.tid)["status"], "in_triage")

    def test_reproducer_folder_has_the_reproducer_role(self):
        proc = self.run_cli("reproducer", "evidence", self.tid)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        proc = self.run_cli("reproducer", "override", self.tid, "--by", "x", PROVEIT_ACTOR="human")
        self.assertIn("only humans may override", proc.stdout + proc.stderr)

    def test_stub_points_at_this_checkout(self):
        code = "import proveit.config as c; print(c.REPO_ROOT)"
        for role in ("skeptic", "reproducer"):
            env = {k: v for k, v in os.environ.items() if k not in STRIPPED}
            proc = subprocess.run([sys.executable, "-c", code], cwd=ROOT / "agents" / role, env=env,
                                  capture_output=True, text=True, timeout=30)
            self.assertEqual(Path(proc.stdout.strip()), ROOT, proc.stderr)
