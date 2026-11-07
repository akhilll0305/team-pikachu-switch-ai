"""The agents' lockdowns: the Skeptic's Codex rules and sandbox profile, and the Reproducer's Claude settings.

The Codex checks run Codex's own policy engine and sandbox when Codex is
installed (they skip otherwise, as on CI). The Claude settings are checked as
data: what is allowed, what is denied, and the role they set.
"""

import json
import os
import shutil
import subprocess
import tempfile
import unittest
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKEPTIC = ROOT / "agents" / "skeptic"
RULES = SKEPTIC / ".codex" / "rules" / "proveit.rules"
CLAUDE = ROOT / "agents" / "reproducer" / ".claude" / "settings.json"
CODEX = shutil.which("codex")

# Every way around the first rules that the 2026-11-05 assessment found, plus near relatives.
BYPASSES = [
    ["Get-Content", "../../work/R-001/ticket.json"], ["type", "..\\..\\work\\R-001\\ticket.json"],
    ["python", "-I", "-c", "print(open('x').read())"], ["python", "-Ic", "print(1)"], ["python", "-E", "-c", "print(1)"],
    ["python3.9", "-c", "print(1)"], ["/usr/bin/python3", "-c", "print(1)"], ["py", "-c", "print(1)"],
    ["python", "-m", "proveit.store"], ["python", "-m", "runpy", "x"], ["dd", "if=x"], ["xargs", "cat"],
    ["tee", "/dev/null"], ["paste", "x"], ["sqlite3"], ["osascript", "-e", "x"], ["powershell", "-c", "gc x"],
    ["pwsh", "-c", "gc x"], ["cmd", "/c", "type", "x"],
    ["cat", "../../work/R-001/ticket.json"], ["head", "x"], ["grep", "-r", "x", "../../work"],
    ["python3", "-c", "print(open('x').read())"], ["python", "-"],
    ["python3", "-m", "json.tool", "x"], ["bash", "-c", "cat x"],
    ["env", "PROVEIT_AGENT=reproducer", "python", "-m", "proveit", "check", "R-001"],
]


def decision(*command):
    out = subprocess.run([CODEX, "execpolicy", "check", "--rules", str(RULES), *command],
                         capture_output=True, text=True, check=True).stdout
    return json.loads(out).get("decision")


@unittest.skipUnless(CODEX, "Codex CLI is not installed")
class SkepticRules(unittest.TestCase):
    def test_its_own_commands_are_not_blocked(self):
        for cmd in (["python", "-m", "proveit", "evidence", "R-001"], ["python3", "-m", "proveit", "show", "R-001"],
                    ["python", "-m", "proveit", "list"], ["python", "-m", "proveit", "tally"]):
            self.assertIsNone(decision(*cmd), cmd)

    def test_every_known_bypass_is_forbidden(self):
        for cmd in BYPASSES:
            self.assertEqual(decision(*cmd), "forbidden", cmd)

    def test_producing_judging_and_human_only_commands_are_forbidden(self):
        for sub in ("check", "override", "cost", "concur", "dispute", "submit", "build", "clear-reporter"):
            for py in ("python", "python3"):
                self.assertEqual(decision(py, "-m", "proveit", sub, "R-001"), "forbidden", (py, sub))


@unittest.skipUnless(CODEX and os.name == "posix", "needs Codex's sandbox (macOS or Linux)")
class SkepticSandbox(unittest.TestCase):
    """The permission profile in agents/skeptic/.codex/config.toml, applied by `codex sandbox` from that folder."""

    def sandboxed(self, *command):
        return subprocess.run([CODEX, "sandbox", "--", *command], cwd=SKEPTIC, capture_output=True, text=True,
                              timeout=60)

    def test_config_loads(self):
        result = subprocess.run([CODEX, "mcp", "list"], cwd=SKEPTIC, capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_private_home_cannot_be_read_and_nothing_can_be_written(self):
        home = Path.home() / ".proveit"
        home.mkdir(exist_ok=True)
        canary = home / ("canary-%s.txt" % uuid.uuid4().hex)
        canary.write_text("SKEPTIC-CANARY")
        target = ROOT / "work" / ("sandbox-write-%s" % uuid.uuid4().hex)
        try:
            read = self.sandboxed("/bin/cat", str(canary))
            self.assertNotIn("SKEPTIC-CANARY", read.stdout)
            self.assertNotEqual(read.returncode, 0)
            write = self.sandboxed("/bin/sh", "-c", "echo x > %s" % target)
            self.assertNotEqual(write.returncode, 0)
            self.assertFalse(target.exists())
        finally:
            canary.unlink()
            if target.exists():
                target.unlink()

    def test_its_commands_still_run(self):
        work = Path(tempfile.mkdtemp(prefix="proveit-sbx-", dir=str(ROOT)))
        try:
            result = self.sandboxed("/usr/bin/env", "PYTHONPATH=../..", "PYTHONDONTWRITEBYTECODE=1",
                                    "PROVEIT_WORK_DIR=%s" % work, "python3", "-m", "proveit", "list")
            self.assertEqual(result.returncode, 0, result.stderr)
        finally:
            shutil.rmtree(work, ignore_errors=True)


class ReproducerSettings(unittest.TestCase):
    def setUp(self):
        self.settings = json.loads(CLAUDE.read_text(encoding="utf-8"))
        self.allow = self.settings["permissions"]["allow"]
        self.deny = self.settings["permissions"]["deny"]

    def test_it_cannot_judge_its_own_evidence(self):
        for rule in self.allow:
            self.assertNotIn(" concur", rule)
            self.assertNotIn(" dispute", rule)
        for py in ("python", "python3"):
            for sub in ("concur", "dispute", "override", "cost", "clear-reporter"):
                self.assertIn("Bash(%s -m proveit %s *)" % (py, sub), self.deny)

    def test_role_and_actor_come_from_its_config(self):
        self.assertEqual(self.settings["env"]["PROVEIT_ACTOR"], "agent")
        self.assertEqual(self.settings["env"]["PROVEIT_AGENT"], "reproducer")

    def test_unlisted_commands_are_denied_and_bypass_is_off(self):
        self.assertEqual(self.settings["permissions"]["defaultMode"], "dontAsk")
        self.assertEqual(self.settings["permissions"]["disableBypassPermissionsMode"], "disable")

    def test_private_home_and_other_pythons_are_denied(self):
        for rule in ("Read(~/.proveit/**)", "Read(//**/.proveit/**)", "Bash(python -I*)", "Bash(python3 -I*)",
                     "Bash(python -c *)", "Bash(python3.*)", "Bash(Get-Content *)", "Bash(xargs *)", "Bash(dd *)",
                     "Edit", "Write", "WebFetch"):
            self.assertIn(rule, self.deny)

    def test_only_proveit_commands_are_allowed(self):
        for rule in self.allow:
            self.assertRegex(rule, r"^Bash\(python3? -m proveit (check|evidence|show|list|tally|export) \*\)$")


if __name__ == "__main__":
    unittest.main()
