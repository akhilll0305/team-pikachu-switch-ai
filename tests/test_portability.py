"""Builds and tests everywhere (checkpoint group G): Docker calls cannot hang, failures explain themselves,
and the suite imports on Windows."""

import os
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

from proveit import sandbox

ROOT = Path(__file__).resolve().parent.parent


class DockerTimeouts(unittest.TestCase):
    def test_a_stuck_daemon_reads_as_unavailable(self):
        with mock.patch("proveit.sandbox.shutil.which", return_value="/usr/bin/docker"), \
                mock.patch("proveit.sandbox.subprocess.run", side_effect=subprocess.TimeoutExpired("docker", 20)):
            self.assertFalse(sandbox.docker_available())

    def test_windows_containers_engine_is_not_usable(self):
        result = subprocess.CompletedProcess(["docker"], 0, stdout="windows\n", stderr="")
        with mock.patch("proveit.sandbox.shutil.which", return_value="docker"), \
                mock.patch("proveit.sandbox.subprocess.run", return_value=result):
            self.assertFalse(sandbox.docker_available())
        result.stdout = "linux\n"
        with mock.patch("proveit.sandbox.shutil.which", return_value="docker"), \
                mock.patch("proveit.sandbox.subprocess.run", return_value=result):
            self.assertTrue(sandbox.docker_available())

    def test_image_probe_times_out_with_a_clear_error(self):
        with mock.patch("proveit.sandbox.subprocess.run", side_effect=subprocess.TimeoutExpired("docker", 20)):
            with self.assertRaises(sandbox.SandboxError) as caught:
                sandbox.image_current("proveit-target:vulnerable")
        self.assertIn("did not finish within 20 s", str(caught.exception))

    def test_every_docker_call_has_a_timeout(self):
        import ast
        tree = ast.parse((ROOT / "proveit" / "sandbox.py").read_text(encoding="utf-8"))
        calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                 and isinstance(n.func.value, ast.Name) and n.func.value.id == "subprocess" and n.func.attr == "run"]
        self.assertTrue(calls)
        for call in calls:
            self.assertIn("timeout", [k.arg for k in call.keywords], "subprocess.run without a timeout at line %d" % call.lineno)
        waits = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                 and n.func.attr == "wait"]
        for call in waits:
            self.assertIn("timeout", [k.arg for k in call.keywords], "wait() without a timeout at line %d" % call.lineno)


class BuildFailures(unittest.TestCase):
    class FakeBuild:
        def __init__(self, lines, code):
            self.lines = lines
            self.returncode = code

        def wait(self, timeout=None):
            return self.returncode

    def build_with(self, lines, code):
        fake = self.FakeBuild(lines, code)
        def popen(cmd, stdout, **kwargs):
            stdout.write("".join(lines).encode("utf-8"))
            return fake
        with mock.patch("proveit.sandbox.image_current", return_value=False), \
                mock.patch("proveit.sandbox.subprocess.Popen", side_effect=popen):
            return sandbox.build("vulnerable", force=True)

    def test_failure_shows_the_end_of_dockers_output(self):
        with self.assertRaises(sandbox.SandboxError) as caught:
            self.build_with(["Step 3/5 : RUN pip install\n", "ERROR: No matching distribution found for Cython==0.29.37\n"], 1)
        self.assertIn("No matching distribution found", str(caught.exception))
        self.assertIn("exit 1", str(caught.exception))

    def test_hash_mismatch_is_named_as_a_download_problem(self):
        with self.assertRaises(sandbox.SandboxError) as caught:
            self.build_with(["ERROR: THESE PACKAGES DO NOT MATCH THE HASHES FROM THE REQUIREMENTS FILE.\n",
                             "    Cython from https://files.pythonhosted.org/...: Expected sha256 abc Got def\n"], 1)
        self.assertIn("corrupted download, proxy or cache, not the Dockerfile", str(caught.exception))

    def test_success_returns_the_image(self):
        self.assertEqual(self.build_with(["Successfully tagged proveit-target:vulnerable\n"], 0), ["proveit-target:vulnerable"])


class Windows(unittest.TestCase):
    def test_suite_imports_without_unix_only_modules(self):
        # What Windows sees: no `resource` module. Discovery must not error (it did: test_harness imported it).
        code = ("import sys, unittest\n"
                "sys.modules['resource'] = None\n"
                "suite = unittest.defaultTestLoader.discover('tests', top_level_dir='.')\n"
                "def walk(s):\n"
                "    for t in s:\n"
                "        if isinstance(t, unittest.TestSuite):\n"
                "            yield from walk(t)\n"
                "        else:\n"
                "            yield t\n"
                "failed = [t.id() for t in walk(suite) if t.__class__.__name__ == '_FailedTest']\n"
                "print('FAILED_IMPORTS', failed)\n")
        out = subprocess.run([sys.executable, "-c", code], cwd=ROOT, capture_output=True, text=True, timeout=120)
        self.assertIn("FAILED_IMPORTS []", out.stdout, out.stdout + out.stderr)

    def test_harness_tests_skip_when_resource_is_missing(self):
        code = ("import sys, unittest\n"
                "sys.modules['resource'] = None\n"
                "import tests.test_harness as th\n"
                "print('HARNESS', th.harness)\n")
        out = subprocess.run([sys.executable, "-c", code], cwd=ROOT, capture_output=True, text=True, timeout=60)
        self.assertIn("HARNESS None", out.stdout, out.stderr)


if __name__ == "__main__":
    unittest.main()
