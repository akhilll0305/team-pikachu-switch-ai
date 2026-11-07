"""A trial must not share the working demo's names, state, tickets or agent folders."""

import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from pathlib import Path
from unittest import mock

try:  # test-only dependency: the project itself is standard library only
    import yaml
except ImportError:  # the Windows CI job runs without it on purpose
    yaml = None

from proveit import config, doctor, intake, targets, trial

ROOT = Path(__file__).resolve().parent.parent


class Plans(unittest.TestCase):
    def test_all_names_and_storage_are_isolated(self):
        p = trial.plan("review")
        self.assertNotEqual(p["agent_name"], intake.DEFAULTS["agent_name"])
        self.assertNotEqual(p["work"], str(config.DEFAULT_WORK_DIR))
        self.assertNotEqual(p["home"], str(config._checkout_home()))
        self.assertNotEqual(Path(p["state_file"]), config._checkout_home() / "intake.json")
        for t in targets.TARGETS.values():
            self.assertNotIn(t.intake_room, p["target_rooms"][t.key].values())
            self.assertNotIn(t.triage_room, p["target_rooms"][t.key].values())
        for role, folder in p["agent_directories"].items():
            self.assertNotEqual(Path(folder), ROOT / "agents" / role)

    def test_bad_names_are_refused_before_any_files_are_created(self):
        for name in ("", "../main", "a/b", "a\\b", "Upper", "a b", "1first", "x" * 17):
            with self.subTest(name=name), self.assertRaises(ValueError):
                trial.plan(name)

    def test_different_worktrees_and_trials_never_share_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            a, b = trial.plan("review", Path(tmp) / "a"), trial.plan("review", Path(tmp) / "b")
            self.assertNotEqual(a["home"], b["home"])
            self.assertNotEqual(a["work"], b["work"])
            self.assertNotEqual(a["home"], trial.plan("other", Path(tmp) / "a")["home"])

    def test_default_room_names_remain_unchanged(self):
        self.assertEqual(trial.room_names({}, targets.SQLPARSE), ("sqlparse-intake", "sqlparse-triage"))
        state = {"intake_room": "old-i", "triage_room": "old-t"}
        self.assertEqual(trial.room_names(state, targets.PYYAML), ("old-i", "old-t"))

    def test_explicit_state_does_not_fall_back_to_other_credentials(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing, legacy = Path(tmp) / "trial.json", Path(tmp) / "legacy.json"
            legacy.write_text('{"api_key":"other-credentials"}')
            with mock.patch("proveit.intake.STATE_FILE", missing), mock.patch("proveit.intake.LEGACY_STATE_FILE", legacy), \
                    mock.patch.dict(os.environ, {"PROVEIT_STATE": str(missing)}):
                state, path = doctor.load_intake_state()
            self.assertIsNone(state)
            self.assertEqual(path, missing)

    def test_activation_changes_only_process_paths_and_creates_nothing(self):
        p = trial.plan("review")
        with mock.patch.dict(os.environ), mock.patch.object(config, "PROVEIT_HOME"), \
                mock.patch.object(config, "WORK_DIR"), mock.patch.object(Path, "mkdir") as mkdir:
            trial.activate("review")
            self.assertEqual(str(config.WORK_DIR), p["work"])
            self.assertEqual(os.environ["PROVEIT_PRIVATE_DIR"], p["private"])
            self.assertEqual(os.environ["PROVEIT_STATE"], p["state_file"])
            mkdir.assert_not_called()


class Preparation(unittest.TestCase):
    def test_generated_agent_stubs_find_checkout_from_nested_trial_folder(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "checkout"
            shutil.copytree(ROOT / "agents", root / "agents")
            shutil.copytree(ROOT / "switch", root / "switch")
            shutil.copytree(ROOT / "proveit", root / "proveit")
            p = trial.prepare("review", root)
            env = {k: v for k, v in os.environ.items()
                   if k not in ("PYTHONPATH", "PROVEIT_ACTOR", "PROVEIT_AGENT")}
            code = ("import os, proveit.config as c; "
                    "print(c.REPO_ROOT); "
                    "print(os.environ['PROVEIT_ACTOR'] + ':' + os.environ['PROVEIT_AGENT'])")
            for role in ("reproducer", "skeptic"):
                with self.subTest(role=role):
                    proc = subprocess.run(
                        [sys.executable, "-c", code],
                        cwd=Path(p["agent_directories"][role]), env=env,
                        capture_output=True, text=True, timeout=30,
                    )
                    self.assertEqual(proc.returncode, 0, proc.stderr)
                    self.assertEqual(proc.stdout.splitlines(), [str(root.resolve()), "agent:" + role])

    def test_setup_refuses_unprepared_trial_before_registering(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(config, "REPO_ROOT", Path(tmp)), \
                mock.patch("proveit.intake.register_agent") as register:
            with self.assertRaisesRegex(SystemExit, "Prepare the trial first"):
                intake.cmd_setup(SimpleNamespace(trial="review"))
            register.assert_not_called()

    def test_trial_setup_refuses_manual_names_or_public_room_creation(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(config, "REPO_ROOT", Path(tmp)), \
                mock.patch("proveit.intake.register_agent") as register:
            p = trial.plan("review")
            Path(p["folder"]).mkdir(parents=True)
            (Path(p["folder"]) / "trial.json").write_text("{}")
            for options in ({"create_rooms": True}, {"agent_name": "prove-it-intake" + "-other"},
                            {"triage_room": "proveit-triage"}):
                args = dict(trial="review", create_rooms=False, agent_name=intake.DEFAULTS["agent_name"],
                            intake_room=None, triage_room=None, reproducer=None, skeptic=None)
                args.update(options)
                with self.subTest(options=options), self.assertRaises(SystemExit):
                    intake.cmd_setup(SimpleNamespace(**args))
            register.assert_not_called()

    @unittest.skipIf(yaml is None, "needs PyYAML to parse the templates (pip install pyyaml); CI's Linux job installs it")
    def test_shared_agent_instructions_are_target_neutral(self):
        template = yaml.safe_load((ROOT / "switch/prove-it.template.yaml").read_text(encoding="utf-8"))
        instructions = {agent["name"]: agent["instructions"] for agent in template["agents"]}
        reproducer = instructions["prove-it-reproducer"]
        skeptic = instructions["prove-it-skeptic"]
        for text in (reproducer, skeptic):
            self.assertNotIn("PyYAML", text)
            self.assertNotIn("safe_load", text)
            self.assertNotIn("full_load", text)
        self.assertIn("ticket's target", reproducer)
        self.assertIn("<entry_point allowed for the ticket's target>", reproducer)
        self.assertIn("this room's scope-policy doc", skeptic)
        self.assertIn("library_frames_recorded", skeptic)
        self.assertIn("code_execution_proven_by_marker", skeptic)
    @unittest.skipIf(yaml is None, "needs PyYAML to parse the templates (pip install pyyaml); CI's Linux job installs it")
    def test_generated_templates_and_settings_keep_isolation_and_lockdowns(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            shutil.copytree(ROOT / "agents", root / "agents")
            shutil.copytree(ROOT / "switch", root / "switch")
            before = {str(p.relative_to(root)): p.read_bytes() for p in root.rglob("*") if p.is_file()}
            with mock.patch("proveit.switch_client.register_agent") as register, \
                    mock.patch("proveit.sandbox.build") as build:
                p = trial.prepare("review", root)
            register.assert_not_called(); build.assert_not_called()
            folder = Path(p["folder"])
            for name in before:
                self.assertEqual((root / name).read_bytes(), before[name], name)
            original = json.loads((root / "agents/reproducer/.claude/settings.json").read_text())
            copied = json.loads((folder / "agents/reproducer/.claude/settings.json").read_text())
            self.assertEqual(original["permissions"], copied["permissions"])
            self.assertEqual(copied["env"]["PROVEIT_WORK_DIR"], p["work"])
            self.assertEqual(copied["env"]["PROVEIT_PRIVATE_DIR"], p["private"])
            codex = (folder / "agents/skeptic/.codex/config.toml").read_text()
            self.assertIn('sandbox_mode = "read-only"', codex)
            self.assertIn('"~/.proveit" = "none"', codex)
            self.assertIn("PROVEIT_PRIVATE_DIR = " + json.dumps(p["private"]), codex)
            for source in (root / "switch").glob("*.template.yaml"):
                text = (folder / source.name).read_text()
                self.assertNotIn("@prove-it-intake", text)
                self.assertNotIn("agents: [prove-it-intake", text)
                self.assertIn("channel_type: channel_private", text)
            text = (folder / "prove-it.template.yaml").read_text()
            self.assertIn("{directory}/.proveit-trials/review/agents/skeptic", text)
            generated = yaml.safe_load(text)
            for role in ("prove-it-reproducer", "prove-it-skeptic"):
                instruction = next(
                    agent["instructions"] for agent in generated["agents"]
                    if agent["name"].endswith(role)
                )
                self.assertNotIn("PyYAML", instruction)
                self.assertNotIn("safe_load", instruction)
                self.assertNotIn("full_load", instruction)
                if role.endswith("reproducer"):
                    self.assertIn("ticket's target", instruction)
                else:
                    self.assertIn("this room's scope-policy doc", instruction)
            self.assertIn("auto_approve: false", text)
            with self.assertRaises(FileExistsError):
                trial.prepare("review", root)


class Connections(unittest.TestCase):
    def test_extra_target_connects_only_to_its_configured_rooms(self):
        p = trial.plan("review")
        state = dict(p, trial="review")
        agent = intake.Intake(state)
        agent.agent = mock.Mock()
        agent.agent.room_id.side_effect = lambda name: {"review-sqlparse-intake": "i", "review-sqlparse-triage": "t"}.get(name)
        conn = mock.Mock(id="connection")
        conn.ready.wait.return_value = True
        agent.agent.connect.return_value = conn
        agent.linked_room = mock.Mock(return_value="t")
        agent.start_extra_targets()
        self.assertEqual(agent.agent.room_id.call_args_list, [mock.call("review-sqlparse-intake"), mock.call("review-sqlparse-triage")])
        self.assertIn("sqlparse", agent.pairs)

    def test_extra_target_refuses_a_link_into_another_room(self):
        p = trial.plan("review")
        agent = intake.Intake(dict(p, trial="review"))
        agent.agent = mock.Mock()
        agent.agent.room_id.side_effect = lambda name: "i" if name.endswith("intake") else "expected"
        agent.agent.connect.return_value.ready.wait.return_value = True
        agent.linked_room = mock.Mock(return_value="production-triage")
        with self.assertRaisesRegex(SystemExit, "unexpected triage"):
            agent.start_extra_targets()
        self.assertEqual(agent.agent.connect.call_count, 1)

    def test_doctor_checks_both_trial_room_pairs(self):
        p = trial.plan("review")
        state = dict(p, api_url="http://invalid", agent_id="trial", api_key="test")
        rooms = [{"name": name, "room_id": name} for pair in p["target_rooms"].values() for name in pair.values()]
        def op(name, args=None, **kw):
            if name == "list_rooms": return rooms
            return {"channel_type": "channel_private" if args["room_id"].endswith("triage") else "channel_public",
                    "agent_names": [p["reproducer"], p["skeptic"]]}
        report = doctor.Report(io.StringIO())
        with mock.patch("proveit.switch_client.Agent") as Agent:
            Agent.return_value.op.side_effect = op
            doctor.check_switch(report, state)
        self.assertFalse(report.failed, report.out.getvalue())
        self.assertIn("review-sqlparse-triage is private", report.out.getvalue())
