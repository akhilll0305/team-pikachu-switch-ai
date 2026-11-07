"""`python -m proveit doctor`: is this machine ready for the demo?

Each check prints PASS, WARN or FAIL with what to do about it. Nothing is
changed. The exit status is 1 if any check FAILs.

Checks that need a running Switch server use Intake's own credentials (from
`python -m proveit.intake setup`) and only read.
"""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from . import config, sandbox

PASS, WARN, FAIL = "PASS", "WARN", "FAIL"


class Report:
    def __init__(self, out=None):
        self.out = out or sys.stdout
        self.results = []

    def add(self, status, what, detail=""):
        self.results.append((status, what, detail))
        self.out.write("%-4s  %s%s\n" % (status, what, (": " + detail) if detail else ""))

    @property
    def failed(self):
        return any(s == FAIL for s, _, _ in self.results)


def check_python(r):
    ok = sys.version_info >= (3, 9)
    r.add(PASS if ok else FAIL, "Python %d.%d" % sys.version_info[:2], "" if ok else "Prove It needs Python 3.9 or newer")


def check_docker(r):
    if not shutil.which("docker"):
        r.add(FAIL, "Docker", "not installed; install Docker Desktop or Colima")
        return False
    if not sandbox.docker_available():
        r.add(FAIL, "Docker", "not running, not responding, or not running Linux containers; start Docker Desktop "
                              "(Linux containers) or `colima start`")
        return False
    r.add(PASS, "Docker engine (Linux containers)")
    return True


def check_emulation(r, machine=None, colima_yaml=None):
    """Mattermost Team Edition ships for amd64 only. On Apple silicon under Colima without Rosetta it runs
    under QEMU, where it crashes (seen three times on 2026-11-05, twice while rooms were created)."""
    import platform
    machine = machine or platform.machine()
    colima_yaml = Path(colima_yaml) if colima_yaml else Path.home() / ".colima" / "default" / "colima.yaml"
    if machine not in ("arm64", "aarch64") or not colima_yaml.exists():
        return
    lines = [l.strip() for l in colima_yaml.read_text(encoding="utf-8").splitlines()]
    rosetta = any(l.replace(" ", "") == "rosetta:true" for l in lines)
    r.add(PASS if rosetta else WARN, "amd64 emulation (Mattermost is amd64-only)",
          "Colima uses Rosetta" if rosetta else "Colima emulates amd64 with QEMU, where Mattermost crashes; run "
          "`colima stop && colima start --vz-rosetta`, then start the containers again")


def check_images(r):
    from . import targets
    for target in targets.TARGETS.values():
        # The default target (PyYAML) must be present; a second target is built
        # only on request, so a missing image there is a WARN, not a FAIL.
        missing_level = FAIL if target.build_by_default else WARN
        build_hint = ("missing or older than the harness; run `python -m proveit build`"
                      if target.build_by_default else
                      "missing; build it with `python -m proveit build --target %s`" % target.key)
        for name, spec in target.builds.items():
            try:
                current = sandbox.image_current(spec["image"], target)
            except sandbox.SandboxError as exc:
                r.add(missing_level, "image %s" % spec["image"], str(exc))
                continue
            r.add(PASS if current else missing_level, "image %s (%s %s)" % (spec["image"], target.name, spec["version"]),
                  "" if current else build_hint)


def check_private_home(r):
    home = config.PROVEIT_HOME
    legacy = config.LEGACY_STATE_DIR / "intake.json"
    if legacy.exists():
        r.add(WARN, "credentials in the checkout", "%s is still in the checkout; it moves to %s the next time "
              "`python -m proveit.intake` runs" % (legacy, home))
    legacy_private = [p for p in config.DEFAULT_WORK_DIR.glob("R-*/private") if p.is_dir()]
    if legacy_private:
        r.add(WARN, "reporter material in work/", "%d ticket(s) still keep private/ in work/; it moves to %s on the "
              "next access" % (len(legacy_private), home / "private"))
    if home.exists() and os.name == "posix" and home.stat().st_mode & 0o077:
        r.add(WARN, "private folder permissions", "%s is readable by other users; run `chmod 700 %s`" % (home, home))
    else:
        r.add(PASS, "private folder", str(home))
    state_file = home / "intake.json"
    if state_file.exists() and os.name == "posix" and state_file.stat().st_mode & 0o077:
        r.add(WARN, "Intake credentials permissions", "%s is readable by other users; run `chmod 600 %s`" % (state_file, state_file))


def load_intake_state():
    """Intake's state, read from where it is now (the doctor never moves files)."""
    from .intake import LEGACY_STATE_FILE, STATE_FILE
    paths = (STATE_FILE,) if os.environ.get("PROVEIT_STATE") else (STATE_FILE, LEGACY_STATE_FILE)
    for path in paths:
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8")), path
    return None, STATE_FILE


def check_intake(r):
    state, path = load_intake_state()
    if not state:
        r.add(FAIL, "Intake registered", "no %s; run `python -m proveit.intake setup --maintainers <you>`" % path)
        return None
    r.add(PASS, "Intake registered", "%s at %s" % (state.get("agent_name"), state.get("api_url")))
    maintainers = state.get("maintainers") or []
    r.add(PASS if maintainers else FAIL, "maintainers", ", ".join(maintainers) if maintainers else
          "none, so every decision is refused; run `python -m proveit.intake maintainers add <your Mattermost username>`")
    return state


def check_switch(r, state):
    from .switch_client import Agent
    agent = Agent(state["api_url"], state["agent_id"], state["api_key"])
    try:
        rooms = agent.op("list_rooms", timeout=10) or []
    except Exception as exc:
        r.add(FAIL, "Switch server", "%s did not answer (%s); start the server in Switch Console" % (
            state["api_url"], type(exc).__name__))
        return
    r.add(PASS, "Switch server", state["api_url"])
    by_name = {room["name"]: room for room in rooms}
    wanted = {"intake": state.get("intake_room", "proveit-intake"), "triage": state.get("triage_room", "proveit-triage")}
    wanted_pairs = list(wanted.items())
    from . import targets
    from .trial import room_names
    for key in state.get("target_rooms") or {}:
        if key == targets.DEFAULT_KEY:
            continue
        if key not in targets.TARGETS:
            r.add(FAIL, "target room configuration", "unknown target " + key)
            continue
        intake_name, triage_name = room_names(state, targets.get(key))
        wanted_pairs.extend([("intake", intake_name), ("triage", triage_name)])
    for role, name in wanted_pairs:
        room = by_name.get(name)
        if not room:
            r.add(FAIL, "room #%s" % name, "Intake is not in it; deploy switch/prove-it.template.yaml")
            continue
        try:
            detail = agent.op("get_room_detail", {"room_id": room["room_id"]}, timeout=10) or {}
        except Exception as exc:
            r.add(WARN, "room #%s" % name, "could not read its details (%s)" % type(exc).__name__)
            continue
        kind = detail.get("channel_type")
        if role == "triage":
            r.add(PASS if kind == "channel_private" else FAIL, "room #%s is private" % name,
                  kind if kind == "channel_private" else "it is %s, so anyone can join it; redeploy the template "
                  "(it sets channel_type: channel_private)" % kind)
            agents = set(detail.get("agent_names") or [])
            for who in (state.get("reproducer", "prove-it-reproducer"), state.get("skeptic", "prove-it-skeptic")):
                r.add(PASS if who in agents else FAIL, "@%s in #%s" % (who, name),
                      "" if who in agents else "not in the room; deploy the template")
        else:
            r.add(PASS, "room #%s" % name, kind or "")
    r.add(PASS, "room link 'triage'", "checked by Intake itself: it refuses to start without it")


def agent_sessions():
    """Switch Console's local agent sessions: (provider, agent name, cwd, mode)."""
    root = Path.home() / ".local" / "state" / "switch" / "sdk-sessions"
    sessions = []
    for path in root.glob("*/config.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        start = (data.get("start") or {})
        given = start.get("input") or {}
        sessions.append({"provider": start.get("provider"), "name": given.get("agentName"), "cwd": given.get("cwd"),
                         "mode": given.get("runtimeMode"), "mtime": path.stat().st_mtime})
    return sorted(sessions, key=lambda s: s["mtime"], reverse=True)


def check_agent_folders(r, sessions=None, state=None):
    sessions = agent_sessions() if sessions is None else sessions
    folders = {"reproducer": config.REPO_ROOT / "agents" / "reproducer", "skeptic": config.REPO_ROOT / "agents" / "skeptic"}
    folders.update({role: Path(path) for role, path in (state or {}).get("agent_directories", {}).items()})
    if not sessions:
        r.add(WARN, "agent folders", "no Switch Console agent sessions found on this machine; deploy the template "
              "and check again")
        return
    for role, folder in folders.items():
        here = [s for s in sessions if s["cwd"] and Path(s["cwd"]).resolve() == folder.resolve()]
        if here:
            s = here[0]
            r.add(PASS, "the %s starts in %s" % (role, folder.relative_to(config.REPO_ROOT).as_posix()), "%s session" % s["provider"])
            if s["mode"]:
                r.add(WARN if s["mode"] == "auto" else PASS, "the %s's permission mode" % role,
                      "Console starts it in %r mode; see agents/README.md (\"Things to check\")" % s["mode"])
        else:
            expected_name = (state or {}).get(role, "prove-it-%s" % role)
            elsewhere = [s for s in sessions if s["name"] == expected_name]
            r.add(FAIL, "the %s's folder" % role, "its session starts in %s, so its lockdown in %s does not apply; "
                  "redeploy the template" % (elsewhere[0]["cwd"] if elsewhere else "no folder found", folder)
                  if elsewhere else "no Console session for it yet; deploy the template")


def check_trust(r, state=None):
    claude = Path.home() / ".claude.json"
    folder = config.REPO_ROOT / "agents" / "reproducer"
    folder = Path((state or {}).get("agent_directories", {}).get("reproducer", folder))
    try:
        projects = json.loads(claude.read_text(encoding="utf-8")).get("projects", {})
        trusted = any(projects.get(str(p), {}).get("hasTrustDialogAccepted") for p in [folder] + list(folder.parents))
        r.add(PASS if trusted else WARN, "Claude Code trusts agents/reproducer",
              "" if trusted else "run `claude` in agents/reproducer once and accept the trust prompt")
    except (OSError, ValueError):
        r.add(WARN, "Claude Code trust", "could not read %s" % claude)
    codex = Path.home() / ".codex" / "config.toml"
    try:
        text = codex.read_text(encoding="utf-8")
        skeptic = config.REPO_ROOT / "agents" / "skeptic"
        skeptic = Path((state or {}).get("agent_directories", {}).get("skeptic", skeptic))
        trusted = any(('[projects."%s"]' % p) in text for p in [skeptic] + list(skeptic.parents))
        r.add(PASS if trusted else WARN, "Codex trusts agents/skeptic",
              "" if trusted else "run `codex` in agents/skeptic once and trust the project")
    except OSError:
        r.add(WARN, "Codex trust", "could not read %s" % codex)


def check_replay_login(r):
    from .replay_login import find_login
    login = find_login()
    r.add(PASS if login else WARN, "replay login (scripts/replay.py)",
          ("as %s at %s" % (login["user"], login["url"])) if login else
          "none; run `python scripts/replay.py login` to post the replays as a Mattermost user")


def run(out=None, live=True):
    r = Report(out)
    check_python(r)
    if check_docker(r):
        check_images(r)
        check_emulation(r)
    check_private_home(r)
    state = check_intake(r)
    if state and live:
        check_switch(r, state)
    check_agent_folders(r, state=state)
    check_trust(r, state=state)
    check_replay_login(r)
    r.out.write("\n%s\n" % ("NOT READY: fix the FAIL lines above." if r.failed else "READY (read any WARN lines)."))
    return r
