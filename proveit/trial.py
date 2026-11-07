"""Prepare an isolated live trial without registering agents or deploying anything.

  python -m proveit.trial review
  python -m proveit.intake --trial review setup --maintainers <you>
  python -m proveit.intake --trial review run
  python -m proveit doctor --trial review

Generated agent folders/templates/tickets live under .proveit-trials/<name>/
in THIS checkout. Credentials and reporter material stay under its separate
~/.proveit/<checkout>-<hash>/trials/<name>/ directory. Existing files are never
overwritten. PyYAML images are shared, read as before, and never built here.
"""

import argparse
import hashlib
import json
import os
import re
from pathlib import Path

from . import config, targets


def plan(name, root=None):
    if not re.fullmatch(r"[a-z][a-z0-9-]{0,15}", name or ""):
        raise ValueError("trial name must be 1-16 lowercase letters/digits/hyphens, starting with a letter")
    root = Path(root or config.REPO_ROOT).resolve()
    key = hashlib.sha256(str(root).encode()).hexdigest()[:8]
    home = Path.home() / ".proveit" / (root.name + "-" + key) / "trials" / name
    folder = root / ".proveit-trials" / name
    names = {"agent_name": name + "-prove-it-intake", "reproducer": name + "-prove-it-reproducer",
             "skeptic": name + "-prove-it-skeptic"}
    rooms = {t.key: {"intake": name + "-" + t.intake_room, "triage": name + "-" + t.triage_room}
             for t in targets.TARGETS.values()}
    return {"name": name, "root": str(root), "folder": str(folder), "home": str(home),
            "state_file": str(home / "intake.json"), "work": str(folder / "work"),
            "private": str(home / "private"), "target_rooms": rooms,
            "agent_directories": {role: str(folder / "agents" / role) for role in ("reproducer", "skeptic")},
            **names, "intake_room": rooms[targets.DEFAULT_KEY]["intake"],
            "triage_room": rooms[targets.DEFAULT_KEY]["triage"]}


def activate(name):
    """Choose a trial's paths in this process only; creates no directories or files."""
    p = plan(name)
    os.environ.update(PROVEIT_HOME=p["home"], PROVEIT_STATE=p["state_file"],
                      PROVEIT_WORK_DIR=p["work"], PROVEIT_PRIVATE_DIR=p["private"])
    config.PROVEIT_HOME, config.WORK_DIR = Path(p["home"]), Path(p["work"])
    return p


def room_names(state, target):
    """The room names for a target; normal deployments retain their existing defaults."""
    override = (state.get("target_rooms") or {}).get(target.key) or {}
    default_intake, default_triage = target.intake_room, target.triage_room
    if target.key == targets.DEFAULT_KEY:
        default_intake = state.get("intake_room", default_intake)
        default_triage = state.get("triage_room", default_triage)
    return override.get("intake", default_intake), override.get("triage", default_triage)


def _environment(p, role):
    return {"PROVEIT_ACTOR": "agent", "PROVEIT_AGENT": role, "PYTHONPATH": p["root"],
            "PYTHONDONTWRITEBYTECODE": "1", "PROVEIT_HOME": p["home"],
            "PROVEIT_WORK_DIR": p["work"], "PROVEIT_PRIVATE_DIR": p["private"]}


def prepare(name, root=None):
    p = plan(name, root)
    root, folder = Path(p["root"]), Path(p["folder"])
    if folder.exists():
        raise FileExistsError("trial already exists; choose another name (nothing was overwritten)")
    files = {}
    # Copy the reviewed lockdowns, changing only environment paths, never permission rules.
    for role in ("reproducer", "skeptic"):
        for source in (root / "agents" / role).rglob("*"):
            if not source.is_file() or "__pycache__" in source.parts:
                continue
            relative = source.relative_to(root / "agents" / role)
            text = source.read_text(encoding="utf-8")
            if relative.as_posix() == ".claude/settings.json":
                data = json.loads(text)
                data.setdefault("env", {}).update(_environment(p, role))
                text = json.dumps(data, indent=2) + "\n"
            elif relative.as_posix() == ".codex/config.toml":
                env = ", ".join(k + " = " + json.dumps(v) for k, v in _environment(p, role).items())
                text, count = re.subn(r"(?m)^set = \{[^\n]+\}$", lambda _: "set = { " + env + " }", text)
                if count != 1:
                    raise ValueError("Skeptic environment format changed; review it before preparing a trial")
            files[Path("agents") / role / relative] = text
    replacements = {"prove-it-intake": p["agent_name"], "prove-it-reproducer": p["reproducer"],
                    "prove-it-skeptic": p["skeptic"]}
    for t in targets.TARGETS.values():
        replacements[t.intake_room] = p["target_rooms"][t.key]["intake"]
        replacements[t.triage_room] = p["target_rooms"][t.key]["triage"]
    pattern = re.compile("|".join(re.escape(k) for k in sorted(replacements, key=len, reverse=True)))
    for source in (root / "switch").glob("*.template.yaml"):
        text = pattern.sub(lambda m: replacements[m.group()], source.read_text(encoding="utf-8"))
        text = text.replace("name: Prove It\n", "name: Prove It Trial " + name + "\n")
        for role in ("reproducer", "skeptic"):
            text = text.replace("{directory}/agents/" + role,
                                "{directory}/.proveit-trials/" + name + "/agents/" + role)
        text = text.replace("    label: Prove It checkout\n",
                            "    label: Prove It checkout\n    default: " + json.dumps(p["root"]) + "\n")
        files[source.name] = text
    files["trial.json"] = json.dumps(p, indent=2) + "\n"
    # Prepare all content first. No registration, API calls, Docker calls or source edits.
    folder.mkdir(parents=True, exist_ok=False)
    for relative, text in files.items():
        path = folder / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("x", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
    return p


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("name")
    args = parser.parse_args(argv)
    try:
        p = prepare(args.name)
    except (ValueError, FileExistsError) as exc:
        parser.exit(1, str(exc) + "\n")
    print("Prepared trial: " + p["folder"])
    print("No agents or rooms were registered or deployed.")
    print("Next: python -m proveit.intake --trial %s setup --maintainers <your username>" % args.name)
    print("Deploy only the generated trial templates; then run Intake with --trial " + args.name)


if __name__ == "__main__":
    main()
