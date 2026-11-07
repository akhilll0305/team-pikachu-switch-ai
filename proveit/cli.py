"""`python -m proveit ...`: the commands the agents in #triage and maintainers run.

  build                          build the vulnerable and patched sandbox images
  check R-001 [--build patched]  run the ticket's payload on one build (default: vulnerable),
                                 config.CHECK_RUNS times, each in a new container
        [--loader ENTRY_POINT]   ...optionally through another entry point allowed for the ticket's target
  evidence R-001                 the evidence pack: fixed fields only, never reporter text
  show R-001                     the ticket record
  list                           tickets and their status
  concur R-001                   the Skeptic could not disprove the evidence
  dispute R-001 --code CODE      a dispute with one reason code (see proveit/reasons.py) and an optional
        [--note TEXT]            internal note; blocks escalation until a human overrides
  override R-001 --by NAME       a maintainer overrides a dispute (humans only)
  cost R-001 --usd X --source S  a maintainer records agent cost from Switch ROI or a dashboard (humans only)
  clear-reporter KEY             lift a reporter's one-open-report limit (humans only; KEY as Intake printed it)
  tally                          totals for the demo's closing slide
  submit FILE                    create a ticket from a report file, without Switch
  export R-001 [--out DIR]       the ticket's evidence as a folder with a SHA-256 manifest
  export --verify DIR            check an exported folder against its manifest
  doctor [--offline]             is this machine ready for the demo? (changes nothing)

Agents run these with PROVEIT_ACTOR=agent and PROVEIT_AGENT=reproducer or
skeptic, both set by the agent's own config (agents/reproducer/.claude/settings.json,
agents/skeptic/.codex/config.toml). The Reproducer may run check and the
read-only commands; the Skeptic only the read-only ones, and it records concur /
dispute by posting them to Intake in #proveit-triage, where Switch vouches for
the sender. An agent's --by is replaced by its role. override, cost and
clear-reporter are for humans only.
"""

import argparse
import json
import os
import sys
from pathlib import Path

from . import actions, evidence, judge, reasons, reports, sandbox, screen, states, store, targets
from .config import ENTRY_POINTS, TARGET


READ_ONLY = {"evidence", "show", "list", "tally"}
# What each agent role may run. The Reproducer produces evidence; the Skeptic judges it.
ROLE_COMMANDS = {
    "reproducer": READ_ONLY | {"check", "export"},
    # The Skeptic only reads. It records concur / dispute by posting them to Intake in the
    # triage room, where Switch vouches for the sender, so no shell can speak for it.
    "skeptic": set(READ_ONLY),
}


def actor():
    return "agent" if os.environ.get("PROVEIT_ACTOR", "").strip().lower() == "agent" else "human"


def agent_role():
    """The agent's role from its config, or None. Only meaningful when actor() is 'agent'."""
    role = os.environ.get("PROVEIT_AGENT", "").strip().lower()
    return role if role in ROLE_COMMANDS else None


def refuse_for_role(cmd):
    """Why an agent may not run `cmd`, or None. Humans are never refused here."""
    if actor() != "agent":
        return None
    if cmd in ("override", "cost", "clear-reporter"):
        return "only humans may %s; this shell runs as an agent (PROVEIT_ACTOR=agent)" % cmd
    role = agent_role()
    allowed = ROLE_COMMANDS.get(role, READ_ONLY)
    if cmd in allowed:
        return None
    if cmd in ("concur", "dispute"):
        return ("agents record verdicts in #proveit-triage, not here: post `@prove-it-intake %s R-001%s` "
                "(Intake accepts it only from the Skeptic)" % (cmd, " <reason_code> [note]" if cmd == "dispute" else ""))
    if role is None:
        return ("this agent has no role (PROVEIT_AGENT is not reproducer or skeptic), so it may only read: %s"
                % ", ".join(sorted(READ_ONLY)))
    return "the %s may not run %s; it may run: %s" % (role, cmd, ", ".join(sorted(allowed)))


def _print(obj):
    print(json.dumps(obj, indent=2, sort_keys=True))


def cmd_build(args):
    from . import targets
    if getattr(args, "target", None):
        chosen = [targets.get(args.target)]
        if chosen[0].key != args.target:
            raise SystemExit("unknown target %r; known: %s" % (args.target, ", ".join(targets.TARGETS)))
    else:
        chosen = targets.buildable()
    built = []
    for target in chosen:
        built += sandbox.build(force=args.force, quiet=False, target=target)
    print("built: %s" % (", ".join(built) or "nothing (images are current)"))


def cmd_check(args):
    record, run, path = actions.check(args.ticket, args.build, actor(), args.by, args.loader)
    print(judge.headline(args.ticket, run))
    print("  - " + judge.describe(run))
    if judge.disagreed(run):
        print("  runs disagreed: see each run")
        for line in judge.run_lines(run):
            print("    " + line)
    print("ticket status: %s" % record["status"])
    for note in evidence.pack(record)["notes"]:
        print("note: " + note)
    print("evidence: " + path)


def cmd_evidence(args):
    pack = evidence.pack(store.load(args.ticket))
    if args.json:
        _print(pack)
    else:
        print(evidence.text(pack))


def cmd_show(args):
    _print(store.load(args.ticket))


def cmd_list(args):
    for r in store.all_tickets():
        print("%s  %-15s %-18s %s" % (r["id"], r["status"], r.get("claim") or "-", r.get("entry_point") or "-"))


def cmd_concur(args):
    record = actions.concur(args.ticket, actor(), args.by)
    print("%s: %s concurs; status %s" % (args.ticket, args.by, record["status"]))


def cmd_dispute(args):
    record = actions.dispute(args.ticket, args.code, actor(), args.by, args.note or "")
    print("%s: disputed by %s (%s); escalation is blocked until a maintainer overrides" % (
        record["id"], args.by, record["skeptic"]["code"]))


def cmd_override(args):
    record = actions.override(args.ticket, actor(), args.by, args.note or "")
    print("%s: override by %s recorded; status %s" % (record["id"], args.by, record["status"]))


def cmd_cost(args):
    record = actions.record_cost(args.ticket, args.usd, args.source, actor(), args.by)
    print("%s: agent cost $%.2f recorded (source: %s)" % (record["id"], record["cost"]["usd"], record["cost"]["source"]))


def cmd_clear_reporter(args):
    from . import reputation
    try:
        key, _ = reputation.clear(args.key)
    except ValueError as exc:
        sys.exit("refused: %s" % exc)
    print("Reporter %s: limit lifted (invalid count reset to 0)." % reputation.short(key))


def cmd_tally(args):
    t = actions.tally()
    if args.json:
        _print(t)
    else:
        print(actions.tally_text(t))


def cmd_export(args):
    from . import export
    if args.verify:
        problems = export.verify(args.verify)
        for problem in problems:
            print(problem)
        if problems:
            sys.exit("export %s does NOT match its manifest" % args.verify)
        print("export %s matches its manifest" % args.verify)
        return
    if not args.ticket:
        sys.exit("give a ticket id, or --verify <folder>")
    print("exported %s to %s" % (args.ticket, export.export(args.ticket, args.out)))


def cmd_doctor(args):
    if args.trial:
        from .trial import activate
        from . import intake
        try:
            intake.STATE_FILE = Path(activate(args.trial)["state_file"])
        except ValueError as exc:
            sys.exit(str(exc))
    from . import doctor
    report = doctor.run(live=not args.offline)
    if report.failed:
        sys.exit(1)


def cmd_submit(args):
    """Offline intake for one report file: the same parsing and screening as the agent."""
    from .intake import fill, target_for
    text = open(args.file, encoding="utf-8").read()
    result = screen.screen(text)
    ticket = reports.parse(text)
    record = store.create({}, text, source="cli")
    fill(record, ticket)
    if result.blocked:
        record["screen_rules"] = sorted({f["rule"] for f in result.findings})
        store.save_private_json(record["id"], "screen.json", result.findings)
        target = "quarantined"
    else:
        target = target_for(ticket)
    store.apply(record, "receive", "human", "cli", target=target)
    print(record["id"], record["status"])


def main(argv=None):
    parser = argparse.ArgumentParser(prog="python -m proveit", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("build"); p.add_argument("--force", action="store_true")
    p.add_argument("--target", help="which target to build (default: the ones built by default, i.e. PyYAML)")
    p.set_defaults(fn=cmd_build)
    p = sub.add_parser("check")
    p.add_argument("ticket")
    p.add_argument("--build", choices=list(TARGET["builds"]), default="vulnerable")
    p.add_argument("--loader", choices=sorted({e for t in targets.TARGETS.values() for e in t.entry_points}),
                   help="entry point allowed for this ticket's target (validated before running)")
    p.add_argument("--by", default="cli")
    p.set_defaults(fn=cmd_check)
    p = sub.add_parser("evidence"); p.add_argument("ticket"); p.add_argument("--json", action="store_true"); p.set_defaults(fn=cmd_evidence)
    p = sub.add_parser("show"); p.add_argument("ticket"); p.set_defaults(fn=cmd_show)
    sub.add_parser("list").set_defaults(fn=cmd_list)
    p = sub.add_parser("concur"); p.add_argument("ticket"); p.add_argument("--by", default="skeptic"); p.set_defaults(fn=cmd_concur)
    p = sub.add_parser("dispute"); p.add_argument("ticket")
    p.add_argument("--code", required=True, choices=reasons.ORDER, help="exactly one reason code")
    p.add_argument("--note", help="internal note: stays in triage, never sent to the reporter")
    p.add_argument("--by", default="skeptic"); p.set_defaults(fn=cmd_dispute)
    p = sub.add_parser("override"); p.add_argument("ticket"); p.add_argument("--by", required=True)
    p.add_argument("--note"); p.set_defaults(fn=cmd_override)
    p = sub.add_parser("cost"); p.add_argument("ticket"); p.add_argument("--usd", type=float, required=True)
    p.add_argument("--source", required=True); p.add_argument("--by", default="maintainer"); p.set_defaults(fn=cmd_cost)
    p = sub.add_parser("tally"); p.add_argument("--json", action="store_true"); p.set_defaults(fn=cmd_tally)
    p = sub.add_parser("clear-reporter", help="lift a reporter's one-open-report limit (humans only)")
    p.add_argument("key", help="the reporter key Intake printed (12 or more hex characters)")
    p.set_defaults(fn=cmd_clear_reporter)
    p = sub.add_parser("submit"); p.add_argument("file"); p.set_defaults(fn=cmd_submit)
    p = sub.add_parser("export"); p.add_argument("ticket", nargs="?"); p.add_argument("--out")
    p.add_argument("--verify", metavar="DIR"); p.set_defaults(fn=cmd_export)
    p = sub.add_parser("doctor", help="check this machine is ready for the demo")
    p.add_argument("--trial", help="check only this trial's isolated configuration")
    p.add_argument("--offline", action="store_true", help="skip the checks that need the Switch server")
    p.set_defaults(fn=cmd_doctor)
    args = parser.parse_args(argv)
    refusal = refuse_for_role(args.cmd)
    if refusal:
        sys.exit("refused: " + refusal)
    if actor() == "agent" and hasattr(args, "by"):
        args.by = agent_role()  # an agent's name comes from its config, never from its own flag
    try:
        args.fn(args)
    except states.IllegalTransition as exc:
        sys.exit("refused: %s" % exc)
    except FileNotFoundError as exc:
        sys.exit("no such ticket: %s" % exc)
    except sandbox.SandboxError as exc:
        sys.exit("sandbox error: %s" % exc)


if __name__ == "__main__":
    main()
