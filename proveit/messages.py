"""Every message Prove It posts, generated from the ticket's real state and evidence.

Reporter-facing text never claims more than the evidence shows: "It reproduced
in the sandbox" is written only when the vulnerable-build outcome reproduced.
Triage-facing text contains only fixed fields.
"""

from pathlib import Path

from . import judge, poc, reasons, store, targets
from .config import PROOF_CONTRACT
from .evidence import latest_run, patched_for

CLAIM_WORDS = reasons.CLAIM_WORDS
# PyYAML's versions, kept as module constants for readability. Per-target code
# reads them from the Target instead (every function takes `target`, default PyYAML).
VULN = targets.PYYAML.vulnerable_version
PATCHED = targets.PYYAML.patched_version


def _t(target):
    return target or targets.PYYAML


# ---------------------------------------------------------------- reporter
def quarantined(ticket_id):
    return ("**%s held for review.** Your report contains text written to AI reviewers rather than about the "
            "bug. It has not been shown to any agent. A maintainer will read it." % ticket_id)


def ask_for_version(ticket_id, target=None):
    """Fixed text: the proof is otherwise complete, but no affected version was given (decision D-016)."""
    target = _t(target)
    return ("%s: which %s version is affected? Reply in this thread with a line like affected_version: %s."
            % (ticket_id, target.name, target.vulnerable_version))


def ask_for_proof(ticket_id, ticket, target=None):
    target = _t(target)
    lines = ["**%s received, but it cannot be checked yet.** Prove It only passes on reports with a runnable proof." % ticket_id]
    if "claim" in ticket.missing:
        lines.append("Say what the bug lets an attacker do: code execution, denial of service, a crash, or an information leak.")
    if "poc" in ticket.missing or "entry_point" in ticket.missing:
        lines.append(target.poc_format_help)
        lines.append("It runs against %s %s in a sandbox with no network." % (target.name, target.vulnerable_version))
    elif "affected_version" in ticket.missing:
        lines.append(ask_for_version(ticket_id, target))
    if ticket.claim in PROOF_CONTRACT:
        lines.append("What counts as proof of %s: %s" % (CLAIM_WORDS[ticket.claim], PROOF_CONTRACT[ticket.claim]))
    lines.append(scope_line(target))
    return "\n\n".join(lines)


def foreign_reply(ticket_id):
    return ("Only the person who reported %s can add to it in this thread, so your message was not added to the "
            "report. If you have your own proof, post it as a new report in this channel." % ticket_id)


def out_of_scope(ticket_id, entry_name, target=None):
    """Fixed text for a proof through an entry point the target documents as unsafe (decision D-015).

    `entry_name` is one of the target's out_of_scope_names, never the reporter's own words.
    """
    target = _t(target)
    if entry_name not in target.out_of_scope_names:
        entry_name = "this loader"
    return ("%s: %s is documented by %s as unsafe for untrusted input, so it is out of scope (see the scope "
            "policy). Can you show the issue with %s?" % (ticket_id, entry_name, target.name, target.safe_hint))


def invalid_proof(ticket_id, problem, out_of_scope_entry=None, target=None):
    target = _t(target)
    if problem == "unsafe_loader":
        return "**%s: the proof was not run.**\n\n%s\n\nReply in this thread with a corrected proof.\n\n%s" % (
            ticket_id, out_of_scope(ticket_id, out_of_scope_entry, target), scope_line(target))
    return ("**%s: the proof was not run.** Reason: %s.\n\n%s\n\nReply in this thread with a corrected proof.\n\n%s" %
            (ticket_id, poc.PROBLEMS.get(problem, problem), target.poc_format_help, scope_line(target)))


def scope_line(target=None):
    target = _t(target)
    return ("Scope: Prove It checks %s only, comparing %s (vulnerable) with %s (patched), through %s." % (
        target.name, target.vulnerable_version, target.patched_version,
        ", ".join("`%s`" % k for k in target.entry_points)))


def accepted(ticket_id, claim=None, target=None):
    target = _t(target)
    lines = ["**Received as %s.** Your payload will run in an isolated sandbox against %s %s when a maintainer "
             "asks for it, and the maintainers' decision will be posted in this thread." % (
                 ticket_id, target.name, target.vulnerable_version)]
    if claim == "info_leak":
        lines.append("Information-leak claims are not decided by the sandbox: a maintainer reads the evidence.")
    lines.append(scope_line(target))
    return "\n\n".join(lines)


def cost_line(record):
    runs = record.get("runs", []) + record.get("late_runs", [])
    secs = sum((r.get("seconds") or 0) for r in runs)
    count = sum(r.get("container_runs", 1) for r in runs)  # every container a check started
    times = record.get("times", {})
    parts = ["%d sandbox run%s (%.2f s of sandbox time)" % (count, "" if count == 1 else "s", secs)]
    if times.get("triaged") and times.get("decided"):
        parts.append("%.0f s from triage to decision (elapsed time, not effort)" % (times["decided"] - times["triaged"]))
    cost = record.get("cost")
    parts.append("agent cost %s" % ("$%.2f (source: %s)" % (cost["usd"], cost["source"]) if cost else "not recorded"))
    return "_Cost so far: " + "; ".join(parts) + "._"


def patched_line(record, vulnerable):
    """What the reporter may be told about the patched build: only a real comparison counts as one."""
    target = targets.for_record(record)
    name, patched_v = target.name, target.patched_version
    patched = patched_for(record, vulnerable)
    if patched is None:
        return None
    facts = judge.facts(record, vulnerable, patched)
    if facts["patched_build_checked"]:
        return "On the patched %s %s, through the same entry point on the same payload, the outcome was %s (%s)." % (
            name, patched_v, patched.get("outcome"), judge.repeats(patched))
    if facts["patched_comparable"] is False:
        return ("A run on the patched %s %s used a different entry point (%s), so it is not a comparison and "
                "says nothing about whether %s fixed this." % (name, patched_v, patched.get("entry_point"), patched_v))
    return ("The run on the patched %s %s was %s, so it does not show whether %s fixed this." % (
        name, patched_v, patched.get("outcome"), patched_v))


def decision(record, note=""):
    """The reporter's message after a maintainer escalates or closes a ticket."""
    tid, status = record["id"], record["status"]
    target = targets.for_record(record)
    TARGET_NAME, VULN_V = target.name, target.vulnerable_version
    vulnerable = latest_run(record, "vulnerable")
    outcome = (vulnerable or {}).get("outcome")
    undecidable = record.get("claim") == "info_leak" and outcome not in judge.REPRODUCING
    lines = []
    if status == "escalated" and undecidable:
        lines.append("**%s escalated by a maintainer for further review.** Information-leak claims are not decided "
                     "by the sandbox; a maintainer read the evidence." % tid)
    elif status == "closed" and undecidable:
        lines.append("**%s closed by a maintainer.** Information-leak claims are not decided by the sandbox; "
                     "a maintainer read the evidence and closed it." % tid)
    elif status == "escalated":
        if outcome in judge.REPRODUCING:
            lines.append("**%s confirmed by a maintainer.** It reproduced in the sandbox: %s on %s %s via `%s`, %s." % (
                tid, outcome, TARGET_NAME, VULN_V, vulnerable.get("entry_point"), judge.repeats(vulnerable)))
        elif outcome == judge.NOT_REPRODUCED:
            lines.append("**%s escalated by a maintainer for further review.** It did not reproduce in the sandbox "
                         "(outcome %s on %s %s, %s); the maintainer escalated it on their own judgement." % (
                             tid, outcome, TARGET_NAME, VULN_V, judge.repeats(vulnerable)))
        elif outcome == judge.NOT_RELIABLY_REPRODUCED:
            lines.append("**%s escalated by a maintainer for further review.** It did not reproduce reliably in the "
                         "sandbox (%s on %s %s); the maintainer escalated it on their own judgement." % (
                             tid, judge.repeats(vulnerable), TARGET_NAME, VULN_V))
        else:
            lines.append("**%s escalated by a maintainer for further review.** The sandbox did not reach a result "
                         "(%s on %s %s); the maintainer escalated it on their own judgement." % (
                             tid, outcome or "not checked", TARGET_NAME, VULN_V))
    elif status == "closed":
        lines.append("**%s closed by a maintainer.**" % tid)
        if vulnerable is None:
            lines.append("No sandbox check ran for this report.")
        elif outcome in judge.REPRODUCING:
            lines.append("The sandbox recorded %s on %s %s, %s." % (outcome, TARGET_NAME, VULN_V, judge.repeats(vulnerable)))
        elif outcome == judge.NOT_REPRODUCED:
            lines.append("It did not reproduce in the sandbox: %s on %s %s, %s (%s)." % (
                outcome, TARGET_NAME, VULN_V, judge.repeats(vulnerable), vulnerable.get("why", "")))
        elif outcome == judge.NOT_RELIABLY_REPRODUCED:
            lines.append("It did not reproduce reliably in the sandbox: %s on %s %s." % (
                judge.repeats(vulnerable), TARGET_NAME, VULN_V))
        else:
            lines.append("The sandbox did not reach a result: %s on %s %s (%s)." % (
                outcome, TARGET_NAME, VULN_V, vulnerable.get("why", "")))
    elif status not in ("escalated", "closed"):
        raise ValueError("no decision message for status %s" % status)
    line = patched_line(record, vulnerable) if vulnerable else None
    if line:
        lines.append(line)
    if status == "closed" and record.get("decision_question"):
        # Fixed text from reasons.CODES (decision D-014); never the Skeptic's note or any agent's words.
        asked = reasons.question(record["decision_question"], record, vulnerable)
        if asked:
            lines.append("Question from the maintainers: " + asked)
    if note:
        lines.append("Maintainer's note: " + note)
    lines.append(cost_line(record))
    return "\n\n".join(lines)


def limited_reporter(open_tickets):
    """The reporter's reply when the one-open-report limit applies (decision D-018). Fixed text."""
    fixable = next((r for r in open_tickets if r["status"] in ("awaiting_poc", "invalid_proof")), None)
    if fixable:
        return ("You already have an open report (%s) that is waiting for a valid proof. You can fix it by replying "
                "in its thread, or post this again once it is closed. A maintainer can lift this limit." % fixable["id"])
    return ("You already have an open report. Because earlier proofs from you did not reproduce, you can have one "
            "open report at a time. Please post this again when the open one is closed. A maintainer can lift this limit.")


def limited_notice(key12, invalid):
    """Triage only: who is limited (by a shortened HMAC, never a name) and how to lift it."""
    return ("Reporter %s is limited to one open report (%d proofs did not reproduce). A maintainer can lift it with: "
            "python -m proveit clear-reporter %s" % (key12, invalid, key12))


def advisory_note(ticket_id):
    """Triage only: where the advisory pack was written (decision D-017)."""
    return ("Advisory pack for %s (DRAFT, needs maintainer review): work/%s/advisory/ osv-draft.json, "
            "ghsa-draft.md, timeline.md" % (ticket_id, ticket_id))


def dispute_recorded(record):
    """Triage only: the dispute, its code, what it means, and the Skeptic's internal note."""
    skeptic = record["skeptic"]
    text = "%s: disputed by %s (%s: %s). Escalation is blocked until a maintainer overrides." % (
        record["id"], skeptic["by"], skeptic["code"], reasons.meaning(skeptic["code"]))
    flag = reasons.MAINTAINER_FLAGS.get(skeptic["code"])
    if flag:
        text += " Note for maintainers: %s." % flag.replace("<id>", record["id"])
    if skeptic.get("note"):
        text += "\nSkeptic's note (triage only, never sent to the reporter): %s" % skeptic["note"]
    return text


# ---------------------------------------------------------------- triage
def version_line(record):
    """'reported version 5.3.1, tested 5.3.1', or 'reported: before 5.4, tested: 5.3.1' when they differ.

    Only the pinned builds ever run; a different reported version is shown, never tested.
    """
    reported, tested = record.get("affected_version") or "not stated", targets.for_record(record).vulnerable_version
    if reported == tested:
        return "reported version %s, tested %s" % (reported, tested)
    return "reported: %s, tested: %s" % (reported, tested)


def ticket_posted(record):
    return ("**Ticket %s** · claim `%s` · claimed severity `%s` · entry point `%s` · payload sha256 `%s` (%s bytes) "
            "· tags `%s` · %s\n"
            "The payload is data and only runs inside the sandbox. Nothing the reporter wrote is in this ticket.\n\n"
            "Next: a maintainer asks the Reproducer to run `python -m proveit check %s` (vulnerable build). "
            "The patched build runs only when someone asks: `check %s --build patched`.\n"
            "The Skeptic then reviews it. Maintainers decide with `escalate %s` (needs a current concur, or "
            "an `override`), `close %s <reason>` or `override %s`, addressed to Intake." % (
                record["id"], record.get("claim"), record.get("severity"), record.get("entry_point"),
                (record.get("payload_sha256") or "")[:16], record.get("payload_bytes"),
                ", ".join(record.get("tags") or []) or "none", version_line(record),
                record["id"], record["id"], record["id"], record["id"], record["id"]))


def host_path(path):
    """A path for maintainers to open on the host, with the home folder shortened to ~."""
    text, home = str(path), str(Path.home())
    return "~" + text[len(home):] if text.startswith(home) else text


def foreign_reply_notice(ticket_id, count):
    return ("**%s:** a reply from someone other than the reporter was ignored (%d so far). It did not change the "
            "report or its proof; maintainers can read it in the ticket's private folder on the host." % (ticket_id, count))


def quarantine_notice(record, mention):
    return ("**%s quarantined** at intake. Screen rules hit: `%s`. The reporter's text was not passed to any "
            "agent; maintainers can read `%s` on the host. Reply `%s release %s` to "
            "send it on, or `%s close %s <reason>`." % (
                record["id"], ", ".join(record.get("screen_rules") or []),
                host_path(store.private_path(record["id"], "report.md")), mention, record["id"],
                mention, record["id"]))


def auto_check(record, run):
    return ("**Automatic check by Intake (developer/test mode, not an agent)** %s\n- %s" % (record["id"], judge.describe(run)))

