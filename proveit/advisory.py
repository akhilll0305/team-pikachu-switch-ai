"""The advisory pack written when a maintainer escalates a ticket (U2, decision D-017).

  work/R-001/advisory/
    osv-draft.json   an OSV record, DRAFT, with a placeholder ID (x_DRAFT-PROVEIT-R-001)
    ghsa-draft.md    a GitHub Security Advisory draft, first line "DRAFT, needs maintainer review"
    timeline.md      every recorded event in order, with UTC timestamps
    timeline.json    the same, as data

Everything comes from fixed fields the ticket already holds and the run
records: never reporter prose, and never the payload itself (work/ is
readable by the agents). The payload is named by its SHA-256, size and known
tags, and the private copy by a relative path only. No fixed version is
claimed: the pack says only what the sandbox recorded.

The same ticket data always gives the same bytes (no "now" timestamps), and
each file is written atomically with LF line endings, so an export's
manifest holds.
"""

import json
import os
import re
import tempfile
from pathlib import Path

from . import judge, reasons, store, targets
from .evidence import comparable, latest_run, patched_for

FOLDER = "advisory"
FILES = ("osv-draft.json", "ghsa-draft.md", "timeline.md", "timeline.json")
DRAFT = "DRAFT, needs maintainer review"
# The ossf/osv-schema version the draft follows (a copy is in tests/data/osv-schema.json).
OSV_SCHEMA_VERSION = "1.9.2"
CVE = re.compile(r"\bCVE-\d{4}-\d{4,}\b")
PRIVATE_PAYLOAD = "the private copy, private/%s/payload.yaml (its folder is shown by `python -m proveit doctor`)"


def folder(ticket_id):
    return store.work_dir() / ticket_id / FOLDER


def draft_id(ticket_id):
    """A placeholder, never a real OSV, GHSA or CVE ID. `x_` is OSV's prefix for local databases."""
    return "x_DRAFT-PROVEIT-%s" % ticket_id


def _event(record, what):
    for event in reversed(record.get("timeline", [])):
        if event.get("what") == what:
            return event
    return None


def _result(run):
    return "%s, %s" % (run.get("outcome"), judge.repeats(run)) if run else "not checked"


def maintainer_aliases(note):
    """CVE IDs in the maintainer's escalate note, in order, without repeats."""
    seen = []
    for cve in CVE.findall(note or ""):
        if cve not in seen:
            seen.append(cve)
    return seen


def facts(record):
    """The recorded facts every file of the pack is built from."""
    vulnerable = latest_run(record, "vulnerable")
    patched = patched_for(record, vulnerable)
    same = comparable(vulnerable, patched)
    escalated = _event(record, "escalate") or {}
    target = targets.for_record(record)
    return {
        "id": record["id"],
        "target_name": target.name,
        "package": target.pypi_name,
        "ecosystem": "PyPI",
        "claim": record.get("claim") if record.get("claim") in reasons.CLAIM_WORDS else None,
        "severity": record.get("severity") if record.get("severity") in reasons.SEVERITIES else "unrated",
        "entry_point": record.get("entry_point") if record.get("entry_point") in target.entry_points else None,
        "entry_points": target.entry_points,
        "payload_noun": target.payload_noun,
        "payload_sha256": record.get("payload_sha256"),
        "payload_bytes": record.get("payload_bytes"),
        "tags": list(record.get("tags") or []),
        "reported_version": record.get("affected_version") or None,
        "vulnerable_version": target.vulnerable_version,
        "patched_version": target.patched_version,
        "vulnerable": vulnerable,
        "patched": patched if same else None,
        "patched_other": patched if patched is not None and not same else None,
        "escalated_at": escalated.get("at"),
        "escalated_by": escalated.get("by"),
        "aliases": maintainer_aliases(escalated.get("note")),
    }


def osv(f):
    vulnerable, patched = f["vulnerable"], f["patched"]
    reproduced = bool(vulnerable) and vulnerable.get("outcome") in judge.REPRODUCING
    claim_words = reasons.CLAIM_WORDS.get(f["claim"], "an unconfirmed issue")
    details = "Claim %s; entry point %s; vulnerable build %s %s: %s; patched build %s: %s." % (
        f["claim"] or "unknown", f["entry_point"] or "unknown", f["target_name"], f["vulnerable_version"],
        _result(vulnerable), f["patched_version"], _result(patched))
    database = {
        "status": DRAFT,
        "generated_by": "Prove It",
        "prove_it_ticket": f["id"],
        "reported_affected_version": f["reported_version"] or "not stated",
        "tested": {"vulnerable": "%s: %s" % (f["vulnerable_version"], _result(vulnerable)),
                   "patched": "%s: %s" % (f["patched_version"], _result(patched))},
    }
    if patched and patched.get("outcome") == judge.NOT_REPRODUCED:
        database["not_reproduced_on"] = [f["patched_version"]]
    if not reproduced:
        database["note"] = "the vulnerable build did not reproduce it reliably; escalated on a maintainer's judgement"
    record = {
        "schema_version": OSV_SCHEMA_VERSION,
        "id": draft_id(f["id"]),
        "modified": f["escalated_at"],
        "summary": "DRAFT: %s in %s via %s (Prove It %s)" % (
            claim_words, f["target_name"], f["entry_point"] or "an unknown entry point", f["id"]),
        "details": details,
        # Only versions the sandbox ran and saw reproduce; the reporter's wording is in database_specific.
        "affected": [{"package": {"ecosystem": f["ecosystem"], "name": f["package"]},
                      "versions": [f["vulnerable_version"]] if reproduced else []}],
        "database_specific": database,
    }
    if f["aliases"]:
        record["aliases"] = f["aliases"]
        database["aliases_source"] = "maintainer-supplied (from the escalate note)"
    return record


def timeline(record):
    """Every recorded step, in the order it was recorded, plus the steps that are missing."""
    events = [{"at": record.get("created_at"), "event": "received", "detail": "report received by Intake"}]
    checks = {"vulnerable": iter([r for r in record.get("runs", []) if r["build"] == "vulnerable"]),
              "patched": iter([r for r in record.get("runs", []) if r["build"] == "patched"])}
    for event in record.get("timeline", []):
        what = event.get("what")
        if what in ("receive", "followup", "release") and event.get("to") == "in_triage":
            events.append({"at": event["at"], "event": "proof accepted",
                           "detail": "payload sha256 %s" % record.get("payload_sha256")})
        elif what in ("check", "check_patched"):
            build = event.get("build") or ("vulnerable" if what == "check" else "patched")
            entry = next(checks[build], None) or {}
            _target = targets.for_record(record)
            events.append({"at": event["at"], "event": "check (%s build)" % build, "detail": "%s on %s %s, %s/%s clean runs, image %s" % (
                entry.get("outcome") or event.get("outcome"), _target.name, _target.version(build),
                entry.get("agreeing", 1), entry.get("container_runs", 1), entry.get("image_id") or "not recorded")})
        elif what in ("concur", "dispute"):
            events.append({"at": event["at"], "event": "Skeptic verdict",
                           "detail": what + (" (%s)" % event["code"] if event.get("code") else "")})
        elif what in ("skeptic_stale", "override_stale"):
            events.append({"at": event["at"], "event": what.replace("_", " "), "detail": "made on earlier evidence"})
        elif what == "override":
            events.append({"at": event["at"], "event": "maintainer override",
                           "detail": "cleared %s" % (", ".join(event.get("cleared") or []) or "the missing Skeptic review")})
        elif what in ("escalate", "close"):
            events.append({"at": event["at"], "event": "maintainer decision", "detail": what})
    missing = []
    if not any(r["build"] == "vulnerable" for r in record.get("runs", [])):
        missing.append("vulnerable build: not checked")
    if not any(r["build"] == "patched" for r in record.get("runs", [])):
        missing.append("patched build: not checked")
    if not any(e.get("what") in ("concur", "dispute") for e in record.get("timeline", [])):
        missing.append("Skeptic verdict: none recorded")
    if not any(e.get("what") == "override" for e in record.get("timeline", [])):
        missing.append("maintainer override: none")
    return {"ticket": record["id"], "status": DRAFT, "events": events, "missing": missing}


def timeline_md(t):
    lines = [DRAFT, "", "# Timeline for %s" % t["ticket"], "",
             "Every step as Prove It recorded it, in order (UTC). Nothing here is estimated.", "",
             "| time (UTC) | step | detail |", "| --- | --- | --- |"]
    lines += ["| %s | %s | %s |" % (e["at"], e["event"], e["detail"]) for e in t["events"]]
    lines += ["", "## Missing steps", ""] + (["- " + m for m in t["missing"]] or ["- none"])
    return "\n".join(lines) + "\n"


def ghsa_md(f, record):
    vulnerable, patched, other = f["vulnerable"], f["patched"], f["patched_other"]
    claim_words = reasons.CLAIM_WORDS.get(f["claim"], "an unconfirmed issue")
    entry = f["entry_point"] or "unknown"
    lines = [DRAFT, "",
             "# DRAFT: %s in %s via %s" % (claim_words, f["target_name"], entry), "",
             "## Summary", "",
             "A report to Prove It (%s) claims %s when an application passes untrusted %s to `%s`. "
             "The claimed severity is %s. This draft says only what the sandbox recorded; a maintainer must "
             "review and complete it." % (f["id"], claim_words, f["payload_noun"], f["entry_points"].get(entry, entry), f["severity"]), "",
             "## Affected versions", "",
             "- Reported affected version: %s (as stated in the report, not tested as such)" % (f["reported_version"] or "not stated"),
             "- Tested vulnerable build, %s %s: %s" % (f["target_name"], f["vulnerable_version"], _result(vulnerable)),
             "- Patched build, %s %s: %s" % (f["target_name"], f["patched_version"], _result(patched) if patched else "not checked"),
             ]
    if other:
        lines.append("- A patched run through a different entry point or payload is not a comparison: %s" % _result(other))
    lines += ["", "No fixed version is claimed. Only the two pinned builds were run.", "",
              "## How it was reproduced", "",
              "- Entry point: `%s`" % entry,
              "- Payload: not included in this draft. SHA-256 `%s`, %s bytes, known tags: %s. The payload is in %s." % (
                  f["payload_sha256"], f["payload_bytes"], ", ".join("`%s`" % t for t in f["tags"]) or "none",
                  PRIVATE_PAYLOAD % f["id"]),
              "- Builds: %s %s (vulnerable) and %s (patched), in a container with no network, a read-only file "
              "system, an unprivileged user, all capabilities dropped and fixed limits." % (
                  f["target_name"], f["vulnerable_version"], f["patched_version"]),
              "- Each check ran the payload several times in fresh containers; n/N above is how many agreed.", "",
              "## Evidence", "",
              "| file | SHA-256 |", "| --- | --- |"]
    for entry_ in record.get("runs", []):
        path = store.work_dir() / record["id"] / "runs" / Path(entry_["file"]).name
        digest = _sha256_file(path) if path.exists() else "missing"
        lines.append("| %s | %s |" % (entry_["file"], digest))
    lines += ["", "## Timeline", "", "See [timeline.md](timeline.md) (every step with UTC timestamps).",
              "", "Aliases: %s" % (", ".join(f["aliases"]) + " (maintainer-supplied)" if f["aliases"] else "none")]
    return "\n".join(lines) + "\n"


def _sha256_file(path):
    import hashlib
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def build(record):
    """name -> text for every file of the pack."""
    f = facts(record)
    t = timeline(record)
    return {
        "osv-draft.json": json.dumps(osv(f), indent=2, sort_keys=True) + "\n",
        "ghsa-draft.md": ghsa_md(f, record),
        "timeline.md": timeline_md(t),
        "timeline.json": json.dumps(t, indent=2, sort_keys=True) + "\n",
    }


def _write_lf(path, text):
    """Atomic (temp file + rename) and always LF, so hashes hold on every OS."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=path.name + ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def write(record):
    """Write the pack for an escalated ticket. Only a successful escalate calls this."""
    if record.get("status") != "escalated":
        raise ValueError("an advisory pack is written only for an escalated ticket, not %s" % record.get("status"))
    out = folder(record["id"])
    for name, text in build(record).items():
        _write_lf(out / name, text)
    return out


def display_path(ticket_id):
    return "work/%s/%s/" % (ticket_id, FOLDER)
