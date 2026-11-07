"""The evidence pack: everything an agent may know about a ticket, and nothing a reporter wrote."""

import hashlib
import json

from . import judge, store, targets

TICKET_FIELDS = ("id", "status", "claim", "severity", "entry_point", "payload_sha256", "payload_bytes", "tags",
                 "poc_problem", "missing", "screen_rules", "affected_version", "tested_version")


def latest_entry(record, build):
    for entry in reversed(record.get("runs", [])):
        if entry["build"] == build:
            return entry
    return None


def latest_run(record, build):
    entry = latest_entry(record, build)
    return store.load_run(entry["file"]) if entry else None


def comparable(vulnerable, patched):
    """A patched run compares with the vulnerable one only through the same entry point on the same payload."""
    return bool(vulnerable and patched and vulnerable.get("entry_point") == patched.get("entry_point")
                and vulnerable.get("payload_sha256") == patched.get("payload_sha256"))


def patched_for(record, vulnerable):
    """The latest patched run comparable with `vulnerable`, else the latest patched run (the checklist says which)."""
    latest = None
    for entry in reversed(record.get("runs", [])):
        if entry["build"] != "patched":
            continue
        run = store.load_run(entry["file"])
        if comparable(vulnerable, run):
            return run
        latest = latest or run
    return latest


def current_evidence(record):
    """The run files a verdict or an override refers to: the latest vulnerable run and its patched comparison."""
    vulnerable = latest_entry(record, "vulnerable")
    patched_file = None
    if vulnerable:
        vuln_run = store.load_run(vulnerable["file"])
        for entry in reversed(record.get("runs", [])):
            if entry["build"] == "patched" and comparable(vuln_run, store.load_run(entry["file"])):
                patched_file = entry["file"]
                break
    return {"vulnerable": vulnerable["file"] if vulnerable else None, "patched": patched_file}


def is_current(review, record):
    """True when a Skeptic verdict or an override was made on the evidence the ticket has now."""
    return bool(review) and review.get("evidence") == current_evidence(record)


def review_token(record):
    """Identifies the immutable run files a reviewer actually inspected, not its later verdict."""
    return hashlib.sha256(json.dumps(current_evidence(record), sort_keys=True).encode()).hexdigest()[:16]


def pack(record):
    vulnerable = latest_run(record, "vulnerable")
    patched = patched_for(record, vulnerable)
    facts = judge.facts(record, vulnerable, patched)
    facts["skeptic_verdict_current"] = None if not record.get("skeptic") else is_current(record["skeptic"], record)
    return {
        "review_token": review_token(record),
        "ticket": {k: record.get(k) for k in TICKET_FIELDS if k in record},
        "target": {name: spec["version"] for name, spec in targets.for_record(record).builds.items()},
        "vulnerable_run": judge.summary(vulnerable) if vulnerable else None,
        "patched_run": judge.summary(patched) if patched else None,
        "runs": [{"build": r["build"], "file": r["file"], "outcome": r.get("outcome"), "by": r.get("by"),
                  "container_runs": r.get("container_runs", 1), "agreeing": r.get("agreeing")}
                 for r in record.get("runs", [])],
        "checklist": facts,
        "notes": judge.notes(facts, vulnerable, patched),
        "skeptic": record.get("skeptic"),
        "override": dict(record["override"], current=is_current(record["override"], record)) if record.get("override") else None,
    }


def text(p):
    t = p["ticket"]
    lines = ["Evidence pack %s (status: %s)" % (t["id"], t["status"]),
             "claim %s | claimed severity %s | entry point %s | payload sha256 %s (%s bytes)" % (
                 t.get("claim") or "-", t.get("severity") or "-", t.get("entry_point") or "-",
                 (t.get("payload_sha256") or "-")[:16], t.get("payload_bytes")),
             "tags: %s" % (", ".join(t.get("tags") or []) or "none"),
             "affected version: reported %s, tested %s" % (t.get("affected_version") or "not stated",
                                                          p["target"].get("vulnerable"))]
    for key in ("vulnerable_run", "patched_run"):
        run = p[key]
        if run:
            lines.append("- " + judge.describe(run))
            if judge.disagreed(run):
                lines.append("  runs disagreed: see each run")
                lines.extend("  " + line for line in judge.run_lines(run))
        else:
            lines.append("- %s build: not run yet" % key.split("_")[0])
    lines.append("checklist:")
    for name, value in p["checklist"].items():
        lines.append("  %-34s %s" % (name, "unknown" if value is None else value))
    for note in p["notes"]:
        lines.append("note: " + note)
    if p.get("skeptic"):
        s = p["skeptic"]
        stale = "" if p["checklist"].get("skeptic_verdict_current") else " (STALE: made on earlier evidence; review again)"
        why = ""
        if s.get("code"):
            why = ": %s (%s)" % (s["code"], s.get("reason") or "")
        elif s.get("reason"):
            why = ": " + s["reason"]  # a free-text dispute recorded before reason codes
        lines.append("skeptic: %s by %s%s%s%s" % (s["verdict"], s["by"], why,
                                                " (overridden)" if s.get("overridden") else "", stale))
    if p.get("override"):
        o = p["override"]
        lines.append("override by %s%s" % (o["by"], "" if o.get("current") else " (made on earlier evidence)"))
    lines.append("review token: %s (include review=%s in a room verdict)" % (p["review_token"], p["review_token"]))
    return "\n".join(lines)
