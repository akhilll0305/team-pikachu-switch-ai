"""What a sandbox run proves. Rules, not opinions.

The harness's parent process classifies each run into one outcome class
from what it observed itself. This module maps outcomes to ticket states and
builds the evidence pack the agents argue over. Every string it produces
comes from fixed templates and allowlisted values: no reporter text.
"""

CODE_EXECUTION = "CODE_EXECUTION"
CRASH = "CRASH"
RESOURCE_EXHAUSTION = "RESOURCE_EXHAUSTION"
NOT_REPRODUCED = "NOT_REPRODUCED"
INVALID_PROOF = "INVALID_PROOF"
INCONCLUSIVE = "INCONCLUSIVE"
# A check's runs disagreed: some reproduced (or not) and others did not. Not an outcome of one run.
NOT_RELIABLY_REPRODUCED = "NOT_RELIABLY_REPRODUCED"
REPRODUCING = (CODE_EXECUTION, CRASH, RESOURCE_EXHAUSTION)

CLAIM_FOR_OUTCOME = {CODE_EXECUTION: "code_execution", CRASH: "crash", RESOURCE_EXHAUSTION: "denial_of_service"}
# The highest severity each outcome can support. Resource exhaustion is never code execution.
SEVERITY_CEILING = {CODE_EXECUTION: "critical", CRASH: "high", RESOURCE_EXHAUSTION: "medium"}
SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}

RUN_FIELDS = ("build", "target", "target_name", "target_version", "entry_point", "payload_sha256", "payload_bytes",
              "outcome", "why",
              "exit_code", "signal", "timed_out", "seconds", "cpu_seconds", "peak_rss_mb", "marker_created",
              "exception_type", "exception_sha256", "exception_frames", "dropped_values", "ran",
              "runs", "agreeing", "reproducing", "split", "image_id", "total_seconds")
# What one run of a check shows next to the others.
DETAIL_FIELDS = ("run", "container", "image_id", "outcome", "why", "seconds", "cpu_seconds", "peak_rss_mb",
                 "marker_created", "exit_code", "signal", "timed_out", "exception_type")
# Fields that say what was run, not what was observed: the same in every run of one check.
IDENTITY_FIELDS = ("build", "image", "target", "target_name", "target_version", "entry_point", "payload_sha256", "payload_bytes")


CONCLUSIVE = REPRODUCING + (NOT_REPRODUCED,)


def combine(records):
    """One check's outcome from its runs (decision D-011): all agree, or NOT_RELIABLY_REPRODUCED.

    `records` are the parent's records of runs made one after another in new
    containers. If every run has the same outcome, the check has that outcome
    and keeps the first run's observations at the top level, so the evidence
    reads as before. If they differ, only what was run is kept at the top
    level and each run's observations stay in runs_detail.
    """
    first = records[0]
    if not first.get("ran"):
        out = dict(first)
        out.update(runs=0, agreeing=0, reproducing=0, split={}, runs_detail=[], total_seconds=0)
        return out
    split = {}
    for record in records:
        split[record.get("outcome")] = split.get(record.get("outcome"), 0) + 1
    if len(split) == 1:
        out = {k: v for k, v in first.items() if k not in ("run", "container")}
    else:
        out = {k: first[k] for k in IDENTITY_FIELDS if k in first}
        out.update(outcome=NOT_RELIABLY_REPRODUCED, ran=True,
                   why="the %d runs disagreed: %s" % (len(records), split_text(split, len(records))))
    ids = sorted({r.get("image_id") for r in records if r.get("image_id")})
    out.update(runs=len(records), agreeing=max(split.values()), split=split,
               reproducing=sum(n for outcome, n in split.items() if outcome in REPRODUCING),
               image_id=ids[0] if len(ids) == 1 else None,
               total_seconds=round(sum((r.get("seconds") or 0) for r in records), 3),
               runs_detail=list(records))
    if len(ids) > 1:
        out["image_ids"] = ids
    return out


def split_text(split, total):
    """'CODE_EXECUTION 2/3, NOT_REPRODUCED 1/3', most frequent first."""
    return ", ".join("%s %d/%d" % (outcome, n, total)
                     for outcome, n in sorted(split.items(), key=lambda kv: (-kv[1], str(kv[0]))))


def short_image(image_id):
    return (image_id[:19] + "...") if image_id else "unknown image"


def repeats(run):
    """How many clean runs agreed, in words. Records from before repeats say so."""
    if run is None:
        return "not run"
    if "runs_detail" not in run:
        return "1/1 (recorded before repeats)"
    if not run.get("runs"):
        return "not run (the proof was refused before the sandbox)"
    if run.get("outcome") == NOT_RELIABLY_REPRODUCED:
        return split_text(run.get("split") or {}, run["runs"])
    return "%d/%d clean runs" % (run["agreeing"], run["runs"])


def disagreed(run):
    return bool(run) and run.get("outcome") == NOT_RELIABLY_REPRODUCED


def run_lines(run):
    """One fixed line per run of a check whose runs disagreed."""
    lines = []
    for detail in (run or {}).get("runs_detail") or []:
        lines.append("run %s: %s, marker %s, %.2f s" % (detail.get("run"), detail.get("outcome"),
                                                       "yes" if detail.get("marker_created") else "no",
                                                       detail.get("seconds") or 0))
    return lines


def status_for(run):
    """The ticket state a vulnerable-build check supports, or None if it proves nothing either way.

    INVALID_PROOF (the sandbox refused the proof) and INCONCLUSIVE leave the
    ticket where it was: neither is evidence that the bug does not exist.
    """
    outcome = run.get("outcome")
    if outcome in REPRODUCING:
        return "reproduced"
    if outcome == NOT_REPRODUCED:
        return "not_reproduced"
    if outcome == NOT_RELIABLY_REPRODUCED:
        return "not_reliably_reproduced"
    return None


def library_frames(run):
    frames = []
    for event in run.get("events") or []:
        for frame in event.get("library_frames") or []:
            if frame not in frames:
                frames.append(frame)
    return frames[:8]


def summary(run):
    """The fixed fields of one run."""
    out = {k: run.get(k) for k in RUN_FIELDS if k in run}
    out["library_frames"] = library_frames(run)
    out["events"] = [{"event": e["event"], "in_library": e["in_library"]} for e in run.get("events") or []][:20]
    out["repeats"] = repeats(run)
    if "runs_detail" in run:
        out["runs_detail"] = [{k: d.get(k) for k in DETAIL_FIELDS if k in d} for d in run["runs_detail"]]
    return out


def describe(run):
    """One line per check, from fixed templates."""
    lib = run.get("target_name", "PyYAML")
    text = "%s on %s %s via %s: %s" % (run.get("build"), lib, run.get("target_version"), run.get("entry_point"),
                                      run.get("outcome"))
    if "runs_detail" in run and run.get("runs"):
        text += ", %s (image %s)" % (repeats(run), short_image(run.get("image_id")))
    elif "runs_detail" not in run:
        text += ", " + repeats(run)
    details = []
    if run.get("why"):
        details.append(run["why"])
    if run.get("exception_type"):
        details.append("raised %s (message sha256 %s...)" % (run["exception_type"], (run.get("exception_sha256") or "?")[:12]))
    frames = library_frames(run)
    if frames:
        details.append("library frames: " + " < ".join(frames[:3]))
    if run.get("seconds") is not None and not disagreed(run):
        details.append("%.3f s, %.1f MB peak" % (run.get("seconds") or 0, run.get("peak_rss_mb") or 0))
    return text + ("; " + "; ".join(details) if details else "")


def headline(ticket_id, run):
    """The Reproducer's first line after a check: outcome, n/N clean runs and the image."""
    build = run.get("build")
    lib = run.get("target_name", "PyYAML")
    if disagreed(run):
        return "%s %s build: %s on %s %s: %s (image %s)" % (
            ticket_id, build, run.get("outcome"), lib, run.get("target_version"), repeats(run), short_image(run.get("image_id")))
    if not run.get("ran"):
        return "%s %s build: %s on %s %s, not run (%s)" % (
            ticket_id, build, run.get("outcome"), lib, run.get("target_version"), run.get("why") or "no reason")
    return "%s %s build: %s on %s %s, %s (image %s)" % (
        ticket_id, build, run.get("outcome"), lib, run.get("target_version"), repeats(run), short_image(run.get("image_id")))


def facts(record, vulnerable, patched):
    """The Skeptic's checklist, answered from the evidence. None means "not known yet"."""
    outcome = (vulnerable or {}).get("outcome")
    claimed = record.get("claim")
    severity = record.get("severity")
    ceiling = SEVERITY_CEILING.get(outcome)
    split_vulnerable = disagreed(vulnerable)
    in_library = None
    if vulnerable and vulnerable.get("ran") and not split_vulnerable:
        in_library = bool(library_frames(vulnerable) or vulnerable.get("exception_frames"))
    patched_outcome = (patched or {}).get("outcome")
    same_input = None if patched is None or vulnerable is None else (
        vulnerable.get("entry_point") == patched.get("entry_point")
        and vulnerable.get("payload_sha256") == patched.get("payload_sha256"))
    # The patched build counts as checked only through the same entry point, on the same payload, with a result.
    # Runs that disagreed on the patched build are a result too: it did not stop the issue every time.
    checked = bool(same_input) and (patched_outcome in CONCLUSIVE or disagreed(patched))
    patched_reproduces = patched_outcome in REPRODUCING or (disagreed(patched) and (patched or {}).get("reproducing", 0) > 0)
    return {
        "entry_point_allowlisted": bool(record.get("entry_point")) and not record.get("poc_problem"),
        "vulnerable_entry_point": (vulnerable or {}).get("entry_point"),
        "vulnerable_outcome": outcome,
        "vulnerable_clean_runs": None if vulnerable is None else repeats(vulnerable),
        "vulnerable_runs_agree": None if vulnerable is None or not vulnerable.get("ran") else not split_vulnerable,
        "outcome_matches_claim": None if outcome is None or split_vulnerable else CLAIM_FOR_OUTCOME.get(outcome) == claimed,
        "library_frames_recorded": in_library,
        "code_execution_proven_by_marker": None if vulnerable is None or split_vulnerable else bool(vulnerable.get("marker_created")),
        "patched_run_present": patched is not None,
        "patched_comparable": same_input,
        "patched_entry_point": (patched or {}).get("entry_point"),
        "patched_build_checked": checked,
        "patched_outcome": patched_outcome,
        "patched_clean_runs": None if patched is None else repeats(patched),
        "reproduces_on_patched_too": None if not checked or outcome is None else (
            outcome in REPRODUCING and patched_reproduces),
        "claim_decidable_by_sandbox": claimed != "info_leak",
        "claimed_severity": severity,
        "severity_supported_by_outcome": None if outcome not in REPRODUCING or severity in (None, "unrated") else (
            SEVERITY_RANK.get(severity, 0) <= SEVERITY_RANK[ceiling]),
    }


def notes(facts_, vulnerable=None, patched=None):
    """Fixed sentences a human should read before deciding."""
    out = []
    if not facts_.get("claim_decidable_by_sandbox", True):
        out.append("information-leak claims are not decided by the sandbox: a maintainer reads the evidence")
    if facts_["vulnerable_outcome"] == INVALID_PROOF:
        out.append("the sandbox refused the proof as invalid; that is not evidence either way")
    elif facts_["vulnerable_outcome"] == INCONCLUSIVE:
        out.append("the vulnerable-build run was inconclusive (%s); run check again" % ((vulnerable or {}).get("why") or "no reason"))
    elif facts_["vulnerable_outcome"] == NOT_RELIABLY_REPRODUCED:
        out.append("the vulnerable-build runs disagreed (%s), so it did not reproduce reliably; escalation needs "
                   "a maintainer's override" % repeats(vulnerable))
    if facts_["reproduces_on_patched_too"]:
        out.append("reproduces on the patched build too: possible new issue, human review required")
    if facts_.get("patched_comparable") is False:
        out.append("the patched run used %s while the vulnerable run used %s%s, so it is not a comparison: "
                   "run check --build patched with the same loader" % (
                       facts_.get("patched_entry_point"), facts_.get("vulnerable_entry_point"),
                       "" if (vulnerable or {}).get("payload_sha256") == (patched or {}).get("payload_sha256")
                       else " on a different payload"))
    elif facts_.get("patched_comparable") and not facts_["patched_build_checked"]:
        out.append("the patched run was %s (%s), so it does not show whether %s fixed it" % (
            facts_["patched_outcome"], (patched or {}).get("why") or "no reason", (patched or {}).get("target_version") or "the patch"))
    if facts_["vulnerable_outcome"] in REPRODUCING and not facts_["patched_build_checked"] and facts_.get("patched_comparable") is None:
        out.append("the patched build has not been checked yet")
    if facts_["outcome_matches_claim"] is False and facts_["vulnerable_outcome"] in REPRODUCING:
        out.append("the outcome class does not match the claimed impact")
    if facts_["severity_supported_by_outcome"] is False:
        out.append("the claimed severity is higher than this outcome supports")
    return out
