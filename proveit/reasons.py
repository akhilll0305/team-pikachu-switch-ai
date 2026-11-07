"""Reason codes: why the Skeptic disputes a result, and the one question a reporter may be asked.

Decision D-013. This table is the only list of codes; the Skeptic's
instructions (switch/prove-it.template.yaml) and the README repeat it.

A dispute carries exactly one code. Some codes are checked against the
recorded evidence and refused when the evidence contradicts them ("code
decides"); the others are the Skeptic's judgement and are accepted as given.

A reporter question is sent only when a maintainer closes a ticket
(decision D-014), never at dispute time. Every question is fixed text whose
placeholders are filled only from closed lists and config, never from
anything a reporter or an agent wrote.
"""

from . import config, judge

# The claim words a question may use, from the closed claim list (reports.CLAIMS).
CLAIM_WORDS = {
    "code_execution": "code execution",
    "denial_of_service": "denial of service",
    "crash": "a crash",
    "info_leak": "an information leak",
}
SEVERITIES = ("critical", "high", "medium", "low")
OUTCOMES = (judge.CODE_EXECUTION, judge.CRASH, judge.RESOURCE_EXHAUSTION, judge.NOT_REPRODUCED,
            judge.NOT_RELIABLY_REPRODUCED, judge.INCONCLUSIVE, judge.INVALID_PROOF)

# code -> (meaning, reporter question or None). Order is the order shown to people.
CODES = {
    "not_reproduced": (
        "did not reproduce on the vulnerable build",
        "The sandbox did not reproduce this on {target_name} {vulnerable_version}. Which exact input and entry point "
        "trigger it?"),
    "not_clean_reproducible": (
        "reproduced in fewer than N/N clean runs",
        "It reproduced in only {reproducing} of {runs} clean runs. What else does it need to happen every time?"),
    "also_on_patched": (
        "also reproduces on the patched build (possible new issue)",
        None),
    "out_of_scope_api": (
        "uses an API PyYAML documents as unsafe (docs/policy/pyyaml-scope.md)",
        "This uses an API that {target_name} documents as unsafe. Can you show it with {safe_hint}?"),
    "outcome_mismatch": (
        "the outcome class does not match the claim",
        "You reported {claim_words}; the sandbox recorded {outcome}. Which input produces {claim_words}?"),
    "severity_overclaimed": (
        "the claimed severity is not supported by the outcome",
        "What makes this {severity} rather than lower?"),
    "version_missing": (
        "the affected version is not stated",
        "Which {target_name} version is affected?"),
    "patched_not_checked": (
        "the patched build has not been checked",
        None),
}
ORDER = list(CODES)
# Shown to maintainers only, never to a reporter.
MAINTAINER_FLAGS = {
    "also_on_patched": "possible new issue on the patched build: needs human review",
    "patched_not_checked": "ask the Reproducer to run `check <id> --build patched`",
}


def code_list():
    return ", ".join(ORDER)


def has_question(code):
    return code in CODES and CODES[code][1] is not None


def meaning(code):
    return CODES[code][0]


def vulnerable_version(target=None):
    from . import targets
    return (target or targets.PYYAML).vulnerable_version


def _result(run):
    return "%s, %s" % (run.get("outcome"), judge.repeats(run))


def contradiction(code, vulnerable, patched):
    """Why the recorded evidence contradicts `code`, or None. `patched` is the latest patched check, if any."""
    if code == "not_reproduced":
        if vulnerable is None:
            return "no vulnerable-build check has run"
        if vulnerable.get("outcome") != judge.NOT_REPRODUCED:
            return "the vulnerable build recorded %s" % _result(vulnerable)
    elif code == "not_clean_reproducible":
        if vulnerable is None:
            return "no vulnerable-build check has run"
        if vulnerable.get("outcome") != judge.NOT_RELIABLY_REPRODUCED:
            return "the vulnerable build recorded %s; its runs agreed" % _result(vulnerable)
    elif code == "also_on_patched":
        from .evidence import comparable
        if patched is None:
            return "no patched check has run"
        if not comparable(vulnerable, patched):
            return "no comparable patched check has run"
        if vulnerable.get("outcome") not in judge.REPRODUCING or patched.get("outcome") not in judge.REPRODUCING:
            return "both comparable builds must have a reproducing outcome; the patched build recorded %s" % _result(patched)
    elif code == "patched_not_checked":
        from .evidence import comparable
        if comparable(vulnerable, patched) and patched.get("outcome") in judge.CONCLUSIVE:
            return "a patched check is recorded: %s" % _result(patched)
    return None


def question(code, record, vulnerable):
    """The reporter question for `code` on this ticket, or None.

    Placeholders take only values from closed lists or config. If a value
    is missing or not on its list, there is no question rather than a
    question that echoes something else.
    """
    if not has_question(code):
        return None
    from . import targets
    target = targets.for_record(record)
    values = {"vulnerable_version": vulnerable_version(target),
              "target_name": target.name, "safe_hint": target.safe_hint}
    outcome = (vulnerable or {}).get("outcome")
    if outcome in OUTCOMES:
        values["outcome"] = outcome
    if record.get("claim") in CLAIM_WORDS:
        values["claim_words"] = CLAIM_WORDS[record["claim"]]
    if record.get("severity") in SEVERITIES:
        values["severity"] = record["severity"]
    if vulnerable and judge.disagreed(vulnerable) and isinstance(vulnerable.get("runs"), int):
        values["reproducing"] = int(vulnerable.get("reproducing") or 0)
        values["runs"] = vulnerable["runs"]
    try:
        return CODES[code][1].format(**values)
    except KeyError:
        return None


def derived(vulnerable):
    """Rule 3 of the close order: the code the evidence itself implies, or None."""
    outcome = (vulnerable or {}).get("outcome")
    if outcome == judge.NOT_REPRODUCED:
        return "not_reproduced"
    if outcome == judge.NOT_RELIABLY_REPRODUCED:
        return "not_clean_reproducible"
    return None
