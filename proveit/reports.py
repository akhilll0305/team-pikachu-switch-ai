"""Turning a reporter's free text into a ticket of fixed fields.

Only the Intake agent ever reads a reporter's prose. Everything downstream
(the Reproducer, the Skeptic, the triage room) gets the ticket: a claim and
a severity chosen from closed lists, an entry point from an allowlist, and
the payload's hash, size and known tags. The payload itself is stored where
only the sandbox reads it. No title, no reporter name, no excerpt.
"""

import re
import textwrap
from dataclasses import asdict, dataclass, field

from . import poc
from .config import PAYLOAD_MAX_BYTES

CLAIM_KEYWORDS = [
    ("code_execution", r"\b(rce|remote code execution|code execution|arbitrary code|execute arbitrary|command execution|executes code|execute code)\b"),
    ("denial_of_service", r"\b(dos|denial of service|memory exhaustion|billion laughs|resource exhaustion|out of memory|cpu exhaustion|hang)\b"),
    ("crash", r"\b(segfault|segmentation fault|crash|buffer overflow|heap overflow|use[- ]after[- ]free|memory corruption)\b"),
    ("info_leak", r"\b(information disclosure|info leak|leaks?|exfiltrat\w*|disclos\w*)\b"),
]
CLAIMS = [c for c, _ in CLAIM_KEYWORDS]
SEVERITIES = ["critical", "high", "medium", "low"]
FENCE = re.compile(r"```[ \t]*([\w+-]*)[ \t]*\r?\n(.*?)```", re.S)
FIELD = re.compile(r"^\s*(?:\*\*)?(severity|entry[ _]point|claimed impact|impact|affected[ _]version)(?:\*\*)?\s*:\s*(.+)$",
                   re.I | re.M)
# `payload: |` followed by an indented block, as in the proof request's example (decision D-016).
PAYLOAD_BLOCK = re.compile(r"^[ \t]*(?:\*\*)?payload(?:\*\*)?[ \t]*:[ \t]*\|[-+]?[ \t]*\r?\n((?:(?:[ \t]+[^\n]*|[ \t]*)(?:\r?\n|$))+)",
                           re.I | re.M)
# An affected version: 5.3.1, <5.4, <=5.3.1 or "before 5.4" (optionally "PyYAML 5.3.1" or "v5.3.1").
VERSION = re.compile(r"(?:pyyaml\s*)?(?:v(?:ersion)?\s*)?(<=|<|before\s+)?\s*(\d+(?:\.\d+){0,3})", re.I)


def parse_version(text):
    """A normalized affected version ("5.3.1", "<5.4", "<=5.3.1", "before 5.4"), or "" if `text` is not one."""
    s = (text or "").strip().strip("`*").strip()
    match = VERSION.fullmatch(s)
    if not match:
        return ""
    op = (match.group(1) or "").strip().lower()
    return ("before %s" % match.group(2)) if op == "before" else "%s%s" % (op, match.group(2))


@dataclass
class Ticket:
    claim: str = ""
    severity: str = "unrated"
    entry_point: str = ""
    payload: str = ""
    poc_problem: str = ""
    missing: list = field(default_factory=list)
    # A normalized version string from parse_version, never the reporter's own words.
    affected_version: str = ""
    # The canonical name (target.out_of_scope_names) of an out-of-scope entry point, never the reporter's words.
    out_of_scope_entry: str = ""
    # Which library this proof is for (targets registry key). "" means PyYAML, the default.
    target: str = ""

    def complete(self):
        return not self.missing and not self.poc_problem

    def to_dict(self):
        return asdict(self)


def classify_claim(text):
    """The claimed impact, picked from a closed list by keyword."""
    lowered = text.lower()
    best, best_pos = "", None
    for claim, pattern in CLAIM_KEYWORDS:
        match = re.search(pattern, lowered)
        if match and (best_pos is None or match.start() < best_pos):
            best, best_pos = claim, match.start()
    return best


def _fields(text):
    return {k.lower().replace("_", " "): v.strip() for k, v in FIELD.findall(text)}


def _payload_block(text):
    match = PAYLOAD_BLOCK.search(text or "")
    if not match:
        return ""
    body = textwrap.dedent(match.group(1).replace("\r\n", "\n")).strip("\n")
    return body + "\n" if body.strip() else ""


def parse(text, target=None):
    """Build a ticket from a report. Never copies prose into the ticket.

    `target` picks the entry-point parser, payload fences and size limit; the
    default is PyYAML, so existing callers and tests are unchanged.
    """
    from . import targets
    target = target or targets.PYYAML
    fields = _fields(text)
    impact_text = fields.get("claimed impact") or fields.get("impact") or text
    claim = classify_claim(impact_text) or classify_claim(text)
    severity = fields.get("severity", "").lower()
    severity = next((s for s in SEVERITIES if s in severity), "") or next(
        (s for s in SEVERITIES if re.search(r"\b%s\b" % s, text.lower())), "unrated")

    python_blocks, payload_blocks = [], []
    for lang, body in FENCE.findall(text):
        lang = lang.lower()
        if lang in ("python", "py", "python3"):
            python_blocks.append(body)
        elif lang in target.fence_langs:
            payload_blocks.append(body)
    block = _payload_block(text)
    if block:
        payload_blocks.append(block)
    payload = max(payload_blocks, key=len) if payload_blocks else ""
    version = parse_version(fields.get("affected version"))

    problem = ""
    entry_point = ""
    missing = []
    if python_blocks or (payload and poc.looks_like_python(payload)):
        problem = "python_code"
    elif payload:
        if len(payload.encode("utf-8", "surrogatepass")) > target.payload_max_bytes:
            problem = "too_large"
        if "entry point" in fields:
            entry_point, entry_problem = target.parse_entry_point(fields["entry point"])
            problem = problem or entry_problem or ""
            entry_point = entry_point or ""
        else:
            missing.append("entry_point")
    elif "entry point" in fields:
        entry_point, entry_problem = target.parse_entry_point(fields["entry point"])
        entry_point = entry_point or ""
        problem = entry_problem if entry_problem in ("unsafe_loader", "c_loader") else ""
        if not problem:
            missing.append("poc")
    else:
        missing.append("poc")
    if not claim:
        missing.append("claim")
    if not version:
        missing.append("affected_version")
    out_of_scope = (target.out_of_scope_name(fields.get("entry point")) or "an unsafe loader") if problem == "unsafe_loader" else ""
    return Ticket(claim=claim, severity=severity, entry_point=entry_point, payload=payload,
                  poc_problem=problem, missing=missing, out_of_scope_entry=out_of_scope, affected_version=version,
                  target=target.key)


def merge(previous, followup_text, target=None):
    """A reporter's follow-up in the same thread replaces the proof and fills gaps."""
    from . import targets
    if target is None:
        target = targets.get(getattr(previous, "target", "") or targets.DEFAULT_KEY)
    update = parse(followup_text, target)
    merged = Ticket(**previous.to_dict())
    if update.payload or update.poc_problem:
        # A new proof (or a rejected one) replaces the old proof.
        merged.payload = update.payload
        merged.entry_point = update.entry_point or (previous.entry_point if update.payload else "")
        merged.poc_problem = update.poc_problem
        merged.out_of_scope_entry = update.out_of_scope_entry
    elif update.entry_point:
        # Only an entry point: it completes the payload already on file.
        merged.entry_point = update.entry_point
        if merged.poc_problem in ("unknown_entry_point", "no_entry_point"):
            merged.poc_problem = ""
            merged.out_of_scope_entry = ""
    if not merged.claim and update.claim:
        merged.claim = update.claim
    if merged.severity == "unrated" and update.severity != "unrated":
        merged.severity = update.severity
    if update.affected_version:
        merged.affected_version = update.affected_version  # a version-only reply completes the proof on file
    missing = []
    if not merged.payload and not merged.poc_problem:
        missing.append("poc")
    elif merged.payload and not merged.entry_point and not merged.poc_problem:
        missing.append("entry_point")
    if not merged.claim:
        missing.append("claim")
    if not merged.affected_version:
        missing.append("affected_version")
    merged.missing = missing
    return merged
