"""Proofs of concept are data: one allowlisted entry point plus a YAML payload.

Everything here runs on the host, before the sandbox, and decides only
whether a submission is a well-formed proof. It never runs or parses the
payload as YAML.
"""

import hashlib
import re

from .config import ENTRY_POINTS, PAYLOAD_MAX_BYTES

PROBLEMS = {
    "python_code": "the proof is Python code; proofs must be a YAML payload plus an entry point",
    "unsafe_loader": "the entry point is a loader PyYAML documents as unsafe by design, so using it is not a vulnerability",
    "c_loader": "C loaders are not available in both pinned builds (PyYAML 5.3.1 has no libyaml here)",
    "unknown_entry_point": "the entry point is not on the allowlist",
    "no_entry_point": "no entry point was given",
    "too_large": "the payload is larger than %d KB" % (PAYLOAD_MAX_BYTES // 1024),
    "not_utf8": "the payload is not UTF-8 text",
    "empty_payload": "the payload is empty",
}

_PY_LINE = re.compile(r"^\s*(import\s+\w|from\s+[\w.]+\s+import\s|def\s+\w+\s*\(|class\s+\w+[\s(:]|print\s*\(|"
                      r"if\s+__name__\s*==|with\s+open\s*\(|exec\s*\(|eval\s*\()", re.M)


# The out-of-scope entry points by their canonical names (docs/policy/pyyaml-scope.md). A message
# names one of these, never what the reporter wrote.
OUT_OF_SCOPE_NAMES = ("yaml.unsafe_load_all", "yaml.unsafe_load", "yaml.load with Loader=yaml.UnsafeLoader",
                      "yaml.load with Loader=yaml.Loader")


def out_of_scope_name(text):
    """The canonical name of the out-of-scope entry point in `text`, or None if it names none."""
    s = (text or "").strip().strip("`").strip()
    if re.search(r"unsafe_load_all", s, re.I):
        return "yaml.unsafe_load_all"
    if re.search(r"unsafe_load", s, re.I):
        return "yaml.unsafe_load"
    if re.search(r"UnsafeLoader", s, re.I):
        return "yaml.load with Loader=yaml.UnsafeLoader"
    if re.search(r"Loader\s*=\s*(yaml\.)?Loader\b", s) or re.search(r"\bwith\s+(yaml\.)?Loader\b(?!\s*=)", s):
        return "yaml.load with Loader=yaml.Loader"
    return None


def parse_entry_point(text):
    """Map what a reporter wrote ("yaml.full_load", "yaml.load(..., Loader=yaml.FullLoader)")
    to an allowlisted key, or return (None, problem)."""
    if not text or not text.strip():
        return None, "no_entry_point"
    s = text.strip().strip("`").strip()
    if re.search(r"unsafe_load|UnsafeLoader", s, re.I):
        return None, "unsafe_loader"
    if re.search(r"\bC(Safe|Full|Unsafe|Base)?Loader\b", s):
        return None, "c_loader"
    if re.search(r"Loader\s*=\s*(yaml\.)?Loader\b", s) or re.search(r"\bwith\s+(yaml\.)?Loader\b(?!\s*=)", s):
        return None, "unsafe_loader"
    if re.fullmatch(r"(yaml\.)?safe_load(\(.*\))?", s):
        return "safe_load", None
    if re.fullmatch(r"(yaml\.)?full_load(\(.*\))?", s):
        return "full_load", None
    if re.match(r"(yaml\.)?load\b", s):
        if re.search(r"\bSafeLoader\b", s):
            return "load:SafeLoader", None
        if re.search(r"\bFullLoader\b", s):
            return "load:FullLoader", None
    if s in ENTRY_POINTS:
        return s, None
    return None, "unknown_entry_point"


def looks_like_python(payload):
    return bool(_PY_LINE.search(payload or ""))


def validate(entry_point, payload, entry_points=None, max_bytes=None):
    """Return a problem code from PROBLEMS, or None if the proof may run.

    `entry_points` and `max_bytes` default to PyYAML's; a target passes its own
    (targets.Target.validate), so the same checks serve every library.
    """
    entry_points = ENTRY_POINTS if entry_points is None else entry_points
    max_bytes = PAYLOAD_MAX_BYTES if max_bytes is None else max_bytes
    if entry_point not in entry_points:
        return "unknown_entry_point" if entry_point else "no_entry_point"
    if isinstance(payload, bytes):
        if len(payload) > max_bytes:
            return "too_large"
        try:
            payload = payload.decode("utf-8")
        except UnicodeDecodeError:
            return "not_utf8"
    if not payload or not payload.strip():
        return "empty_payload"
    try:
        size = len(payload.encode("utf-8"))
    except UnicodeEncodeError:
        return "not_utf8"
    if size > max_bytes:
        return "too_large"
    if looks_like_python(payload):
        return "python_code"
    return None


def sha256(payload):
    return hashlib.sha256(payload.encode("utf-8", "surrogatepass")).hexdigest()


# Tags are reporter-controlled text, so only well-known PyYAML tags are shown.
_TAG = re.compile(r"(?<![\w!])(!![\w/.:-]*|!<[^>\s]*>|![\w/.:-]+)")
_KNOWN = re.compile(r"!!(python/(object/apply|object/new|object|name|module|tuple|str|unicode|bytes|bool|int|"
                    r"float|complex|list|dict|none)|str|int|float|bool|null|map|seq|set|omap|pairs|binary|"
                    r"timestamp|merge|value|yaml)")
# Callables a payload might name after a python/* tag; anything else is hashed.
_KNOWN_SUFFIX = {"eval", "exec", "compile", "open", "map", "tuple", "list", "dict", "getattr", "setattr",
                 "__import__", "input", "print", "type", "object", "os.system", "os.popen", "os.getcwd",
                 "os.remove", "subprocess.Popen", "subprocess.call", "subprocess.check_output",
                 "builtins.open", "builtins.eval", "builtins.exec", "time.sleep", "posix.system"}


def _short_hash(text):
    return hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()[:12]


def safe_tag(tag):
    if tag.startswith("!<tag:yaml.org,2002:") and tag.endswith(">"):
        tag = "!!" + tag[len("!<tag:yaml.org,2002:"):-1]
    base, sep, suffix = tag.partition(":") if tag.startswith("!!python/") else (tag, "", "")
    if not re.fullmatch(_KNOWN, base):
        return "unknown-tag:%s" % _short_hash(tag)
    if not sep:
        return base
    return "%s:%s" % (base, suffix if suffix in _KNOWN_SUFFIX else "unknown-name:%s" % _short_hash(suffix))


def tags(payload):
    """The YAML tags a payload uses, each shown only if it is a known PyYAML tag."""
    seen = []
    for match in _TAG.finditer(payload or ""):
        tag = safe_tag(match.group(1))
        if tag not in seen:
            seen.append(tag)
        if len(seen) >= 20:
            break
    return seen
