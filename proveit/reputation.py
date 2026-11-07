"""A proof record per reporter (U3, decision D-018): outcomes only, keyed by an HMAC.

  <private folder>/reporters.json   {"<hmac>": {"good": 1, "invalid": 2, "updated": "...Z",
                                                "cleared": "...Z" or null, "id_source": "sender"}}
  <private folder>/reporter-secret  the HMAC key: random, made on first use, never printed

The key is HMAC-SHA256(secret, the reporter's Switch participant ID), or of
their Switch display name when a message carries no ID (`id_source` records
which field was used, never its value). Nothing else is stored: no names,
report text, payloads or titles. The record belongs to Intake, so every room
pair Intake serves shares it.

What counts, at most once per ticket:
  invalid  a ticket closed while its vulnerable-build check recorded
           NOT_REPRODUCED or NOT_RELIABLY_REPRODUCED (not information-leak
           claims, which the sandbox does not decide); a proof Intake rejected
  good     an escalated ticket
Nothing else counts: open tickets, tickets waiting for a proof, quarantined
reports, or closes for any other reason.

The only consequence: a reporter with invalid >= config.INVALID_THRESHOLD
who already has an open report may not open a second one. Nobody is ever
blocked outright, and a maintainer can lift the limit (clear-reporter). No
text analysis or AI detection of any kind is involved.
"""

import contextlib
import hashlib
import hmac
import json
import logging
import os
import secrets

from . import config, store

log = logging.getLogger("proveit.reputation")
RECORD = "reporters.json"
SECRET = "reporter-secret"
LOCK = ".reporters.lock"
SHORT = 12
# A reporter's ticket in one of these states is "open" for the limit. Quarantined reports are not
# counted here: the screen handles them.
OPEN_FOR_LIMIT = ("awaiting_poc", "invalid_proof", "in_triage", "reproduced", "not_reproduced",
                  "not_reliably_reproduced", "disputed")
FIXABLE = ("awaiting_poc", "invalid_proof")


def _root():
    root = store.private_root()
    root.mkdir(parents=True, exist_ok=True)
    return root


def _secret():
    path = _root() / SECRET
    if not path.exists():
        try:
            fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(secrets.token_bytes(32))
        except FileExistsError:
            pass  # another process made it first; use theirs
    return path.read_bytes()


def identity(payload):
    """(value, field name) for a message's sender, or (None, None) when it names nobody."""
    for name in ("sender", "sender_name"):
        value = payload.get(name)
        if isinstance(value, str) and value.strip():
            return value.strip(), name
    return None, None


def key_for(value):
    return hmac.new(_secret(), value.encode("utf-8"), hashlib.sha256).hexdigest()


def short(key):
    return key[:SHORT]


@contextlib.contextmanager
def _locked():
    with open(_root() / LOCK, "a+") as handle:
        store._lock_file(handle)
        try:
            yield
        finally:
            store._unlock_file(handle)


def load():
    path = _root() / RECORD
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}


def _save(data):
    store._write(_root() / RECORD, json.dumps(data, indent=2, sort_keys=True))


def _entry(data, key, source):
    entry = data.setdefault(key, {"good": 0, "invalid": 0, "updated": None, "cleared": None, "id_source": source})
    entry["updated"] = store.now()
    if source:
        entry["id_source"] = source
    return entry


def add(key, source, what):
    """Count one outcome ("good" or "invalid") for a reporter. Callers count each ticket at most once."""
    if not key:
        return None
    with _locked():
        data = load()
        entry = _entry(data, key, source)
        entry[what] += 1
        _save(data)
        return dict(entry)


def get(key):
    return load().get(key) if key else None


def is_limited(key):
    entry = get(key)
    return bool(entry) and entry.get("invalid", 0) >= config.INVALID_THRESHOLD


def resolve(prefix):
    """The full key for a full key or its first characters. Raises ValueError if none or several match."""
    prefix = (prefix or "").strip().lower()
    if len(prefix) < SHORT or any(c not in "0123456789abcdef" for c in prefix):
        raise ValueError("give a reporter key of at least %d hex characters, as Intake printed it" % SHORT)
    matches = [k for k in load() if k.startswith(prefix)]
    if not matches:
        raise ValueError("no reporter %s in the proof record" % prefix[:SHORT])
    if len(matches) > 1:
        raise ValueError("%s matches more than one reporter; give more characters" % prefix[:SHORT])
    return matches[0]


def clear(prefix):
    """A maintainer lifts the limit: invalid back to 0, and when that happened."""
    with _locked():
        key = resolve(prefix)
        data = load()
        entry = data[key]
        entry["invalid"] = 0
        entry["cleared"] = entry["updated"] = store.now()
        _save(data)
        return key, dict(entry)


def open_tickets(key):
    """The reporter's tickets that count as open for the limit, oldest first."""
    found = []
    for record in store.all_tickets():
        if record["status"] in OPEN_FOR_LIMIT and \
                store.load_private_json(record["id"], "contact.json").get("reporter_key") == key:
            found.append(record)
    return found
