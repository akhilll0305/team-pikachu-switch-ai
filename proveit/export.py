"""`python -m proveit export R-001`: the ticket's evidence as a folder anyone can check.

The folder holds only what agents may already read, never reporter text:

  ticket.json     the ticket record (fixed fields, status, timeline)
  runs/*.json     every sandbox run record
  evidence.json   the evidence pack (checklist, notes, verdict, override)
  evidence.txt    the same, as the Skeptic reads it
  advisory/*      the advisory pack, when the ticket was escalated (DRAFT; no payload)
  manifest.json   SHA-256 of every file above, the payload's SHA-256, the
                  pinned PyYAML builds, and when it was made

`python -m proveit export --verify <folder>` recomputes the hashes, so a
maintainer or a third party can tell whether anything was changed.
"""

import hashlib
import json
import time
from pathlib import Path

from . import config, evidence, store, targets

MANIFEST = "manifest.json"


def _sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def export(ticket_id, out=None):
    record = store.load(ticket_id)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    folder = Path(out) if out else store.work_dir() / "exports" / ("%s-%s" % (ticket_id, stamp))
    (folder / "runs").mkdir(parents=True, exist_ok=False)
    pack = evidence.pack(record)

    def write(name, text):
        # Always LF, so the hashes in the manifest hold on every OS and after Git normalizes line endings.
        with open(str(folder / name), "w", encoding="utf-8", newline="\n") as f:
            f.write(text)

    write("ticket.json", json.dumps(record, indent=2, sort_keys=True))
    for entry in record.get("runs", []):
        name = Path(entry["file"]).name
        write("runs/" + name, json.dumps(store.load_run(entry["file"]), indent=2, sort_keys=True))
    from . import advisory
    pack_dir = advisory.folder(ticket_id)
    if pack_dir.is_dir():
        (folder / advisory.FOLDER).mkdir()
        for name in advisory.FILES:
            if (pack_dir / name).exists():
                write("%s/%s" % (advisory.FOLDER, name), (pack_dir / name).read_text(encoding="utf-8"))
    write("evidence.json", json.dumps(pack, indent=2, sort_keys=True))
    write("evidence.txt", evidence.text(pack) + "\n")
    files = sorted(str(p.relative_to(folder)).replace("\\", "/") for p in folder.rglob("*") if p.is_file())
    manifest = {
        "ticket": ticket_id, "generated_at": stamp, "status": record["status"],
        "payload_sha256": record.get("payload_sha256"), "entry_point": record.get("entry_point"),
        "target": {name: spec["version"] for name, spec in targets.for_record(record).builds.items()},
        "files": {name: _sha256(folder / name) for name in files},
        "note": "Fixed fields only: no reporter text and no payload. Check with: python -m proveit export --verify <folder>",
    }
    write(MANIFEST, json.dumps(manifest, indent=2, sort_keys=True))
    return folder


def verify(folder):
    """A list of problems; empty when every file matches the manifest and nothing was added."""
    folder = Path(folder)
    manifest = json.loads((folder / MANIFEST).read_text(encoding="utf-8"))
    problems = []
    for name, digest in manifest["files"].items():
        path = folder / name
        if not path.exists():
            problems.append("missing: " + name)
        elif _sha256(path) != digest:
            problems.append("changed: " + name)
    present = {str(p.relative_to(folder)).replace("\\", "/") for p in folder.rglob("*") if p.is_file()} - {MANIFEST}
    problems += ["not in the manifest: " + name for name in sorted(present - set(manifest["files"]))]
    return problems
