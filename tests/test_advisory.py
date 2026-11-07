"""The advisory pack written on escalate (U2, decision D-017). No Docker."""

import json
import re
import unittest
from pathlib import Path

from proveit import actions, advisory, export, states, store
from tests.helpers import WorkDirTest, replay, stub_runs

SCHEMA = Path(__file__).resolve().parent / "data" / "osv-schema.json"
CANARY = "Hy5CANARYm"
try:
    import jsonschema  # optional, test-only
except ImportError:  # pragma: no cover - depends on the environment
    jsonschema = None


class Base(WorkDirTest):
    def escalated(self, text=None, patched="NOT_REPRODUCED", note="confirmed, CVE-2020-14343", sender="reporter"):
        self.agent = self.make_intake()
        self.report(self.agent, text or replay("01-real-cve-2020-14343.md"), sender=sender)
        tid = store.all_tickets()[-1]["id"]
        with stub_runs("CODE_EXECUTION", *( [patched] if patched else [])):
            actions.check(tid, actor="agent", by="reproducer")
            if patched:
                actions.check(tid, "patched", actor="agent", by="reproducer")
        self.say(self.agent, "@prove-it-intake dispute %s %s" % (tid, "outcome_mismatch" if patched else "patched_not_checked"),
                 sender="prove-it-skeptic", kind="agent")
        self.say(self.agent, "@prove-it-intake override %s checked" % tid)
        self.say(self.agent, ("@prove-it-intake escalate %s %s" % (tid, note)).strip())
        self.assertEqual(store.load(tid)["status"], "escalated")
        return tid

    def pack(self, tid):
        out = advisory.folder(tid)
        return {name: (out / name).read_text(encoding="utf-8") for name in advisory.FILES}


class Writing(Base):
    def test_escalate_writes_pack(self):
        tid = self.escalated()
        self.assertEqual(sorted(p.name for p in advisory.folder(tid).iterdir()), sorted(advisory.FILES))
        self.assertIn("Advisory pack for %s (DRAFT, needs maintainer review): work/%s/advisory/ osv-draft.json, "
                      "ghsa-draft.md, timeline.md" % (tid, tid), self.agent.triage.text())
        self.assertEqual(list(advisory.folder(tid).glob("*.tmp")), [])

    def test_close_and_refused_escalate_write_nothing(self):
        self.agent = self.make_intake()
        self.report(self.agent, replay("01-real-cve-2020-14343.md"))
        tid = store.all_tickets()[-1]["id"]
        with stub_runs("CODE_EXECUTION"):
            actions.check(tid, actor="agent", by="reproducer")
        self.say(self.agent, "@prove-it-intake escalate %s" % tid)  # refused: no review
        self.assertEqual(store.load(tid)["status"], "reproduced")
        self.assertFalse(advisory.folder(tid).exists())
        self.say(self.agent, "@prove-it-intake close %s duplicate" % tid)
        self.assertEqual(store.load(tid)["status"], "closed")
        self.assertFalse(advisory.folder(tid).exists())
        self.assertNotIn("Advisory pack", self.agent.triage.text())
        with self.assertRaises(ValueError):
            advisory.write(store.load(tid))

    def test_same_data_same_bytes(self):
        tid = self.escalated()
        first = self.pack(tid)
        advisory.write(store.load(tid))
        self.assertEqual(self.pack(tid), first, "rewriting the same data gives the same bytes")
        self.assertEqual(sorted(p.name for p in advisory.folder(tid).iterdir()), sorted(advisory.FILES), "no duplicates")
        with self.assertRaises(states.IllegalTransition):
            actions.decide(tid, "escalate", "human", "maintainer")  # escalated is terminal: no second pack

    def test_files_use_lf(self):
        tid = self.escalated()
        for name in advisory.FILES:
            self.assertNotIn(b"\r\n", (advisory.folder(tid) / name).read_bytes(), name)


class Content(Base):
    def test_every_file_marked_draft_and_placeholder_id(self):
        tid = self.escalated()
        pack = self.pack(tid)
        self.assertTrue(pack["ghsa-draft.md"].startswith("DRAFT, needs maintainer review\n"))
        self.assertTrue(pack["timeline.md"].startswith("DRAFT, needs maintainer review\n"))
        osv = json.loads(pack["osv-draft.json"])
        self.assertEqual(osv["id"], "x_DRAFT-PROVEIT-%s" % tid)
        self.assertTrue(osv["summary"].startswith("DRAFT:"))
        self.assertEqual(osv["database_specific"]["status"], "DRAFT, needs maintainer review")
        self.assertEqual(osv["database_specific"]["generated_by"], "Prove It")
        self.assertEqual(json.loads(pack["timeline.json"])["status"], "DRAFT, needs maintainer review")
        self.assertNotRegex(osv["id"], r"^(CVE|GHSA|OSV|PYSEC)-")

    def test_osv_structure_strict(self):
        osv = json.loads(self.pack(self.escalated())["osv-draft.json"])
        self.assertEqual(set(osv) - {"schema_version", "id", "modified", "summary", "details", "affected",
                                     "database_specific", "aliases"}, set())
        for key, kind in (("schema_version", str), ("id", str), ("modified", str), ("summary", str), ("details", str),
                          ("affected", list), ("database_specific", dict), ("aliases", list)):
            self.assertIsInstance(osv[key], kind, key)
        self.assertRegex(osv["modified"], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
        self.assertRegex(osv["id"], r"^[A-Za-z0-9_.:-]+$")
        self.assertEqual(osv["affected"][0]["package"], {"ecosystem": "PyPI", "name": "PyYAML"})
        self.assertTrue(all(isinstance(v, str) for v in osv["affected"][0]["versions"]))

    @unittest.skipIf(jsonschema is None, "jsonschema is not installed (optional, test-only); the strict structure test still runs")
    def test_osv_schema_validates(self):
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        osv = json.loads(self.pack(self.escalated())["osv-draft.json"])
        jsonschema.validate(osv, schema)
        self.assertEqual(osv["schema_version"], advisory.OSV_SCHEMA_VERSION)

    def test_no_fixed_version(self):
        osv = json.loads(self.pack(self.escalated())["osv-draft.json"])
        text = json.dumps(osv)
        self.assertNotIn('"fixed"', text)
        self.assertNotIn("ranges", osv["affected"][0])
        self.assertIn("No fixed version is claimed", self.pack(store.all_tickets()[-1]["id"])["ghsa-draft.md"])

    def test_not_reproduced_on_only_when_patched_says_so(self):
        fixed = json.loads(self.pack(self.escalated(patched="NOT_REPRODUCED"))["osv-draft.json"])
        self.assertEqual(fixed["database_specific"]["not_reproduced_on"], ["5.4"])
        unchecked = json.loads(self.pack(self.escalated(patched=None))["osv-draft.json"])
        self.assertNotIn("not_reproduced_on", unchecked["database_specific"])
        both = json.loads(self.pack(self.escalated(patched="CODE_EXECUTION"))["osv-draft.json"])
        self.assertNotIn("not_reproduced_on", both["database_specific"])

    def test_alias_only_from_maintainer_note(self):
        with_cve = json.loads(self.pack(self.escalated(note="confirmed, CVE-2020-14343"))["osv-draft.json"])
        self.assertEqual(with_cve["aliases"], ["CVE-2020-14343"])
        self.assertEqual(with_cve["database_specific"]["aliases_source"], "maintainer-supplied (from the escalate note)")
        # The report itself names CVE-2020-14343 (fixture 01), but only the maintainer's note counts.
        without = json.loads(self.pack(self.escalated(note="confirmed"))["osv-draft.json"])
        self.assertNotIn("aliases", without)
        self.assertNotIn("aliases_source", without["database_specific"])

    def test_osv_versions_never_contain_a_range(self):
        tid = self.escalated()  # fixture 01 reports "before 5.4"
        osv = json.loads(self.pack(tid)["osv-draft.json"])
        self.assertEqual(osv["affected"][0]["versions"], ["5.3.1"])
        self.assertEqual(osv["database_specific"]["reported_affected_version"], "before 5.4")
        for version in osv["affected"][0]["versions"]:
            self.assertRegex(version, r"^\d+(\.\d+)*$")

    def test_timeline_ordered_timestamped_complete_and_marks_missing(self):
        tid = self.escalated(patched=None)
        t = json.loads(self.pack(tid)["timeline.json"])
        steps = [e["event"] for e in t["events"]]
        self.assertEqual(steps, ["received", "proof accepted", "check (vulnerable build)", "Skeptic verdict",
                                 "maintainer override", "maintainer decision"])
        stamps = [e["at"] for e in t["events"]]
        self.assertTrue(all(re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", s) for s in stamps), stamps)
        self.assertEqual(stamps, sorted(stamps), "in recorded order")
        self.assertIn("payload sha256 %s" % store.load(tid)["payload_sha256"], t["events"][1]["detail"])
        self.assertIn("3/3 clean runs, image sha256:", t["events"][2]["detail"])
        self.assertEqual(t["events"][3]["detail"], "dispute (patched_not_checked)")
        self.assertIn("patched build: not checked", t["missing"])
        self.assertIn("- patched build: not checked", self.pack(tid)["timeline.md"])
        self.assertIn("Patched build, PyYAML 5.4: not checked", self.pack(tid)["ghsa-draft.md"])
        full = json.loads(self.pack(self.escalated(patched="NOT_REPRODUCED"))["timeline.json"])
        self.assertIn("check (patched build)", [e["event"] for e in full["events"]])
        self.assertNotIn("patched build: not checked", full["missing"])


class NoReporterMaterial(Base):
    def test_no_payload_and_no_canary_in_pack(self):
        text = ("Title: {c} title\nSeverity: critical {c}\nAffected version: 5.3.1\nEntry point: yaml.full_load\n"
                "Claimed impact: arbitrary code execution {c}\nexpected: {c}\nactual: {c}\n\n"
                "```yaml\n{c}key: \"{c}value\"\n```\n").format(c=CANARY)
        tid = self.escalated(text=text, sender=CANARY + "-reporter")
        payload = store.payload(tid)
        self.assertIn(CANARY, payload)
        for name, body in self.pack(tid).items():
            self.assertNotIn(CANARY, body, name)
            self.assertNotIn(CANARY.lower(), body.lower(), name)
            self.assertNotIn(payload.strip(), body, "%s must not contain the payload" % name)
        self.assertIn(store.load(tid)["payload_sha256"], self.pack(tid)["ghsa-draft.md"])
        self.assertIn("private/%s/payload.yaml" % tid, self.pack(tid)["ghsa-draft.md"])

    def test_pack_has_no_absolute_path_or_home_name(self):
        tid = self.escalated()
        home = Path.home()
        for name, body in self.pack(tid).items():
            self.assertIsNone(re.search(r"\b[A-Za-z]:[\\/]", body), "%s has a drive letter" % name)
            self.assertNotIn(str(home), body, name)
            self.assertNotIn(home.as_posix(), body, name)
            self.assertIsNone(re.search(r"(?<![\w.])/(home|Users|root)/", body), "%s has a home-folder path" % name)
            self.assertNotIn(home.name, body, "%s names the home folder" % name)
            self.assertNotIn(".proveit", body, name)


class Export(Base):
    def test_export_manifest_covers_pack_and_verifies(self):
        tid = self.escalated()
        folder = export.export(tid, self.tmp / "out")
        manifest = json.loads((folder / "manifest.json").read_text(encoding="utf-8"))
        for name in advisory.FILES:
            self.assertIn("advisory/" + name, manifest["files"])
        self.assertEqual(export.verify(folder), [])
        (folder / "advisory" / "osv-draft.json").write_text("{}", encoding="utf-8")
        self.assertIn("changed: advisory/osv-draft.json", export.verify(folder))
