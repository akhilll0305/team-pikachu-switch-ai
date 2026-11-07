"""Safe concurrent writes (checkpoint group F): Intake, the Reproducer's CLI and a maintainer's CLI
are separate processes writing the same tickets."""

import os
import subprocess
import sys
import threading
import time
import unittest
from unittest import mock

from proveit import actions, config, store
from tests.helpers import WorkDirTest, fake_run, replay

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class ConcurrentWrites(WorkDirTest):
    def ticket(self):
        agent = self.make_intake()
        self.report(agent, replay("01-real-cve-2020-14343.md"))
        return store.all_tickets()[-1]["id"]

    def test_two_simultaneous_checks_are_both_recorded(self):
        # The assessment's probe: both threads shared one .tmp file, one crashed and a run was lost.
        tid = self.ticket()

        def slow(entry, payload, build, target=None):
            time.sleep(0.3)
            return fake_run("CODE_EXECUTION", build=build, entry=entry)
        errors = []

        def check(build):
            try:
                actions.check(tid, build, actor="agent", by="reproducer")
            except Exception as exc:  # pragma: no cover - the failure being tested for
                errors.append(exc)
        with mock.patch("proveit.actions.sandbox.run_poc", side_effect=slow):
            actions.check(tid, actor="agent", by="reproducer")  # the patched build needs a vulnerable check first
            threads = [threading.Thread(target=check, args=(b,)) for b in ("vulnerable", "patched", "vulnerable", "patched")]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
        self.assertEqual(errors, [])
        record = store.load(tid)
        files = sorted(r["file"] for r in record["runs"])
        self.assertEqual(len(files), 5)
        self.assertEqual(len(set(files)), 5, files)
        on_disk = sorted(p.name for p in (config.WORK_DIR / tid / "runs").glob("*.json"))
        self.assertEqual(len(on_disk), 5, on_disk)
        self.assertEqual(len({name[:2] for name in on_disk}), 5, "every run has its own number")
        self.assertEqual(list((config.WORK_DIR / tid).rglob("*.tmp")), [])

    def test_simultaneous_reports_get_different_ids(self):
        ids, lock = [], threading.Lock()

        def create(i):
            record = store.create({}, "report %d" % i, source="test")
            with lock:
                ids.append(record["id"])
        threads = [threading.Thread(target=create, args=(i,)) for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(len(ids), 8)
        self.assertEqual(len(set(ids)), 8, ids)

    def test_simultaneous_saves_of_one_ticket_never_fail(self):
        tid = self.ticket()
        errors = []

        def save(n):
            try:
                for _ in range(20):
                    with store.ticket_lock(tid):
                        record = store.load(tid)
                        record.setdefault("counter", 0)
                        record["counter"] += 1
                        store.save(record)
            except Exception as exc:  # pragma: no cover
                errors.append(exc)
        threads = [threading.Thread(target=save, args=(i,)) for i in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        self.assertEqual(store.load(tid)["counter"], 80, "no update may be lost")

    def test_the_lock_holds_across_processes(self):
        tid = self.ticket()
        holder = subprocess.Popen(
            [sys.executable, "-c",
             "import sys, time\n"
             "from proveit import config, store\n"
             "from pathlib import Path\n"
             "config.WORK_DIR = Path(sys.argv[1])\n"
             "with store.ticket_lock(sys.argv[2]):\n"
             "    print('held', flush=True)\n"
             "    time.sleep(1.0)\n",
             str(config.WORK_DIR), tid], cwd=ROOT, stdout=subprocess.PIPE, text=True)
        self.assertEqual(holder.stdout.readline().strip(), "held")
        started = time.monotonic()
        with store.ticket_lock(tid):
            waited = time.monotonic() - started
        holder.wait(10)
        holder.stdout.close()
        self.assertGreater(waited, 0.5, "the second process must wait for the first")

    def test_locking_a_missing_ticket_creates_nothing(self):
        with self.assertRaises(FileNotFoundError):
            with store.ticket_lock("R-999"):
                pass
        self.assertFalse((config.WORK_DIR / "R-999").exists())

    def test_lock_is_reentrant_in_one_thread(self):
        tid = self.ticket()
        with store.ticket_lock(tid):
            # Nested use, as when Intake holds the lock and calls an action that takes it again.
            with store.ticket_lock(tid):
                record = store.load(tid)
                store.save(record)
        done = threading.Event()

        def take():
            with store.ticket_lock(tid):
                done.set()
        worker = threading.Thread(target=take)
        worker.start()
        self.assertTrue(done.wait(5), "the lock must be free again once the outer block ends")
        worker.join(5)


if __name__ == "__main__":
    unittest.main()
