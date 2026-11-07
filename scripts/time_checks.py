"""Wall time of `check` with 1 run versus config.CHECK_RUNS runs (the U1a timing rule).

Uses the real sandbox (Docker must be running) on throwaway tickets made from
the replay fixtures, in a temporary work folder. Prints a Markdown table:

  | check | runs=1 (s) | runs=3 (s) | added (s) |

Each cell is the mean of --repeat measurements (default 3); the individual
measurements are printed above the table. The worst case is a full_load
payload that keeps the CPU busy until the harness's 10 s call limit
(RESOURCE_EXHAUSTION). The container's own 20 s timeout cannot be reached by
a data payload, so it is not measured.

  python scripts/time_checks.py [--repeat 3]
"""

import argparse
import os
import statistics
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

BUSY = ("Title: timing worst case\nSeverity: medium\nAffected version: 5.3.1\nEntry point: yaml.full_load\n"
        "Claimed impact: denial of service\n\n```yaml\n!!python/object/new:tuple\n- !!python/object/new:map\n"
        "  - !!python/name:exec\n  - [\"while True: pass\"]\n```\n")


class Room:
    def post(self, body, thread_id=None):
        pass


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repeat", type=int, default=3)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="proveit-timing-") as tmp:
        os.environ["PROVEIT_WORK_DIR"] = str(Path(tmp) / "work")
        from proveit import actions, config, sandbox, store
        from proveit.intake import Intake
        config.WORK_DIR = Path(tmp) / "work"
        if not sandbox.docker_available():
            sys.exit("Docker must be running.")
        sandbox.build()
        replays = ROOT / "reports" / "replays"
        intake = Intake({"agent_name": "prove-it-intake", "maintainers": []}, source="timing")
        intake.intake = intake.triage = Room()
        n = [0]

        def ticket(text, followup=None):
            n[0] += 1
            root = "m%d" % n[0]
            intake.on_intake_event(None, "message", {"payload": {"body": text, "message_id": root, "thread_id": None,
                                                                 "sender_name": "timing", "sender_kind": "user"}})
            if followup:
                n[0] += 1
                intake.on_intake_event(None, "message", {"payload": {
                    "body": followup, "message_id": "m%d" % n[0], "thread_id": root,
                    "sender_name": "timing", "sender_kind": "user"}})
            return store.all_tickets()[-1]["id"]

        def read(name):
            return (replays / name).read_text(encoding="utf-8")

        cases = [
            ("01 vulnerable", lambda: ticket(read("01-real-cve-2020-14343.md")), "vulnerable"),
            ("01 patched", lambda: ticket(read("01-real-cve-2020-14343.md")), "patched"),
            ("02 vulnerable", lambda: ticket(read("02-slop-safe-load-rce.md"), read("02-slop-safe-load-rce.followup.md")),
             "vulnerable"),
            ("03 vulnerable", lambda: ticket(read("03-slop-billion-laughs.md")), "vulnerable"),
            ("worst case: 10 s call limit, vulnerable", lambda: ticket(BUSY), "vulnerable"),
        ]
        rows = []
        for label, make, build in cases:
            means = {}
            for runs in (1, 3):
                config.CHECK_RUNS = runs
                samples = []
                for _ in range(args.repeat):
                    tid = make()
                    if build == "patched":
                        actions.check(tid, "vulnerable", actor="human", by="timing")
                    start = time.perf_counter()
                    _, run, _ = actions.check(tid, build, actor="human", by="timing")
                    samples.append(time.perf_counter() - start)
                    outcome = run["outcome"]
                means[runs] = statistics.mean(samples)
                print("%s, runs=%d: %s -> %s" % (label, runs, ", ".join("%.2f" % s for s in samples), outcome))
            rows.append((label, means[1], means[3]))
        print("\n| check | runs=1 (s) | runs=3 (s) | added (s) |\n| --- | --- | --- | --- |")
        for label, one, three in rows:
            print("| %s | %.2f | %.2f | %.2f |" % (label, one, three, three - one))


if __name__ == "__main__":
    main()
