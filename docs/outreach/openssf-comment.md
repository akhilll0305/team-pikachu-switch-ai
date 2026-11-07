# Draft comment for OpenSSF issue #178

> **Status:** draft only, **not posted**. Target: <https://github.com/ossf/wg-vulnerability-disclosures/issues/178>. A team member posts it by hand, if at all, after reading it again and only once this work is merged and has had a live run (the repo link points at `main`). The comment is the text between the lines (under 150 words).

---

We built one implementation of several practices from this thread and the draft guide, for a single library (PyYAML), during a hackathon. Two things we learned:

1. Scope works best enforced in code. Intake rejects a proof through a loader PyYAML documents as unsafe before anything runs, with a fixed answer citing the policy. Nobody has to argue it per report.
2. Reason codes need an evidence check. Each rejection carries one code with one fixed question for the reporter, and the code is refused when the recorded runs contradict it (for example "not reproduced" when every clean run reproduced).

We also repeat each proof three times in fresh containers, and we do no AI detection. Code, tests and limits: https://github.com/akhilll0305/team-pikachu-switch-ai

---
