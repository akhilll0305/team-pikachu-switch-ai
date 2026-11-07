# Checkpoint 2026-11-05: assessment fixes

The read-only assessment of `7b42217` (main) found 31 issues. They are merged
here into groups that share code, then fixed one group at a time on branch
`fix/checkpoint-2026-11-05`. A box is ticked only with evidence: the test,
command or live observation that shows it. Items only a person can do are in
group M and say so; they are not ticked on anyone's behalf.

Finding numbers (F1 to F31) refer to the assessment.

## A. Only maintainers decide (F1)

- [x] A1 Triage room is private in the template (`channel_type: channel_private`); intake room stays public.
- [x] A2 Intake accepts `escalate` / `close` / `override` / `release` only from maintainers on an allowlist (`maintainers` in `.proveit/intake.json`, set by `setup --maintainers`, default the deployer); everyone else gets a refusal.
- [x] A3 Read-only commands (`status`, `tally`, `evidence`) stay open to anyone in triage.
- [x] A4 Tests: an outsider's `close` / `escalate` / `override` / `release` are refused and the ticket is unchanged; a listed maintainer still decides.

  Evidence: `tests/test_intake.py` (`test_outsider_in_triage_cannot_decide`, `test_outsider_can_still_read`, `test_no_maintainers_configured_refuses_everyone`); rehearsal step 4 shows `someone-else` refused; template with `channel_type: channel_private` accepted by Switch 0.31.0 `/templates/validate` (no errors, no warnings).

## B. Agent roles and lockdowns (F2, F3, F4)

- [x] B1 Each agent's identity comes from its own config (`PROVEIT_AGENT=reproducer|skeptic`), not from `--by`. Agents' `--by` is replaced by their role.
- [x] B2 The CLI enforces roles: the Reproducer may `check` and read; the Skeptic may only read. No agent can `concur`/`dispute` from a shell.
  *Changed from the plan:* the Skeptic records `concur` / `dispute` by posting `@prove-it-intake concur R-001` in triage. Switch tells Intake who sent a message, so Intake records a verdict only from the real `prove-it-skeptic` agent (or a listed maintainer). This is stronger than an environment variable, and it lets the Skeptic's sandbox be read-only (decision D-009).
- [x] B3 Reproducer's Claude allow list no longer contains `concur`/`dispute` (they are denied); the deny list covers other Python forms (`python -I*`, `python3.*`, `py`, absolute paths), file readers and `~/.proveit/**`.
- [x] B4 Skeptic's Codex lockdown no longer relies on listing commands.
  *Changed from the plan:* `approval_policy = "untrusted"` was tried and Codex 0.166 refuses to load it ("no longer supported"), which would have disabled the Skeptic's config. Instead a Codex **permission profile** (`default_permissions`) makes the OS sandbox deny every read of `~/.proveit`, every write outside the temp folder, and the network. The rules forbid every bypass found (`python -I -c`, `python3.9 -c`, `Get-Content`, `type`, `dd`, `xargs`, `paste`, `tee`, `powershell`, `pwsh`, `cmd`, `osascript`, ...).
- [x] B5 Reporter material, Intake's credentials and the sandbox's staging mounts move to `~/.proveit/<checkout>-<hash>/` (outside the checkout, so both configs can deny it by a fixed path). Old `work/<id>/private/` and `.proveit/intake.json` are moved on first use.
- [x] B6 `tests/test_agent_rules.py` covers every bypass from the assessment with `codex execpolicy`, checks the profile with `codex sandbox` from `agents/skeptic` (read of `~/.proveit` refused, write refused, proveit commands still run), and checks the Claude settings as data.
- [x] B7 Console's `--permission-mode auto` is documented in `agents/README.md` (live result recorded in J5).

  Evidence: 99 tests OK, rehearsal twice identical, template accepted by Switch's `/templates/validate`. `codex sandbox` from `agents/skeptic` with the project config: `cat ~/.proveit/...` -> "Operation not permitted"; `echo x > ../../work/zz` -> "Operation not permitted"; `python3 -m proveit list` runs.

## C. Evidence says only what it shows (F5, F6, F7, F8, F27, F28, F29)

- [x] C1 The patched comparison uses only a patched run with the same entry point and payload hash as the vulnerable run; otherwise the checklist says `patched_comparable: False` and a note explains.
- [x] C2 An inconclusive or invalid patched run does not count as "patched build checked"; a note says it was inconclusive.
- [x] C3 Skeptic verdicts and overrides record the run they refer to; a new vulnerable run marks an earlier verdict stale.
- [x] C4 Escalation needs a current Skeptic concur or a maintainer override (decision D-007); the refusal says which.
- [x] C5 `INVALID_PROOF` never becomes `not_reproduced`.
- [x] C6 Information-leak claims are never reported as "did not reproduce": the reporter is told the sandbox cannot decide them.
- [x] C7 A timeout where the child used little CPU (a slow or overloaded host) is `INCONCLUSIVE`, not `RESOURCE_EXHAUSTION`.
- [x] C8 Reporter messages state the patched result only when it is comparable, and never as proof of a fix when it is not.
- [x] C9 Tests for each of the above.

  Evidence: `tests/test_evidence.py` (16 tests: loader and payload mismatch, inconclusive patched run, stale concur and override, escalation needs review, invalid and inconclusive runs, information leaks, scope line); `tests/test_harness.py` busy vs idle timeout; `tests/test_sandbox.py` `test_sleep_is_not_a_proof` now gets `INCONCLUSIVE` from the real sandbox (cpu < 5 s). 115 tests OK with Docker, rehearsal twice identical. D-007 recorded in `context.md` (group K).

## D. Only the reporter completes their report (F9)

- [x] D1 In a reporter's thread, only the original reporter's replies change the ticket (decision D-008). Others get a notice and nothing changes.
- [x] D2 Ignored contributions are recorded privately (who, when, a hash) and counted in the ticket as `foreign_replies`, so maintainers can see that someone else tried.
- [x] D3 Tests: Bob's reply leaves Alice's ticket unchanged; Alice's reply still works.

  Evidence: `tests/test_intake.py` `Ownership` (Bob's proof ignored: status stays `awaiting_poc`, no payload, report unchanged, `foreign.json` has sender and SHA-256, triage sees only a count; Alice's reply still moves it to triage; a stranger in a triaged thread changes nothing). D-008 recorded in `context.md` (group K).

## E. Intake does not lose or repeat work (F21, F22, F23, F24)

- [x] E1 The event cursor per room is saved next to Intake's state (`~/.proveit/<checkout>/cursors-<agent>.json`) and resumed after a restart; reports posted while Intake was down are processed.
- [x] E2 The cursor advances only after the handler succeeded.
- [x] E3 The same message delivered twice creates one ticket (dedupe on message id).
- [x] E4 If telling the reporter fails, the ticket records `notified: false`, triage gets a warning, and `@prove-it-intake notify R-001` resends.
- [x] E5 Tests for each.

  Evidence: `tests/test_reliability.py` (cursor saved and resumed with `Last-Event-ID` and no `start_from=head`; cursor moves only after the handler, retried 3 times, then the event is kept in `failed-events.jsonl` and skipped; never goes backwards; duplicate report and duplicate command act once, also across a restart; a retry after a part-way failure does not duplicate the ticket; a failed notification is recorded, warned about and resent with `notify`, keeping the maintainer's note). 135 tests OK with Docker.

## F. Safe concurrent writes (F25)

- [x] F1 Temporary files have unique names.
- [x] F2 Every load-modify-save of a ticket holds a per-ticket lock (works on macOS, Linux and Windows).
- [x] F3 Run files and ticket ids are created exclusively, so two writers never share a number.
- [x] F4 Test: two simultaneous checks on one ticket both end up recorded; two simultaneous reports get different ids.

  Evidence: `tests/test_store.py` (5 concurrent checks all recorded with distinct numbers and no `.tmp` left; 8 concurrent reports get 8 ids; 4 threads x 20 updates lose none; a lock held by another process makes this one wait; locking a missing ticket creates nothing). 124 tests OK with Docker, rehearsal twice identical.

## G. Builds and tests everywhere (F10, F11, F12, F20)

- [x] G1 `tests/test_harness.py` skips on non-POSIX systems instead of failing discovery.
- [ ] G2 CI runs the unit tests on `windows-latest` (Docker tests skip there) as well as the full suite on Ubuntu. *Job added to `.github/workflows/ci.yml`; ticked when the PR's CI run passes (group N).*
- [x] G3 Dockerfile pins exact Cython and wheel versions.
- [x] G4 Every Docker call has a timeout; build failures include Docker's output.
- [x] G5 Fresh `python -m proveit build --force` on the demo machine, then the full suite with `PROVEIT_REQUIRE_DOCKER=1`, no unexpected skips.

  Evidence (macOS 27.2 arm64, Docker 29.5.2, Python 3.9.6, Codex 0.166.0): `docker build --no-cache` of both images succeeds and installs PyYAML 5.3.1 / 5.4 with Cython 0.29.37 and wheel 0.45.1; `python -m proveit build --force` then `PROVEIT_REQUIRE_DOCKER=1 python -m unittest discover -s tests -v`: 144 tests OK, none skipped; rehearsal twice identical. Windows discovery simulated by hiding `resource`: no import failures (`tests/test_portability.py`). `docker_available()` now also requires a Linux engine, so Docker Desktop in Windows-containers mode (and the Windows CI runner) skips the sandbox tests instead of failing. G4: `tests/test_portability.py` checks every `subprocess.run` / `wait` in `sandbox.py` has a timeout, and that build failures show Docker's last lines (with a hint for SHA-256 mismatches). F11's Cython hash mismatch is a download problem, not a code defect.

## H. Demo tooling and preflight (F13, F14, F30, F31)

- [x] H1 `scripts/replay.py` works against Console's native server: `replay.py login` saves a login to `~/.proveit/<checkout>/reporter.json` (older `.proveit/reporter.json` and env still work), port from Console's `ports.json`, channel found by display name, newest wins so leftovers are ignored, the public intake channel is joined if needed.
- [x] H2 `python -m proveit doctor` checks: Docker, both images current, Switch server reachable, Intake registered, rooms and `triage` link, triage private, agents present and in their own folders, maintainers set, reporter login for replays.
- [x] H3 Tests for doctor's checks that do not need live services.
- [x] H4 SETUP troubleshooting covers the Mattermost crash on room changes and the "admin" display name for Codex posts.

  Evidence: `python -m proveit doctor` run live on this machine (it found the real remaining problems: triage still public and no maintainers set, both fixed in J3), and it changes nothing (a bug where it moved the credentials file was found and fixed). `tests/test_doctor.py` (15 tests: agent folders and `auto` mode, missing maintainers, never moves files, private home 700 / login file 600, login precedence and Console port, newest channel wins, public channel joined, deleted channels ignored, agents may not run the doctor). 159 tests OK. The SETUP row about Switch naming the Skeptic as the sender is confirmed or corrected in J4.

## I. Honest metrics and scope (F26, F27)

- [x] I1 "Maintainer time" is renamed "time to decision" everywhere (tally, messages, docs).
- [x] I2 The reporter's first reply states the scope (PyYAML 5.3.1 vs 5.4, the four entry points).
- [x] I3 Tests updated.

  Evidence: `actions.decision_seconds`, tally field `seconds_to_decision`, tally line "time to decision 1.4 s", reporter cost line "N s from triage to decision (elapsed time, not effort)"; README and DEMO say the same. Scope line (I2) was added with group C: `messages.scope_line()` in the accepted, ask-for-proof and invalid-proof replies (`tests/test_evidence.py` `Scope`). 159 tests OK, rehearsal twice identical.

## J. Live verification (F15, F16, F17, F18, F19)

- [x] J1 Headless e2e (`scripts/e2e.py`) rerun on this branch; log saved to `docs/evidence/`.
- [x] J2 Rehearsal twice on this branch.
- [x] J3 Console redeployed from the updated template; Intake restarted on the new code.
- [x] J4 (also confirm what sender name Intake receives for the Skeptic's posts, and correct SETUP's troubleshooting row if needed) Live run in Switch Console with the real Claude Reproducer and Codex Skeptic: check, patched check, Skeptic review, maintainer decision, reporter reply. Room log and ticket JSON saved to `docs/evidence/`.
- [ ] J5 Live permission checks: each agent asked to read `private/` and to run a forbidden command; results recorded.
- [ ] J6 Live outsider check: a non-maintainer's `close` is refused in the real room.

  Progress 2026-11-05 18:05 IST: J1 `docs/evidence/e2e-2026-11-05-macos.log` E2E PASSED. J2 rehearsal twice identical. J3 Console redeployed from the updated template (triage `channel_private`, agents in their own folders, `doctor` READY); Colima switched to Rosetta after Mattermost (amd64 under QEMU) crashed three times. J4 started: R-004 reached triage from the reporter's account; `@prove-it-reproducer check R-004` was answered "On it" but no run had appeared after 2 minutes (probably waiting for a permission approval in Console). Found live and fixed: Intake's ticket message @-mentioned the Skeptic, causing an agent-to-agent reply loop. Still needed: a person runs `python3 -m proveit.intake maintainers add Admin` and restarts Intake (the deployer posts as `Admin` through Switch's chat), then the J4 to J6 steps.

  Progress 2026-11-06 03:30 IST (Windows 11, Console 0.40.1): J4 done. All four replays live with Claude Code 2.1.318 and Codex 0.166.0: check, patched check (same loader), Skeptic review, refused escalation while disputed, override, escalate, close, quarantine, refused escalation of the quarantined report, tally. Intake receives the Skeptic's posts as `prove-it-skeptic` although Mattermost shows "admin" (SETUP row confirmed). Evidence: `docs/evidence/live-console-2026-11-06-windows.log`, `docs/evidence/live-2026-11-06-windows-R-001/`. J5 and J6 not run.

## K. Documentation (F30)

- [ ] K1 README: tested-with table filled from this machine, OS support, verification table, commands, limits.
- [ ] K2 SETUP, DEMO, agents/README, blog draft match the code.
- [ ] K3 `context.md` updated (status, decisions D-007 and D-008, history); `AGENTS.md` and `context.md` committed.

## L. Future work (F31 list)

- [x] L1 `python -m proveit export R-001`: a folder of fixed-field evidence (ticket, runs, SHA-256 manifest), no reporter text. Tested.
- [ ] L2 README "After the hackathon" section: adapters, GitHub/HackerOne intake, separate OS user for agents, automatic fixing as a separate workflow.

## M. Only a person can do these

Tooling for each is in place; they are not ticked by the agent.

- [x] M1 Configure Switch Trust and confirm replay 04 is blocked (SETUP section 5). Done 2026-11-06 by the human maintainer on the Windows demo machine. With the Regex-only policy, 04 was blocked before the room and every legitimate message passed unchanged. The Jailbreak detector was dropped because it blocked report 02's proof (D-010 in `context.md`). Evidence: `docs/evidence/live-trust-2026-11-06-windows.log`.
- [ ] M2 Run the Trust red-team evaluation and record the score.
- [ ] M3 Record agent cost from Switch ROI with `python -m proveit cost`.
- [ ] M4 A Windows teammate runs the suite on Windows.
- [ ] M5 Confirm decisions D-007 and D-008 as a team (defaults chosen here).
- [ ] M6 Record the demo video and submit by 2026-11-07 11:59 PM IST.

## N. Pull request

- [ ] N1 Branch pushed and a PR opened against `main` with this checklist's result.

## O. OpenSSF triage practices (branch feat/openssf-triage)

O1 to O6 are verified offline. Live coverage is partial, as recorded under O8; do not claim the complete practices live until the remaining room checks pass.

- [x] O1 (U1a) Each check runs 3 times, one after another, in fresh containers; runs that disagree give `NOT_RELIABLY_REPRODUCED`, which needs an override to escalate (D-011, D-012). Evidence: `tests/test_repeats.py`, `tests/test_sandbox.py` `Repeats.test_real_check_runs_three_fresh_containers_and_leaves_none`, timing from `scripts/time_checks.py` in the commit message.
- [x] O2 (U1b) A dispute needs exactly one reason code; codes that contradict the evidence are refused; the reporter's one fixed question is sent only on close, chosen in the D-014 order (D-013, D-014). Evidence: `tests/test_reasons.py`. The new Skeptic instructions are in `switch/prove-it.template.yaml` and are **not** in the live Console agent yet: merging this branch makes Intake refuse the live Skeptic's free-text disputes until they are pasted in.
- [x] O3 (U1c) [docs/policy/pyyaml-scope.md](policy/pyyaml-scope.md) written and enforced at Intake: out-of-scope entry points get a fixed answer and never reach the sandbox (D-015). The allowlist needed no change. Evidence: `tests/test_scope.py`.
- [x] O4 (U1d) The proof request lists four fields; `affected_version` is required, and `expected`/`actual` never reach agents (D-016). Replays 01 to 04 updated and still labelled as replays. Evidence: `tests/test_report_fields.py`, `tests/test_sandbox.py` `Canary` (canary in expected/actual).
- [x] O5 (U2) A successful `escalate` writes the DRAFT advisory pack (OSV draft `x_DRAFT-PROVEIT-R-NNN`, GHSA draft, timeline); no payload, no fixed version; included in the export (D-017). Evidence: `tests/test_advisory.py`; the OSV schema copy and its source are in `tests/data/`.
- [x] O6 (U3) Proof record per reporter (HMAC of the Switch id, outcomes only, one strike per ticket); at 2 failures a reporter may have one open report at a time until `clear-reporter`; agents are refused in the CLI and the room (D-018). Evidence: `tests/test_reputation.py`; rehearsal step 6.
- [x] O7 (U5) README (who pays, OpenSSF practices with a source per row, verification rows, commands, test count), DEMO (3:00, new scenes marked "needs a live run before recording", take order and the reporter limit), SETUP, blog draft, and a draft OpenSSF comment in `docs/outreach/` (not posted). Links and headings checked by hand.
- [ ] O8 Complete live run of everything in O1 to O6. Partial live evidence: isolated R-001 ran on both PyYAML builds 3/3, and the room history now shows a current Skeptic concurrence after a maintainer supplied the evidence pack. The managed Skeptic's own evidence command failed to import `proveit`; reason-coded dispute, reporter question, advisory pack, reporter limit and `clear-reporter` still need live verification. The Console automation tool declined access, so no Console settings were changed.

## P. Second target (U4, branch feat/second-library)

Each item is verified offline, not yet live. It is stacked on `feat/openssf-triage`; the merge path is branch 2 -> branch 1 -> `main`. Nothing here deploys the sqlparse rooms or changes a live agent. Decisions D-019 to D-023.

- [x] P0 (Gate 0) A public CVE whose PoC is a text input to a documented entry point, reproducing offline on a pinned pair under the same limits as PyYAML, before any adapter or room code. sqlparse CVE-2023-30608 (ReDoS, GHSA-rrm6-wvj7-cwh2): a 43-byte SQL payload through `sqlparse.parse` recorded RESOURCE_EXHAUSTION 3/3 on 0.4.3 and NOT_REPRODUCED 3/3 on 0.4.4. Evidence: `tests/test_second_target.py` and [verification log](evidence/fix-pass-2026-11-07-windows.log); the earlier local report remains untracked.
- [x] P1 (C1) One target adapter (`proveit/targets.py`); the sandbox, Intake, messages, evidence and advisory take a target. PyYAML unchanged: same tests, same rehearsal digest `d7ad7ae2c8b6294c`, `target/` byte-identical (harness hash `9b1b9e654cc0f147`) (D-019). Evidence: `tests/test_targets.py`.
- [x] P2 (C2) sqlparse target with its own `target-sqlparse/` (own Dockerfile and image tags, harness and child copied with a header), allowlist `parse`/`format`/`split`, an empty out-of-scope list, [its scope policy](policy/sqlparse-scope.md), built only by `proveit build --target sqlparse` (D-020, D-023). Evidence: `tests/test_second_target.py` (Docker tests skip without the images, never build one); second-target rehearsal `c34d857c31d97fb6`.
- [x] P3 (C3) One Intake serves both room pairs; target comes from the room not the text; global ticket ids; shared reporter record; cross-room decisions accepted; the sqlparse rooms in a separate template `switch/prove-it.sqlparse.rooms.template.yaml`; shared Reproducer/Skeptic instructions are now target-neutral and refer to the ticket target and room scope policy (D-021, D-022). Evidence: `tests/test_rooms.py`, `tests/test_trial.py`.
- [x] P4 (C4) README ("A second target" section replacing the future-work line, verification rows, test count 285), context.md (D-019 to D-023, status, history), this checklist, DEMO note (take order unchanged). Links and headings checked by hand.
- [ ] P5 Live run: the room pair is not deployed and neither registered agent has the updated target-neutral instructions. Deploy the separate room template, build sqlparse images on the demo machine, update both agents, then run and review a ticket in those rooms. Not done; Console automation access was declined, so no changes were made.

## Q. Second-library fix pass (2026-11-07)

- Adapter compatibility and harness-copy guards: `tests/test_targets.py` now exists. Classification, limits and normalized shared functions match; no pre-existing shared-code drift was found. The sqlparse header now also names main()'s library-label difference. Unknown target keys retain the documented PyYAML fallback.
- Loader selection is validated against the ticket's target before any run. Evidence reason codes require a conclusive, comparable patched result where applicable.
- Delivery receipts survive report retries and restarts; terminal decision messages are idempotent; failed advisory work is retryable. Late checks do not rewrite the decision evidence. Agent verdicts require an evidence review token.
- Build waiting has an effective deadline even for silent builds. CI explicitly builds/rehearses sqlparse and requires its Docker tests; OSV schema validation is installed.
- Evidence: `tests/test_fix_pass.py`, `tests/test_targets.py`, `tests/test_portability.py`. Final Windows checks: 306 tests OK, 12 expected skips; optional OSV schema test passed separately with jsonschema 4.26.0. Both rehearsals passed twice with unchanged digests. See [verification log](evidence/fix-pass-2026-11-07-windows.log).
- Not verified live: updated instructions/templates, permission probes, outsider checks, Trust red-team evaluation and recorded costs. Historical live logs remain historical.


## R. Isolated second-branch trial preparation (2026-11-07)

- [x] Trial-specific names, generated settings/templates, credentials and ticket/private storage. Existing agent permission rules preserved; unexpected triage links refused. Evidence: `tests/test_trial.py` (12 tests), [guide](TRIAL.md).
- [x] Full suite after the parser and prompt fixes: 321 tests OK (12 skipped). Default rehearsal twice: `d7ad7ae2c8b6294c`; sqlparse rehearsal twice: `c34d857c31d97fb6`. Protected PyYAML target files byte-identical; all four existing image IDs unchanged. The current run skipped the optional OSV schema test; it passed separately with jsonschema 4.26.0 in the earlier [fix-pass log](evidence/fix-pass-2026-11-07-windows.log).
- [ ] Full generated-trial verification. Partial: the isolated Reproducer/Skeptic and PyYAML rooms are deployed, and Claude ran both R-001 builds 3/3. A current visible Skeptic concurrence followed a maintainer-supplied evidence pack, but its own `proveit evidence` command failed to import the package. Agent permissions, all U1–U3 behaviors, and cross-room flow remain unverified live.
- Live preflight: all three generated templates were accepted by Switch with no findings; isolated Intake registered. The isolated Reproducer and Skeptic and primary rooms are now deployed and running. The current trial chat shows the Skeptic's visible concurrence for R-001 only after a maintainer supplied sanitized current evidence. The agent's own evidence command had a `No module named proveit` failure; do not claim its independent evidence read is verified. SQL rooms are absent. Console automation access was declined, so the remaining template/room changes await a manual Console update. [Preflight evidence](evidence/trial-preflight-2026-11-07-windows.log).
