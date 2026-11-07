# Isolated live trial status — 2026-11-07

This is a short, sanitized account of the local `review` trial as inspected in
Switch on 2026-11-07. It is not a complete end-to-end sign-off.

## Observed

- `R-001` ran through `full_load` on pinned PyYAML 5.3.1 and 5.4 builds.
- PyYAML 5.3.1 recorded `CODE_EXECUTION`, 3/3 clean runs, image prefix
  `d8219ba0f788`.
- PyYAML 5.4 recorded `NOT_REPRODUCED`, 3/3 clean runs, image prefix
  `00125fc0958b`.
- The Switch-managed Skeptic's first evidence command failed with
  `No module named proveit`. A later read-only room-history inspection showed
  a visible Skeptic concurrence after a maintainer supplied the sanitized
  evidence pack. That confirms the reply arrived, but not an independent read
  by the Skeptic.
- The isolated Reproducer and Skeptic are running in the primary PyYAML rooms.
  The sqlparse rooms have not been deployed.

## Still unverified

- A fresh managed Skeptic evidence command and review from its own session.
- Live reason-coded dispute behavior, fixed reporter question, advisory pack,
  reporter limit and reset, permission probes, and cross-room behavior.
- The sqlparse rooms, sqlparse images on the demo machine, and a live sqlparse
  check/review.
- Reporter and maintainer identity separation for human decisions.

No ticket escalation or close was observed. The Windows computer-use layer
declined access to Switch Console during this work, so no Console settings,
agent definitions, or rooms were changed.

## Follow-up the same day: fixes and headless checks (no Switch Console)

Run on a separate Windows 11 machine with Docker Desktop 29.6.2 and the headless
Switch 0.31.0 server from `scripts/switch-server.sh`. No Switch Console, so no
Claude Code or Codex sessions.

**`No module named proveit` (item 1): cause and fix.**
- The Skeptic's `PYTHONPATH = "../.."` comes only from
  `agents/skeptic/.codex/config.toml`, and is relative. The managed session did
  not apply it.
- The same variables also carry the agent's role (`PROVEIT_ACTOR`,
  `PROVEIT_AGENT`). Without them the CLI would have treated the Skeptic's shell
  as a human maintainer once the import worked.
- Fix: `agents/skeptic/proveit/` and `agents/reproducer/proveit/` are stand-in
  packages. `python -m proveit` run from an agent's folder finds the real package
  from the stand-in's own location, and the folder fixes the role. An environment
  that claims `PROVEIT_ACTOR=human` cannot widen it.
- `tests/test_agent_folders.py` runs the CLI from both folders with
  `PYTHONPATH`, `PROVEIT_ACTOR`, `PROVEIT_AGENT` and the home folder removed or
  unusable.

**Headless live checks** ([log](live-checks-2026-11-07-headless.log), `python scripts/live_checks.py`): 35 of 35 passed.
- Both room templates deployed unmodified through Switch's `create_room_from_yaml`.
- A reporter and a maintainer as separate Mattermost accounts.
- Item 2: a contradicting dispute code refused; a valid one recorded; escalation
  refused while disputed; the reporter got the fixed `not_reproduced` question on close.
- Item 3: escalation posted the DRAFT advisory note; `osv-draft.json`,
  `ghsa-draft.md`, `timeline.md` exist, with no payload or reporter prose.
- Item 4: after two failed proofs a second open report was refused. The reporter
  account's `clear-reporter`, `close` and `escalate` were refused even from inside
  triage. The maintainer lifted the limit.
- Item 5: a sqlparse report became a sqlparse ticket in `#sqlparse-triage`;
  0.4.3 RESOURCE_EXHAUSTION 3/3, 0.4.4 NOT_REPRODUCED 3/3; the review recorded;
  escalated with its advisory note; the reporter told.
- Switch 0.31.0 sends `sender` for human messages, so the reporter record is keyed
  by participant id.
- The Reproducer and Skeptic were Switch protocol agents driven by the script.
  They ran `python -m proveit` from their own folders with no environment (item 1's
  mechanism), but their choices were scripted.
- Setup detail: an agent registered with the registration token is owned by the
  server's bootstrap user, which has no linked Mattermost account, so a template's
  `{$creator}` fails until the gateway admin links one. Console users are linked
  when they sign in, so this is specific to the headless setup.

**Still needs Switch Console** (not possible without it):
- The managed Skeptic running `python -m proveit evidence R-001` from its own
  session and posting its verdict.
- The live Skeptic choosing and posting a reason-coded dispute.
- Updating the two registered agents to the target-neutral instructions,
  deploying the sqlparse rooms in Console, and both agents working a sqlparse ticket.
- Human decisions in Console's rooms by separate reporter and maintainer accounts.
