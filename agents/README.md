# Agent working folders

The Switch template starts each triage agent in its own folder here, not in
the repository root, so the lockdowns below apply only to the agents and
never to people developing Prove It.

| Folder | Agent | Config | What it enforces |
| --- | --- | --- | --- |
| `reproducer/` | Reproducer (Claude Code) | `.claude/settings.json` | `defaultMode: dontAsk` (anything not allowed is denied, no prompt), `disableBypassPermissionsMode: disable`. Allows only `python -m proveit check / evidence / show / list / tally / export`. Denies `concur` / `dispute` (it may not judge its own evidence), `override` / `cost`, every other way of running Python (`-c`, `-I`, `python3.x`, ...), file readers, shells, network tools, `docker`, `git`, the Edit/Write tools, web tools, and reads of `~/.proveit/**`. Sets `PROVEIT_ACTOR=agent`, `PROVEIT_AGENT=reproducer`. |
| `skeptic/` | Skeptic (Codex) | `.codex/config.toml`, `.codex/rules/proveit.rules` | A Codex **permission profile**: the OS sandbox may read the disk except `~/.proveit` (`"none"`), may write only its temp folder, and has no network. `sandbox_mode = "read-only"` is the fallback. The rules forbid, before the sandbox is even reached, `proveit check / concur / dispute / override / cost / submit / build`, every other way of running Python, file readers (`cat`, `Get-Content`, `dd`, `xargs`, ...), shells, network tools, `docker` and file changes. Sets `PROVEIT_ACTOR=agent`, `PROVEIT_AGENT=skeptic`. |

## Where the secrets are

Everything an agent must never read lives in `~/.proveit/<checkout>-<hash>/`
(see `proveit/config.py`), not in the checkout:

- `private/R-001/`: the reporter's text, payload, screen result and thread.
- `intake.json`: Intake's Switch credentials and the maintainer list.
- `reporter.json`: the Mattermost login `scripts/replay.py` uses (optional).
- `mounts/`: the sandbox's short-lived staging copies of payloads.

Because the path starts at the home folder, both lockdowns can name it
without knowing where you cloned the repository. Older versions kept these in
`work/<id>/private/` and `.proveit/`; they are moved on first use.

## Who records what

| Action | Who | How |
| --- | --- | --- |
| Run a payload (`check`) | Reproducer | its shell, `python -m proveit check R-001` |
| Concur / dispute | Skeptic | a message in `#proveit-triage`: `@prove-it-intake concur R-001 review=<token>` or `@prove-it-intake dispute R-001 <reason_code> review=<token> [note]` (one code from `proveit/reasons.py`). Switch tells Intake who sent it; Intake records it only from `prove-it-skeptic` (or a maintainer). The Skeptic's shell is read-only. |
| Escalate, close, override, release | Maintainers listed in Intake's settings | `@prove-it-intake escalate R-001`, ... (`python -m proveit.intake maintainers add <name>`) |

`PROVEIT_AGENT` gives each agent its role in the CLI, and an agent's `--by` is
replaced by that role. It is an honest-mistake guard, not a boundary: the
boundaries are the Skeptic's sandbox profile, the Reproducer's allow list,
Switch's sender identity in the room, and the payload sandbox.

## Things to check in Switch Console

- **Bypass permissions must stay off** for both agents. The template sets
  `auto_approve: false`.
- **Console starts agents in its `auto` mode.** On Switch Console (2026-11-05)
  the Reproducer runs as `claude --permission-mode auto` even with
  `auto_approve: false`. A command-line mode can take the place of
  `defaultMode: dontAsk`, so a command that is neither allowed nor denied may
  go to Claude's own automatic check instead of being refused. The deny list
  above is written for that case: it names the ways around the allow list
  instead of relying on "everything else is denied". Check it on your machine
  (`python -m proveit doctor` shows the mode it sees), and see
  [docs/evidence/](../docs/evidence/) for the live result.
- **Trust each folder once** so project settings apply: run `claude` in
  `agents/reproducer` and accept the trust prompt; run `codex` in
  `agents/skeptic` and trust the project. Claude Code's deny rules apply even
  before trust; its allow rules and `env` wait for it. Codex ignores
  `.codex/` until the project is trusted.

`PYTHONPATH=../..` lets `python -m proveit` run from these folders; tickets
still live in the checkout's `work/`.

`tests/test_agent_rules.py` checks the Claude settings as data, and the Codex
rules and sandbox profile with Codex itself (`codex execpolicy` and `codex
sandbox`) when Codex is installed.

Every agent verdict must carry `review=<token>` copied from the evidence pack it inspected. Intake checks the token while holding the ticket lock; a delayed verdict is refused after the evidence changes. Maintainer verdicts may omit it. Update the live Skeptic instructions before using this branch.

## How `python -m proveit` works from these folders

Each folder has a small `proveit/` package (`agents/<role>/proveit/__init__.py`).
Python looks in the working folder first for `python -m`, so the agent finds it.
It points at the real `proveit/` in the checkout from its own location, and it
fixes the folder's role (`PROVEIT_ACTOR=agent`, `PROVEIT_AGENT=<role>`).

This does not depend on the session applying `PYTHONPATH` or role variables from
the agent's config. On 2026-11-07 the Switch-managed Skeptic's session did not,
and failed with `No module named proveit`. An environment that claims to be a
human cannot widen the role either. `tests/test_agent_folders.py` checks both
folders with those variables removed.
