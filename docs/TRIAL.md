# Isolated live trial on the second branch

Run these commands from the `feat/second-library` checkout, currently
`D:\PROJECTS\Switch-the-flip\pikachu-lib2`. Keep the working demo's agents,
rooms, Intake process and configuration in place. Use this trial only after
the full tests and both offline rehearsals pass twice.

## Prepare without deploying

```sh
python -m proveit.trial review
```

This writes ignored files under `.proveit-trials/review/`: copies of the
reviewed agent settings, three templates and `trial.json`. It refuses to
overwrite an existing trial. It registers no agents, creates no rooms and
does not build or retag Docker images. The agent permission rules stay the
same; only their environment paths change.

The trial uses `review-prove-it-intake`, `review-prove-it-reproducer` and
`review-prove-it-skeptic`. Its four rooms are `review-proveit-intake`,
`review-proveit-triage`, `review-sqlparse-intake` and
`review-sqlparse-triage`. Tickets stay under `.proveit-trials/review/work/`.
Credentials, cursors and private reporter material stay under the checkout's
separate `~/.proveit/<checkout>-<hash>/trials/review/` directory.

## Register and deploy only the trial

```sh
python -m proveit.intake --trial review setup --maintainers <your-username>
```

Intake finds the Console server as described in [SETUP](SETUP.md#3-register-the-intake-agent).
Do not use `--overwrite` to replace a trial belonging to another checkout;
choose a new trial name instead. Trial setup refuses manual agent/room-name
overrides and `--create-rooms`.

In Console, add the generated `.proveit-trials/review/prove-it.template.yaml`.
Check its preview: all names must start with `review-`; the agent directories
must be inside this checkout's `.proveit-trials/review/agents/`. Keep **Bypass
permissions** off. Deploy it once, then deploy the generated
`prove-it.sqlparse.rooms.template.yaml` to add the second room pair using the
same agents. The generated `prove-it.rooms.template.yaml` is only for
recovering room creation after agent creation; do not deploy both room
templates for the same primary pair.

Trust only the generated agent folders when the providers require project
trust. Preserve the Skeptic's read-only sandbox: it posts its verdict to
Intake in the room with `review=<token>`; it never needs write access to record
a verdict. Do not loosen the permission profiles to make a test pass.

```sh
python -m proveit.intake --trial review run
python -m proveit doctor --trial review
```

Use `--trial review` on every Intake/doctor invocation for this trial.
It selects the isolated credentials and paths for that process only. Intake
refuses trial links that point outside the configured triage rooms. Ordinary
commands without the option keep their existing configuration.

## Evidence and rollback

Verify actual Claude/Codex behavior: PyYAML vulnerable and patched checks,
an evidence-token verdict and stale-token refusal, a reason-coded dispute,
maintainer decisions and advisory files; then sqlparse and the shared reporter
limit across both room pairs. Permission probes must use a synthetic private
canary, never real credentials. Existing server-wide Switch Trust still
applies; record a pre-room Trust block separately from Intake quarantine.

Record provider versions, actual responses, refusals and unverified steps.
An offline scripted rehearsal cannot establish these live results.

Keep one logical change per commit on `feat/second-library`, with tests and
the result in [context.md](../context.md). If a published commit regresses the
workflow, use `git revert <commit>` on this branch and test again. Stop the
trial Intake and trial agents if the live trial fails; retain the evidence.
Do not reset main, rewrite shared history, or rebuild the protected PyYAML
images.
