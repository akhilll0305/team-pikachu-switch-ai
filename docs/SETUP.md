# Setting up Prove It in Switch Console

About 15 minutes the first time. You need Docker, Python 3.9+, Switch Console, and Claude Code and Codex signed in. Everything runs on your machine.

On Apple silicon Macs, Docker Desktop or a Docker-compatible Colima runtime works. If using Colima, install the Docker Compose plugin and make sure `docker compose version` succeeds. The sandbox keeps its temporary PoC mount under the checkout's ignored `.proveit/` directory, which must be shared with the Docker VM (keep the checkout under your home folder).

## 1. Get the code and build the sandbox

```sh
git clone https://github.com/akhilll0305/team-pikachu-switch-ai
cd team-pikachu-switch-ai
python -m proveit build
python -m unittest discover -s tests       # 325 tests; Docker running; duration depends on host
python scripts/rehearse.py                 # the whole demo offline, no Switch
```

Expected on Windows 11 (2026-11-07): the latest full run on this branch reported `Ran 325 tests ... OK (skipped=15)` with Docker and both image pairs present, on a machine without the Codex CLI (its 3 rule tests skip; with Codex installed it is 12 skips). The optional OSV schema test is skipped when `jsonschema` is absent; it passed separately with jsonschema 4.26.0 ([earlier fix-pass evidence](evidence/fix-pass-2026-11-07-windows.log)). Without sqlparse images, the two sqlparse reproduction tests add two skips and never build an image. Source archives or shallow checkouts can also skip the unavailable Git baseline guard.

`build` creates `proveit-target:vulnerable` (PyYAML 5.3.1) and `proveit-target:patched` (PyYAML 5.4). It needs network once; the sandbox never has network. Images rebuild automatically when the harness changes.

**Settings** (edit `proveit/config.py`; they are not environment variables, so an agent's shell cannot change them):

- `CHECK_RUNS = 3`: how many times one `check` runs the payload, one after another, each in a new container with the same limits. All runs must agree; if they differ, the check records `NOT_RELIABLY_REPRODUCED`, which a maintainer must override before escalating. On the demo machine, 3 runs add about 1.4 s to a normal check; a payload that hits the 10 s call limit takes about 32 s (`python scripts/time_checks.py` measures it on yours). Verified offline, not yet live.
- `INVALID_THRESHOLD = 2`: a reporter whose proofs failed this many times may have only one open report at a time. A failure is a ticket closed as `NOT_REPRODUCED` or `NOT_RELIABLY_REPRODUCED`, or a proof Intake rejected, at most one per ticket. A second report gets a fixed reply, its text is not stored, and `#proveit-triage` is told how to lift the limit: `python -m proveit clear-reporter <key>` on the host, or `@prove-it-intake clear-reporter <key>` from a maintainer in the room (agents are refused). The record is `reporters.json` in the private folder, keyed by an HMAC of the reporter's Switch id; deleting the private folder (the DEMO reset) clears it. Verified offline, not yet live.

## 2. Start a Switch server

In Switch Console: **Add a server → Run a server on this computer → Start**, and wait until the sidebar shows **Running locally**. Then **Home → Messaging apps → Mattermost → Sign-in details… → Open in Mattermost** and sign in.

Under **Settings → Agent providers**, confirm Claude Code and Codex both show **Signed in** (`claude auth login`, `codex login`).

**On Windows** (checked with Console 0.40.1 on 2026-11-06): Console cannot run Claude Code or Codex inside itself ("Not supported here"); it runs them as *managed agents* on the machine **This computer**, through its agents controller. The template picks that machine on its own (`location: [$first]`), so no Linux, WSL or SSH host is needed. **Your Agents → Add agent** shows the machine and whether Claude Code and Codex are **Ready** there.

## 3. Register the Intake agent

Intake is our own Switch agent, written against the agent protocol. It is not a Claude or Codex session, so Console does not create it; this command does:

```sh
python -m proveit.intake setup
```

It finds Console's local server settings (either the Docker `.env` or the native server's `native/run/switch-core.env` under `<app data>/<Switch Console>/local-switch-server/`), registers `prove-it-intake` with the server's registration token, and opens it to everyone in its rooms so reporters can reach it. Credentials go to `~/.proveit/<checkout>-<hash>/intake.json`, outside the checkout. Use `--env-file` and `--api-url` for a server elsewhere, and `--overwrite` to re-register.

## 4. Deploy the template

In Switch Console open **Templates**, add a template from YAML, and paste [`switch/prove-it.template.yaml`](../switch/prove-it.template.yaml). On the form:

- **Prove It checkout**: the folder you cloned in step 1. Console 0.40.1 has a display bug in this box when agents run on a managed machine: it shows the finished path (`<checkout>/agents/reproducer`) and every key you type is added to that. Click in it, press **Ctrl+A**, paste the checkout path with **Ctrl+V** once, and do not type in it again. Check the **Preview** instead: it must show `<checkout>/agents/reproducer` and `<checkout>/agents/skeptic`, nothing doubled. The Reproducer starts in `agents/reproducer/` and the Skeptic in `agents/skeptic/` inside it; each folder holds that agent's permission lockdown ([agents/README.md](../agents/README.md)).
- **Reproducer runs on** / **Skeptic runs on** (under Advanced): Claude Code and Codex by default. Keep them on different vendors. On a managed machine Console may show a yellow "No agent type is set up for Switch on <machine id>" under these fields; that check looks in the wrong place. The **Preview** and "Defaults to claude / codex" are what count.

Create it (**Create all**). If the agents were created but the rooms were not (for example Mattermost was down), do not run the whole template again: the agent names are taken and nothing is created. Add [`switch/prove-it.rooms.template.yaml`](../switch/prove-it.rooms.template.yaml) as a second template (under another name) and use that; it creates only the rooms, link, instructions and document. You get `prove-it-reproducer`, `prove-it-skeptic`, and a **Prove It** room group with `#proveit-intake` and `#proveit-triage`, linked as `triage`, plus the room instructions and the `verdict-rules` and `scope-policy` documents. The kickoff asks both agents to introduce themselves in triage.

**If you deployed before 2026-11-07,** the Skeptic still has the old instructions and posts free-text disputes, which Intake now refuses (a dispute needs one reason code, see the README's Commands). Paste the Skeptic's `instructions` from the template into its **Configuration**, check that Console logs a new revision (troubleshooting below), and add the `scope-policy` room document. Then do a full live run before relying on it. Not yet done on the demo machine.

Then, for each agent:

- Confirm **Bypass permissions** is off. The template sets `auto_approve: false`; check that Console shows it that way.
- Trust its folder once, so its project settings apply (trusting the whole checkout also covers both folders): run `claude` in `agents/reproducer` and accept the trust prompt; run `codex` in `agents/skeptic` and trust the project. Deny rules in Claude Code apply even before trust; allow rules and the `env` block wait for it.
- Skeptic only: preserve its read-only sandbox. It records verdicts by posting to Intake in the room with the evidence's `review=<token>`; it does not run the `concur` or `dispute` CLI and needs no writable ticket directory.

The two agents use `addressing: owner-agents`: only you (the deployer) and your own agents can instruct them. Other maintainers you add to `#proveit-triage` can still decide through Intake (`escalate`, `close`, `override`, `release`), which checks that the sender is a person.

If Console refuses the template because it cannot add `prove-it-intake` to a room, create the rooms from the template anyway with that name removed, then type `!invite-agent @prove-it-intake` in each room. The link labelled `triage` from `#proveit-intake` to `#proveit-triage` must exist: Intake finds the triage room through it and refuses to start without it.

## 5. Turn on Switch Trust

Switch Trust checks each human message before it enters a room. A blocked message never becomes a room message, so neither Intake nor any agent receives it. Mattermost still shows the post to people, and Switch replies in its thread: "🚫 Your message was blocked by Switch Trust and was not delivered to the room." Checked live on 2026-11-06 ([evidence](evidence/live-trust-2026-11-06-windows.log)).

1. Sign up at [app.switchagents.ai](https://app.switchagents.ai/) (organization name, then a short survey).
2. **Settings → Configurations → Guardrail policies → Add policy.** Name it `Prove It guard` and set it up like this:
   - **Regex**: On. Custom name `Prove It injection`. Tick **User** only, with Action **Block** and Severity **High**. Severity is only a label; it does not change what matches. Paste these two patterns, one per line:
     ```
     (?i)ignore\s+((all|your|previous)\s+)+(instructions|rules)
     (?i)print (your )?env(ironment)?
     ```
     The first pattern uses `\s+` because replay 04 breaks the line after "previous". The older pattern `(?i)ignore (all |your |previous )+(instructions|rules)` did not match it.
   - **Everything else Off**, including **Jailbreak**. With Jailbreak on, report 02's proof (`!!python/object/apply:os.system [...]`) was blocked too, so the slop could never be tested and closed with evidence. A bug report's proof describes an attack.
   - **Secrets and every PII detector stay off**, and nothing uses **Redact**. Redaction would change a payload, so its SHA-256 and the sandbox result would no longer match what the reporter sent. Agents never see reporter text anyway.
   - Leave **Assistant** unticked. Switch checks agents' posts (Intake, Reproducer, Skeptic) as the Assistant role, so a User-only policy never blocks them.

   Click **Create policy**. Copy its ID from the **Policy ID** column, or from the **ID:** box on the policy's page. A new account also has a **Baseline Monitoring (Alert)** policy: do not use its ID. Its Alert action adds a "flagged" line to messages.
3. **Settings → Admin → API keys → Create key**: any name, Role **Editor**, an expiration of your choice. The key is shown once, so copy it.
4. In Switch Console, on the server's **Home** page, open **Switch Trust Integration** (server admins only). Fill in:
   - **Switch Trust Endpoint:** `https://api.switchagents.ai`
   - **Guardrails Policy ID:** the policy ID
   - **Switch Trust API key:** the key

   Save. It shows **Monitoring Active**, and the server applies the settings to the next message with no restart. Keep the key and policy ID out of the repository and chat.
5. Post `python scripts/replay.py report 04`. Expect the 🚫 reply in its thread, no ticket, and nothing in Intake's output. switch-core.log shows `[BRIDGE-IN] message from … not relayed — Switch Trust outcome=blocked`. Trust's **Live** page lists the check as **Blocked**.

Limits:
- The text of every human message is sent to Switch Trust's cloud service to be checked, and the start of it shows in Trust's **Live** page.
- Messages with a file attached are not checked.
- If Trust cannot be reached, messages pass with "⚠️ Switch Trust could not check this message" appended (read from Switch's source; not tested live).
- The second pattern also matches a genuine report worded like "the payload makes the app print environment variables". The reporter gets the block notice and can reword it.

To turn Trust off, click **Turn off** in the same Console section.

Prove It works without this step: Intake's screen quarantines replay 04, and even a paraphrased injection only ever reaches the agents as fixed fields.

## 6. Run Intake

```sh
python -m proveit.intake run
```

It should print `Intake is listening in #proveit-intake and the room it links to as 'triage'`. Leave it running.

## 7. Try it

Post a report in `#proveit-intake` from Mattermost, or replay ours as your Mattermost user:

```sh
python scripts/replay.py report 01        # real CVE-2020-14343
python scripts/replay.py report 02        # synthetic slop, no proof: Intake asks for one
python scripts/replay.py followup 02      # the "proof": a safe_load payload
python scripts/replay.py report 03        # synthetic slop: billion laughs
python scripts/replay.py report 04        # injection hidden in an HTML comment
```

In `#proveit-triage`, as a maintainer:

```
@prove-it-reproducer check R-001
@prove-it-reproducer run R-001 on the patched build
@prove-it-skeptic review R-001
@prove-it-intake override R-001 patched build checked
@prove-it-intake escalate R-001 confirmed, CVE-2020-14343
@prove-it-intake close R-002 safe_load refused the tag
@prove-it-intake tally
```

A close can name the reason code whose fixed question the reporter gets: `close R-002 reason=not_reproduced <note>`. Without it, the question comes from the standing dispute or from the evidence. Every replay posts as the same Mattermost user, so after two of its tickets are closed as `NOT_REPRODUCED` that user can have only one open report at a time. Triage then shows the key to use with `@prove-it-intake clear-reporter <key>`.

`!interrupt @prove-it-reproducer` is Switch's room command to stop an agent mid-run (not yet tried by us). It stops the agent, not a sandbox run already started; that one ends within 20 seconds anyway.

Record agent cost per report from Switch ROI or your provider's dashboard: `python -m proveit cost R-001 --usd <amount> --source "<where you read it>"`.

## Without Switch Console

`scripts/switch-server.sh up` runs Switch's published server (0.31.0) and Mattermost on ports 18000/18065, and `python scripts/e2e.py --env-file .proveit/switch-server/.env` replays every report through it and checks the outcomes. There, Intake runs the checks itself through a developer/test flag on `python -m proveit.intake run`, because those rooms have no LLM agents. `scripts/switch-server.sh down` stops it; `reset` also deletes its data.

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| `Could not find Switch Console's local server` | Start the server in Console first, or pass `--env-file` |
| `An agent named prove-it-intake already exists` | `python -m proveit.intake setup --overwrite` |
| Reporter gets "You're not permitted to direct messages to me" | Setup could not open the agent; in Console set prove-it-intake's **Who can talk to your agent** to everyone |
| `Room proveit-intake not found` | Deploy the template, or run setup with `--create-rooms --users <your Mattermost username>` |
| `#proveit-intake has no Switch room link labelled 'triage'` | Deploy the template (it creates the link) or run setup with `--create-rooms` |
| Agents in triage do not answer | Console must stay open; mention them with `@` and the exact name, as the deployer |
| `refused: only humans may override` | You ran it from an agent's shell (`PROVEIT_ACTOR=agent`); run it in your own terminal |
| Anything else | Run `python -m proveit doctor`: it checks Docker, the images, Intake, the rooms, the maintainers, the agents' folders and trust, and says what to fix |
| Template run says `Read timed out` for both rooms, and Mattermost stops answering | Mattermost crashed. On Apple silicon the cause is emulation: Mattermost Team Edition ships for amd64 only, and Colima without Rosetta runs it under QEMU, where it segfaults (seen three times on 2026-11-05). Fix once: `colima stop && colima start --vz-rosetta`, then `docker start` the containers again (they have no restart policy); `python -m proveit doctor` checks this. Docker Desktop: Settings > General > "Use Rosetta for x86_64/amd64 emulation". Right after a crash: `docker restart switchdash-local-mattermost-mattermost-1`, wait for `curl http://127.0.0.1:<port>/api/v4/system/ping`, and run the template again |
| `scripts/replay.py` posts but Intake never answers | It posted into a channel left over from an earlier deployment. Current versions pick the newest channel with that display name; check with `python scripts/replay.py thread 01` |
| The Skeptic's messages show as "admin" in Mattermost | Cosmetic: Switch posts that Codex session under the deployer's Mattermost identity. Switch still tells Intake the sender is `prove-it-skeptic`, which is what Intake checks before recording a verdict (confirmed live on 2026-11-06: Intake logged `triage command from 'prove-it-skeptic'`) |
| Template run fails with "machine '<name>' is not connected to Switch or has not reported recently" | Console's agents controller cannot report. In `switch-console.log` look for `Status report failed ... kill EPERM`: a stale process id from an earlier session now belongs to a protected Windows process (seen on 2026-11-06). Quit Console, open `<app data>/switchdash/agent-controller/servers/<server>/watchers/<agent>/health.json`, set `"pid"` to a number no process uses (it must stay a number), and start Console again |
| Agent never answers; `switch-console.log` says `Could not start agent ... The working directory ... does not exist` | The agent was created with a wrong folder (a typo in the checkout box). Fix **Directory** in the agent's **Configuration**; the controller starts it on the next revision. Messages sent meanwhile are delivered when it starts |
| Room creation fails with `localhost:<port>/api/v4/channels ... actively refused` | Mattermost's container stopped (it has no restart policy; restarting Docker or WSL stops it). `docker start switchdash-local-mattermost-mattermost-1`, wait for `/api/v4/system/ping`, then create the rooms again with the rooms-only template |
| A maintainer's message or a reporter's follow-up gets no reaction from Intake | Seen twice in the 2026-11-06 live run: the message reached Mattermost but Switch never delivered it to Intake (Intake's log has no line for it). Send it again |
| An agent ignores changed instructions | Saving them in the agent's **Configuration** creates a new revision and restarts its idle session; check `switch-console.log` for `Started agent ... revision N`. A dispute recorded before the change stays until a maintainer overrides it |
| Nothing typed in Mattermost reaches Switch; switch-core.log repeats `mattermostdriver.websocket ... timed out during opening handshake` | Seen on 2026-11-06 on Windows. `localhost` resolves to IPv6 `::1` first, and WSL's `networkingMode=mirrored` (in `%USERPROFILE%\.wslconfig`) made `::1:<port>` hang instead of refusing, so the server's websocket to Mattermost timed out. Comment out that line, quit Console, run `wsl --shutdown`, let Docker Desktop restart, `docker start` the Mattermost container, then open Console. The server logs `Websocket authentification OK` once it reconnects |
| Agents work (Intake records the Skeptic's verdict) but their replies never appear in `#proveit-triage`; switch-core.log says `Mattermost post /posts failed: You do not have the appropriate permissions` | Seen on 2026-11-06 after Switch re-created the agents' Mattermost bot accounts during a reconnect: the new bots were not members of the private triage channel. In `#proveit-triage` type `/invite @prove-it-reproducer @prove-it-skeptic` |
| `Refused: only Prove It's maintainers can ...` | Add yourself: `python -m proveit.intake maintainers add <your Mattermost username>`, then restart `python -m proveit.intake run` |
| The Skeptic's `python -m proveit evidence` fails with `No module named proveit` | Seen on 2026-11-07 in a Switch-managed Codex session that did not apply the Codex config's `PYTHONPATH`. Fixed on `feat/second-library`: pull it. `agents/skeptic/proveit/` makes the command work from the Skeptic's folder with no environment. If it still fails, the session is not starting in `agents/skeptic`: check the agent's working folder in Console |

Branch fix pass: update the Skeptic instructions to copy `review=<token>` from `proveit evidence` into every concur/dispute message. A stale token is refused; read the evidence again. These template changes need server validation and a fresh live run. The historical live logs do not verify the new instructions.

For a separate trial of the second branch without replacing the working demo, use [the isolated trial guide](TRIAL.md).
