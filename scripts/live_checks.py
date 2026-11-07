"""Live checks of Intake's side of the OpenSSF triage and the sqlparse rooms, over a real Switch server.

Runs against the private Switch server from scripts/switch-server.sh (Switch
0.31.0 + Mattermost), with no Switch Console:

  bash scripts/switch-server.sh reset && bash scripts/switch-server.sh up
  python scripts/live_checks.py --env-file .proveit/switch-server/.env --log docs/evidence/live-checks-<date>.log

What is real here: the Switch server and Mattermost, the room templates
(switch/prove-it.rooms.template.yaml and switch/prove-it.sqlparse.rooms.template.yaml,
deployed unmodified through Switch's create_room_from_yaml), the Intake agent,
two separate Mattermost accounts (a reporter and a maintainer listed in
Intake's settings), the sandbox, and every `python -m proveit` command, run
from the agents' own folders (agents/reproducer, agents/skeptic) with no
PYTHONPATH or role variables, exactly as their sessions would.

What is a stand-in, and labelled so in the transcript: the Reproducer and the
Skeptic are registered Switch protocol agents named prove-it-reproducer and
prove-it-skeptic, driven by this script instead of Claude Code and Codex. Their
*choices* are scripted; their messages travel through Switch as agent
messages, so Intake treats them exactly as it treats the real agents. This
does not verify how Claude Code or Codex behave; that needs Switch Console.

Checked (items 2 to 6 of the 2026-11-07 live-trial notes):
  2  a reason-coded dispute is accepted; a code the evidence contradicts is refused;
     closing with a reason gives the reporter the matching fixed question
  3  escalation writes the DRAFT advisory pack and posts its note in triage
  4  two failed proofs limit the reporter to one open report; only a maintainer lifts it
  5  the sqlparse room pair deploys and a sqlparse report runs through Intake,
     the vulnerable and patched checks and the Skeptic's review
  6  the reporter account cannot decide anything, even from inside the triage room
  and item 1's mechanism: `python -m proveit evidence` from agents/skeptic with no environment.

Needs a freshly reset server: the room names are fixed by the templates.
"""

import argparse
import json
import os
import re
import secrets
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

AGENT_ENV_STRIPPED = ("PYTHONPATH", "PROVEIT_ACTOR", "PROVEIT_AGENT", "PROVEIT_HOME", "PROVEIT_PRIVATE_DIR")


class Checks:
    def __init__(self, log_path):
        self.results = []
        self.lines = []
        self.log_path = log_path

    def say(self, text):
        print(text)
        self.lines.append(text)

    def check(self, name, ok, detail=""):
        self.results.append((name, bool(ok)))
        self.say("%s %s%s" % ("PASS" if ok else "FAIL", name, (": " + detail) if detail else ""))
        return ok

    def save(self):
        if self.log_path:
            Path(self.log_path).parent.mkdir(parents=True, exist_ok=True)
            Path(self.log_path).write_text("\n".join(self.lines) + "\n", encoding="utf-8", newline="\n")


def wait_for(predicate, timeout=60, step=1.0):
    end = time.time() + timeout
    while time.time() < end:
        value = predicate()
        if value:
            return value
        time.sleep(step)
    return predicate()


def mm_request(base, method, path, token=None, body=None):
    req = urllib.request.Request(base + "/api/v4" + path, method=method,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Content-Type": "application/json"})
    if token:
        req.add_header("Authorization", "Bearer " + token)
    with urllib.request.urlopen(req, timeout=20) as resp:
        raw = resp.read()
        return json.loads(raw) if raw else None, resp.headers


def link_owner_to_maintainer(api_url, server, mm_url, agent_id, maintainer):
    """As the gateway admin, claim the maintainer's Mattermost identity for the agent's owner."""
    import http.cookiejar
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def gw(method, path, body=None):
        req = urllib.request.Request(api_url.rstrip("/") + "/gateway" + path, method=method,
                                     data=json.dumps(body).encode() if body is not None else None,
                                     headers={"Content-Type": "application/json"})
        with opener.open(req, timeout=20) as resp:
            raw = resp.read()
            return json.loads(raw) if raw else None

    gw("POST", "/auth/login", {"email": server["GATEWAY_ADMIN_EMAIL"], "password": server["GATEWAY_ADMIN_PASSWORD"]})
    owner_id = gw("GET", "/agents/%s" % agent_id)["owner_id"]
    bridge = next(i["bridge_id"] for i in gw("GET", "/auth/me/identities") if i.get("bridge_type") == "mattermost")
    login = mm_request(mm_url, "POST", "/users/login", body={"login_id": maintainer,
                                                              "password": server["MATTERMOST_USER_PASSWORD"]})
    mm_user = login[0]
    gw("POST", "/collaborations/%s/identities" % bridge,
       {"external_user_id": mm_user["id"], "username": maintainer, "user_id": owner_id})
    return owner_id


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--env-file", required=True)
    parser.add_argument("--api-url", default="http://127.0.0.1:18000")
    parser.add_argument("--log", help="write the transcript here (no secrets are printed)")
    args = parser.parse_args()
    out = Checks(args.log)
    tmp = Path(tempfile.mkdtemp(prefix="proveit-live-"))
    work = tmp / "work"
    env = dict(os.environ, PROVEIT_WORK_DIR=str(work), PROVEIT_STATE=str(tmp / "state" / "intake.json"),
               PYTHONUNBUFFERED="1", PYTHONDONTWRITEBYTECODE="1")
    os.environ.update(PROVEIT_WORK_DIR=str(work), PROVEIT_STATE=env["PROVEIT_STATE"])  # before proveit is imported

    from proveit import config, evidence, reasons, store
    from proveit.intake import read_env
    from proveit.switch_client import Agent, SwitchError, register_agent
    from replay import Mattermost
    config.WORK_DIR = work
    server = read_env(args.env_file)
    mm_url = "http://127.0.0.1:%s" % server.get("MATTERMOST_HOST_PORT", "8065")
    maintainer = server["MATTERMOST_USER"]
    out.say("# Prove It live checks against Switch %s (headless, scripts/switch-server.sh), %s" % (
        server.get("SWITCH_VERSION", "?"), time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())))
    out.say("# Reproducer and Skeptic are scripted Switch protocol agents (stand-ins), not Claude Code or Codex.")

    # --- 1. Agents: Intake plus the two stand-ins, under the names the templates use -----------
    for name in ("prove-it-reproducer", "prove-it-skeptic"):
        register_agent(args.api_url, server["AGENT_REGISTRATION_TOKEN"], name, "Scripted stand-in for live checks",
                       display_name=name, overwrite=True)
    stand_in = {}
    for name in ("prove-it-reproducer", "prove-it-skeptic"):
        reg = register_agent(args.api_url, server["AGENT_REGISTRATION_TOKEN"], name, "Scripted stand-in for live checks",
                             display_name=name, overwrite=True)
        stand_in[name] = Agent(args.api_url, reg["id"], reg["api_key"], client_name="proveit-live-checks")
    subprocess.run([sys.executable, "-m", "proveit.intake", "setup", "--env-file", args.env_file, "--api-url",
                    args.api_url, "--agent-name", "prove-it-intake", "--overwrite", "--maintainers", maintainer],
                   cwd=ROOT, env=env, check=True, capture_output=True, text=True)
    state = json.loads(Path(env["PROVEIT_STATE"]).read_text(encoding="utf-8"))
    intake_agent = Agent(state["api_url"], state["agent_id"], state["api_key"])
    out.say("Registered prove-it-intake (maintainers: %s) and the two stand-in agents" % maintainer)

    # --- 2. Deploy the real room templates, unmodified -----------------------------------------
    # A template puts its deployer in the rooms as {$creator}: the Switch user who owns the
    # deploying agent, through their linked Mattermost account. In Console that is the person
    # signed in. An agent registered with the registration token (as here) is owned by the
    # server's bootstrap user, which has no linked account, so the gateway admin links it to the
    # maintainer's Mattermost account first (Switch's "Claim Bridge Identity", an admin action).
    owner_id = link_owner_to_maintainer(args.api_url, server, mm_url, state["agent_id"], maintainer)
    out.say("Linked the deploying agent's owner (%s) to Mattermost account %r, so {$creator} is the maintainer"
            % (owner_id[:8], maintainer))
    if intake_agent.room_id("proveit-intake") or intake_agent.room_id("sqlparse-intake"):
        sys.exit("The rooms already exist on this server. Run: bash scripts/switch-server.sh reset && "
                 "bash scripts/switch-server.sh up")
    for path in ("switch/prove-it.rooms.template.yaml", "switch/prove-it.sqlparse.rooms.template.yaml"):
        doc = (ROOT / path).read_text(encoding="utf-8")
        try:
            result = intake_agent.op("create_room_from_yaml", {"yaml": doc}, timeout=120)
            out.check("template %s deployed by Switch (create_room_from_yaml, unmodified)" % path, bool(result))
        except SwitchError as exc:
            out.check("template %s deployed by Switch" % path, False, "HTTP %s %s" % (exc.status, exc.detail[:300]))
            out.save()
            sys.exit(1)
    rooms = {n: intake_agent.room_id(n) for n in ("proveit-intake", "proveit-triage", "sqlparse-intake", "sqlparse-triage")}
    out.check("all four rooms exist", all(rooms.values()))

    # --- 3. Two separate people: the maintainer (in Intake's list) and a reporter (not) --------
    admin_token = mm_request(mm_url, "POST", "/users/login", body={
        "login_id": server["MATTERMOST_ADMIN_USER"], "password": server["MATTERMOST_ADMIN_PASSWORD"]})[1]["Token"]
    reporter = "reporter-%s" % secrets.token_hex(3)
    reporter_password = "Rp-" + secrets.token_urlsafe(12)
    user, _ = mm_request(mm_url, "POST", "/users", admin_token, {
        "email": "%s@example.invalid" % reporter, "username": reporter, "password": reporter_password})
    team, _ = mm_request(mm_url, "GET", "/teams/name/%s" % server["MATTERMOST_TEAM_NAME"], admin_token)
    mm_request(mm_url, "POST", "/teams/%s/members" % team["id"], admin_token, {"team_id": team["id"], "user_id": user["id"]})
    mm_rep = Mattermost(mm_url, reporter, reporter_password)  # signs the reporter in once, so the bridge knows them
    for room, people in (("proveit-intake", [maintainer, reporter]), ("sqlparse-intake", [maintainer, reporter]),
                         ("proveit-triage", [maintainer]), ("sqlparse-triage", [maintainer])):
        intake_agent.op("add_users_to_room", {"room_id": rooms[room], "user_names": people})
    mm_maint = Mattermost(mm_url, maintainer, server["MATTERMOST_USER_PASSWORD"])
    ch = {"proveit-intake": mm_rep.channel("proveit-intake"), "sqlparse-intake": mm_rep.channel("sqlparse-intake"),
          "proveit-triage": mm_maint.channel("proveit-triage"), "sqlparse-triage": mm_maint.channel("sqlparse-triage")}
    out.check("reporter is not a member of either triage room",
              not any(c["name"] in ("proveit-triage", "sqlparse-triage") for c in mm_rep.call("GET", "/users/me/channels")))
    out.say("People: maintainer %r (listed in Intake's maintainers), reporter %r (a separate account, not listed)"
            % (maintainer, reporter))

    # --- 4. Start Intake; connect the stand-ins to the triage rooms ------------------------------
    log_file = open(tmp / "intake.log", "w")
    intake = subprocess.Popen([sys.executable, "-m", "proveit.intake", "run"], cwd=ROOT, env=env,
                              stdout=log_file, stderr=subprocess.STDOUT)
    try:
        if not wait_for(lambda: "Also serving target sqlparse" in (tmp / "intake.log").read_text(), timeout=90):
            out.say((tmp / "intake.log").read_text()[-2000:])
            out.check("Intake serves the PyYAML and sqlparse room pairs", False)
            out.save()
            sys.exit(1)
        out.check("Intake serves the PyYAML and sqlparse room pairs", True)
        skeptic_conn = {t: stand_in["prove-it-skeptic"].connect(rooms[t], lambda *a: None)
                        for t in ("proveit-triage", "sqlparse-triage")}
        for conn in skeptic_conn.values():
            conn.ready.wait(20)

        def agent_cli(role, *argv):
            agent_env = {k: v for k, v in env.items() if k not in AGENT_ENV_STRIPPED}
            agent_env["PROVEIT_PRIVATE_DIR"] = str(tmp / ".proveit-private")
            proc = subprocess.run([sys.executable, "-m", "proveit"] + list(argv), cwd=ROOT / "agents" / role,
                                  env=agent_env, capture_output=True, text=True, encoding="utf-8", errors="replace",
                                  timeout=180)
            out.say("  [%s stand-in, from agents/%s, no PYTHONPATH] $ python -m proveit %s -> exit %d" % (
                role, role, " ".join(argv), proc.returncode))
            for line in (proc.stdout + proc.stderr).strip().splitlines()[:14]:
                out.say("      " + line)
            return proc

        def skeptic_reads(tid):
            proc = agent_cli("skeptic", "evidence", tid)
            token = re.search(r"review token: ([0-9a-f]{16})", proc.stdout)
            out.check("item 1 mechanism: Skeptic reads %s's evidence from its folder with no environment" % tid,
                      proc.returncode == 0 and token and "No module named" not in proc.stderr)
            return token.group(1) if token else ""

        def skeptic_says(triage, text):
            out.say("  [prove-it-skeptic stand-in in #%s] %s" % (triage, text))
            skeptic_conn[triage].post(text)

        def maintainer_says(triage, text, who=None):
            who = who or mm_maint
            out.say("  [%s in #%s] %s" % ("maintainer" if who is mm_maint else "REPORTER", triage, text))
            who.post(ch[triage], text)

        def triage_posts(triage):
            data = mm_maint.call("GET", "/channels/%s/posts?per_page=200" % ch[triage])
            return [data["posts"][i]["message"] for i in reversed(data["order"])]

        def reporter_thread(intake_room, root):
            data = mm_rep.call("GET", "/posts/%s/thread" % root)
            return [p["message"] for p in sorted(data["posts"].values(), key=lambda p: p["create_at"]) if p["id"] != root]

        def ticket_for(root):
            def find():
                for record in store.all_tickets():
                    contact = store.load_private_json(record["id"], "contact.json")
                    if contact.get("message_id") and contact.get("intake_thread") and record.get("status") != "new":
                        if root in (contact.get("message_id"), contact.get("intake_thread")):
                            return record
                return None
            return wait_for(find, timeout=20) or wait_for(lambda: store.all_tickets()[-1] if store.all_tickets() else None, 5)

        def post_report(room, path, root_id=None):
            text = (ROOT / path).read_text(encoding="utf-8")
            post = mm_rep.post(ch[room], text, root_id=root_id)
            out.say("  [REPORTER in #%s] posted %s%s" % (room, Path(path).name, " in its thread" if root_id else ""))
            return post["id"]

        def newest_ticket(before):
            return wait_for(lambda: [t for t in store.all_tickets() if t["id"] not in before] or None, 20)

        def seen(triage, needle, timeout=30):
            return wait_for(lambda: any(needle in m for m in triage_posts(triage)), timeout)

        # --- A. PyYAML: reason-coded dispute, refusal, patched check, override, escalate, advisory pack
        out.say("\n== A. Items 2 and 3: real CVE-2020-14343 (PyYAML)")
        before = {t["id"] for t in store.all_tickets()}
        root01 = post_report("proveit-intake", "reports/replays/01-real-cve-2020-14343.md")
        r1 = (newest_ticket(before) or [{}])[0].get("id")
        out.check("01 became a ticket in triage", r1 and seen("proveit-triage", "**Ticket %s**" % r1))
        agent_cli("reproducer", "check", r1)
        out.check("%s reproduced on the vulnerable build (3/3)" % r1, store.load(r1)["status"] == "reproduced")
        token = skeptic_reads(r1)
        skeptic_says("proveit-triage", "@prove-it-intake dispute %s not_reproduced review=%s" % (r1, token))
        out.check("a dispute code the evidence contradicts is refused",
                  seen("proveit-triage", "Refused dispute for %s" % r1) and store.load(r1)["status"] == "reproduced",
                  next((m for m in triage_posts("proveit-triage") if "Refused dispute for %s" % r1 in m), "")[:200])
        skeptic_says("proveit-triage", "@prove-it-intake dispute %s patched_not_checked review=%s" % (r1, token))
        out.check("a valid reason-coded dispute is recorded",
                  wait_for(lambda: store.load(r1)["status"] == "disputed", 20)
                  and (store.load(r1).get("skeptic") or {}).get("code") == "patched_not_checked")
        maintainer_says("proveit-triage", "@prove-it-intake escalate %s" % r1)
        out.check("escalate is refused while disputed", seen("proveit-triage", "Refused escalate for %s" % r1)
                  and store.load(r1)["status"] == "disputed")
        agent_cli("reproducer", "check", r1, "--build", "patched")
        maintainer_says("proveit-triage", "@prove-it-intake override %s patched build checked: fixed in 5.4" % r1)
        wait_for(lambda: store.load(r1)["status"] == "reproduced", 20)
        maintainer_says("proveit-triage", "@prove-it-intake escalate %s confirmed, CVE-2020-14343" % r1)
        out.check("%s escalated" % r1, wait_for(lambda: store.load(r1)["status"] == "escalated", 30))
        out.check("triage shows the DRAFT advisory note", seen("proveit-triage", "Advisory pack for %s (DRAFT" % r1))
        pack = work / r1 / "advisory"
        files = sorted(p.name for p in pack.glob("*")) if pack.exists() else []
        out.check("advisory files exist in the work folder", {"osv-draft.json", "ghsa-draft.md", "timeline.md"} <= set(files),
                  ", ".join(files))
        payload = store.payload(r1)
        report_text = (ROOT / "reports/replays/01-real-cve-2020-14343.md").read_text(encoding="utf-8")
        blob = "".join((pack / f).read_text(encoding="utf-8") for f in files) if files else ""
        out.check("advisory pack holds no payload and no reporter prose",
                  blob and payload.strip() not in blob and "bypasses the fix for CVE-2020-1747" not in blob
                  and "__import__" not in blob)
        osv = json.loads((pack / "osv-draft.json").read_text(encoding="utf-8")) if "osv-draft.json" in files else {}
        out.say("  osv-draft.json: id=%s, affected=%s" % (osv.get("id"), json.dumps(osv.get("affected"))[:160]))
        out.check("reporter told in their thread", wait_for(
            lambda: any("confirmed by a maintainer" in m for m in reporter_thread("proveit-intake", root01)), 20))

        # --- B. Close with a reason code -> the reporter's fixed question; the reporter limit; identities
        out.say("\n== B. Items 2, 4 and 6: slop reports, the reporter's question, the reporter limit")
        before = {t["id"] for t in store.all_tickets()}
        root02 = post_report("proveit-intake", "reports/replays/02-slop-safe-load-rce.md")
        r2 = (newest_ticket(before) or [{}])[0].get("id")
        wait_for(lambda: store.load(r2)["status"] == "awaiting_poc", 15)
        post_report("proveit-intake", "reports/replays/02-slop-safe-load-rce.followup.md", root_id=root02)
        out.check("02 reached triage after its proof", wait_for(lambda: store.load(r2)["status"] == "in_triage", 30))
        agent_cli("reproducer", "check", r2)
        out.check("%s not reproduced" % r2, store.load(r2)["status"] == "not_reproduced")
        skeptic_says("proveit-triage", "@prove-it-intake concur %s review=%s" % (r2, skeptic_reads(r2)))
        out.check("a concur with a current review token is recorded",
                  wait_for(lambda: (store.load(r2).get("skeptic") or {}).get("verdict") == "concur", 20))
        maintainer_says("proveit-triage", "@prove-it-intake close %s reason=not_reproduced safe_load refused the tag" % r2)
        wait_for(lambda: store.load(r2)["status"] == "closed", 20)
        expected_q = reasons.question("not_reproduced", store.load(r2), evidence.latest_run(store.load(r2), "vulnerable"))
        got = wait_for(lambda: [m for m in reporter_thread("proveit-intake", root02) if "Question from the maintainers" in m], 20)
        out.check("the reporter gets the fixed question for reason=not_reproduced",
                  got and expected_q and expected_q in got[-1], expected_q or "")

        before = {t["id"] for t in store.all_tickets()}
        post_report("proveit-intake", "reports/replays/03-slop-billion-laughs.md")
        r3 = (newest_ticket(before) or [{}])[0].get("id")
        wait_for(lambda: store.load(r3)["status"] == "in_triage", 20)
        agent_cli("reproducer", "check", r3)
        skeptic_says("proveit-triage", "@prove-it-intake concur %s review=%s" % (r3, skeptic_reads(r3)))
        wait_for(lambda: (store.load(r3).get("skeptic") or {}).get("verdict") == "concur", 20)
        maintainer_says("proveit-triage", "@prove-it-intake close %s no exhaustion in 3 clean runs" % r3)
        out.check("%s closed" % r3, wait_for(lambda: store.load(r3)["status"] == "closed", 20))

        before = {t["id"] for t in store.all_tickets()}
        post_report("proveit-intake", "reports/replays/01-real-cve-2020-14343.md")
        r4 = (newest_ticket(before) or [{}])[0].get("id")
        out.check("with no open report the reporter can still file one (%s)" % r4,
                  wait_for(lambda: store.load(r4)["status"] == "in_triage", 20))
        before = {t["id"] for t in store.all_tickets()}
        limited_root = post_report("proveit-intake", "reports/replays/03-slop-billion-laughs.md")
        notice = seen("proveit-triage", "is limited to one open report")
        key_line = next((m for m in triage_posts("proveit-triage") if "is limited to one open report" in m), "")
        key12 = (re.search(r"Reporter ([0-9a-f]{6,})", key_line) or [None, ""])[1]
        out.check("after two failed proofs a second open report is refused", notice and key12
                  and {t["id"] for t in store.all_tickets()} == before
                  and wait_for(lambda: any("one open report" in m for m in reporter_thread("proveit-intake", limited_root)), 20),
                  key_line[:160])
        rec = json.loads((tmp / ".proveit-private" / "reporters.json").read_text(encoding="utf-8")) \
            if (tmp / ".proveit-private" / "reporters.json").exists() else {}
        sources = sorted({str(v.get("id_source")) for v in (rec.get("reporters", rec) or {}).values() if isinstance(v, dict)})
        out.say("  proof record identity source used by Switch 0.31.0 for human messages: %s" % (", ".join(sources) or "?"))

        # Item 6: the reporter account cannot decide, even from inside the triage room.
        intake_agent.op("add_users_to_room", {"room_id": rooms["proveit-triage"], "user_names": [reporter]})
        mm_rep_triage = mm_rep.channel("proveit-triage")
        ch["proveit-triage-as-reporter"] = mm_rep_triage
        out.say("  (negative probe: the reporter account is added to #proveit-triage to try maintainer commands)")
        for text in ("@prove-it-intake clear-reporter %s" % key12, "@prove-it-intake close %s not a bug" % r4,
                     "@prove-it-intake escalate %s" % r4):
            out.say("  [REPORTER in #proveit-triage] " + text)
            mm_rep.post(mm_rep_triage, text)
        out.check("reporter account's clear-reporter / close / escalate are refused",
                  wait_for(lambda: sum("is not one of them" in m for m in triage_posts("proveit-triage")) >= 3, 30)
                  and store.load(r4)["status"] == "in_triage")
        maintainer_says("proveit-triage", "@prove-it-intake clear-reporter %s" % key12)
        out.check("a maintainer lifts the limit", seen("proveit-triage", "limit lifted by %s" % maintainer))
        before = {t["id"] for t in store.all_tickets()}
        post_report("proveit-intake", "reports/replays/03-slop-billion-laughs.md")
        out.check("after clear-reporter the reporter can file again", newest_ticket(before))

        # --- C. sqlparse in its own rooms
        out.say("\n== C. Item 5: sqlparse CVE-2023-30608 in #sqlparse-intake / #sqlparse-triage")
        before = {t["id"] for t in store.all_tickets()}
        root_sql = post_report("sqlparse-intake", "reports/replays/sqlparse/101-real-cve-2023-30608.md")
        rs = (newest_ticket(before) or [{}])[0].get("id")
        out.check("the sqlparse report became a sqlparse ticket in #sqlparse-triage",
                  rs and wait_for(lambda: store.load(rs).get("target") == "sqlparse", 10)
                  and seen("sqlparse-triage", "**Ticket %s**" % rs))
        agent_cli("reproducer", "check", rs)
        vuln = evidence.latest_run(store.load(rs), "vulnerable") or {}
        out.check("sqlparse 0.4.3: RESOURCE_EXHAUSTION", vuln.get("outcome") == "RESOURCE_EXHAUSTION", vuln.get("why", ""))
        agent_cli("reproducer", "check", rs, "--build", "patched")
        patched = evidence.latest_run(store.load(rs), "patched") or {}
        out.check("sqlparse 0.4.4: NOT_REPRODUCED", patched.get("outcome") == "NOT_REPRODUCED")
        skeptic_says("sqlparse-triage", "@prove-it-intake concur %s review=%s" % (rs, skeptic_reads(rs)))
        out.check("the Skeptic's review is recorded from #sqlparse-triage",
                  wait_for(lambda: (store.load(rs).get("skeptic") or {}).get("verdict") == "concur", 20))
        maintainer_says("sqlparse-triage", "@prove-it-intake escalate %s confirmed, CVE-2023-30608" % rs)
        out.check("%s escalated with its advisory note in #sqlparse-triage" % rs,
                  wait_for(lambda: store.load(rs)["status"] == "escalated", 30)
                  and seen("sqlparse-triage", "Advisory pack for %s (DRAFT" % rs))
        out.check("the sqlparse reporter is told in their thread", wait_for(
            lambda: any("confirmed by a maintainer" in m for m in reporter_thread("sqlparse-intake", root_sql)), 20))

        out.say("\n== Transcript: #proveit-triage")
        for m in triage_posts("proveit-triage"):
            out.say("  | " + m.replace("\n", "\n  | ")[:700])
        out.say("\n== Transcript: #sqlparse-triage")
        for m in triage_posts("sqlparse-triage"):
            out.say("  | " + m.replace("\n", "\n  | ")[:700])
    finally:
        intake.terminate()
        log_file.close()

    failed = [n for n, ok in out.results if not ok]
    out.say("\n%d checks, %d passed, %d failed" % (len(out.results), len(out.results) - len(failed), len(failed)))
    out.say("LIVE CHECKS PASSED" if not failed else "LIVE CHECKS FAILED: %s" % "; ".join(failed))
    out.save()
    if failed:
        print("\nIntake log tail:\n" + (tmp / "intake.log").read_text()[-3000:])
        sys.exit(1)


if __name__ == "__main__":
    main()
