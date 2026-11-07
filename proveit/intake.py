"""The Intake agent: Prove It's own Switch agent, built on the agent protocol.

It sits in two linked rooms:

  #proveit-intake   anyone can post a report here. Intake is the only agent
                    in the room, and it runs no code and has no shell.
  #proveit-triage   maintainers, the Reproducer (Claude Code) and the Skeptic
                    (Codex). Intake finds this room through the intake room's
                    Switch link labelled "triage", posts tickets of fixed
                    fields here, and relays maintainers' decisions back to
                    the reporter's thread.

It deliberately has no language model. The one component that reads
attacker-controlled prose is plain code: it screens the text, demands a
proof in the data-only format (entry point + YAML payload), and hands
triage a ticket with no reporter text in it.

  python -m proveit.intake setup   register the agent with a Switch server
  python -m proveit.intake run     connect to the rooms and work
"""

import argparse
import functools
import json
import logging
import os
import re
import sys
import threading
from pathlib import Path

from . import actions, config, evidence, messages, reasons, reports, reputation, screen, states, store, targets
from .config import LEGACY_STATE_DIR, PROVEIT_HOME, ensure_home
from .switch_client import Agent, CursorStore, SwitchError, open_to_everyone, register_agent

log = logging.getLogger("proveit.intake")
STATE_FILE = Path(os.environ.get("PROVEIT_STATE") or PROVEIT_HOME / "intake.json")
LEGACY_STATE_FILE = LEGACY_STATE_DIR / "intake.json"
TRIAGE_LINK_LABEL = "triage"
# Decisions only the maintainers listed in the state file may make.
HUMAN_ONLY = ("escalate", "close", "release", "override", "notify", "clear-reporter")
# Verdicts only the Skeptic agent (or a maintainer) may record.
VERDICTS = ("concur", "dispute")

DEFAULTS = {
    "agent_name": "prove-it-intake",
    "intake_room": "proveit-intake",
    "triage_room": "proveit-triage",
    "reproducer": "prove-it-reproducer",
    "skeptic": "prove-it-skeptic",
}


# --------------------------------------------------------------------------
# Finding the Switch server Console runs, so nobody copies secrets by hand.
# --------------------------------------------------------------------------
def console_env_candidates():
    home = Path.home()
    roots = [Path(os.environ.get("APPDATA", home / "AppData" / "Roaming")),
             home / "Library" / "Application Support",
             Path(os.environ.get("XDG_CONFIG_HOME", home / ".config"))]
    found = []
    for root in roots:
        if root.exists():
            found.extend(root.glob("*/local-switch-server/.env"))
            found.extend(root.glob("*/local-switch-server/native/run/switch-core.env"))
    return found


def read_env(path):
    values = {}
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            key, _, value = line.partition("=")
            values[key.strip()] = value.strip().strip('"')
    return values


def split_names(text):
    """'alice, @bob' -> ['alice', 'bob']"""
    return [n.strip().lstrip("@") for n in (text or "").split(",") if n.strip().lstrip("@")]


def move_legacy_state():
    """Older versions kept Intake's credentials in the checkout's .proveit/; move them out of the agents' reach."""
    if not os.environ.get("PROVEIT_STATE") and not STATE_FILE.exists() and LEGACY_STATE_FILE.exists():
        ensure_home()
        LEGACY_STATE_FILE.replace(STATE_FILE)
        _private_file(STATE_FILE)
        log.info("moved %s to %s", LEGACY_STATE_FILE, STATE_FILE)


def _private_file(path):
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def load_state():
    move_legacy_state()
    if not STATE_FILE.exists():
        sys.exit("No agent registered yet. Run: python -m proveit.intake setup")
    return json.loads(STATE_FILE.read_text(encoding="utf-8"))


def save_state(state):
    if STATE_FILE.parent == config.PROVEIT_HOME:
        ensure_home()
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, indent=2), encoding="utf-8")
    _private_file(STATE_FILE)


def cmd_setup(args):
    from .trial import plan
    trial = plan(args.trial) if getattr(args, "trial", None) else None
    if trial and not (Path(trial["folder"]) / "trial.json").is_file():
        sys.exit("Prepare the trial first: python -m proveit.trial " + args.trial)
    if trial and args.create_rooms:
        sys.exit("For a trial, deploy only its generated templates; they keep triage private")
    if trial and (args.agent_name != DEFAULTS["agent_name"] or any(getattr(args, key) for key in
            ("intake_room", "triage_room", "reproducer", "skeptic"))):
        sys.exit("--trial supplies isolated agent/room names; do not combine it with name overrides")
    env_file = args.env_file
    if not env_file:
        candidates = console_env_candidates()
        if not candidates:
            sys.exit("Could not find Switch Console's local server. Start it in Switch Console "
                     "(Add a server > Run a server on this computer), or pass --env-file.")
        env_file = str(candidates[0])
    env = read_env(env_file)
    api_url = args.api_url or "http://127.0.0.1:%s" % env.get("API_HOST_PORT", env.get("SERVER_PORT", "8000"))
    token = env.get("AGENT_REGISTRATION_TOKEN")
    if not token:
        sys.exit("%s has no AGENT_REGISTRATION_TOKEN" % env_file)
    print("Switch server: %s (settings from %s)" % (api_url, env_file))

    name = trial["agent_name"] if trial else args.agent_name
    try:
        reg = register_agent(api_url, token, name,
                             "Prove It intake: screens bug reports and asks for a runnable proof before any human reads them.",
                             display_name="Prove It Intake", overwrite=args.overwrite)
    except SwitchError as exc:
        if exc.status == 409:
            sys.exit("An agent named %s already exists. Re-run with --overwrite to replace its key." % name)
        raise
    print("Registered agent %s (%s)" % (name, reg["id"]))

    if env.get("GATEWAY_ADMIN_EMAIL") and env.get("GATEWAY_ADMIN_PASSWORD"):
        open_to_everyone(api_url, env["GATEWAY_ADMIN_EMAIL"], env["GATEWAY_ADMIN_PASSWORD"], reg["id"])
        print("Opened %s to everyone in its rooms, so reporters can reach it" % name)
    else:
        print("WARNING: no Gateway admin login in %s. In Switch Console, set this agent's "
              "'Who can talk to your agent' to everyone." % env_file)

    state = dict(DEFAULTS, agent_name=name, api_url=api_url, agent_id=reg["id"], api_key=reg["api_key"])
    if trial:
        state.update({key: trial[key] for key in ("agent_name", "reproducer", "skeptic", "intake_room", "triage_room",
                                                   "target_rooms", "agent_directories")})
        state["trial"] = args.trial
    for key in ("intake_room", "triage_room", "reproducer", "skeptic"):
        if getattr(args, key):
            state[key] = getattr(args, key)
    state["maintainers"] = split_names(args.maintainers)
    save_state(state)
    print("Saved credentials to %s (outside the checkout, never committed)" % STATE_FILE)
    if state["maintainers"]:
        print("Maintainers who may decide: %s" % ", ".join(state["maintainers"]))
    else:
        print("WARNING: no maintainers set, so Intake will refuse every escalate/close/override/release. "
              "Add yours: python -m proveit.intake maintainers add <your Mattermost username>")

    if args.create_rooms:
        agent = Agent(api_url, reg["id"], reg["api_key"])
        users = args.users.split(",") if args.users else None
        intake = agent.room_id(state["intake_room"]) or agent.create_room(
            state["intake_room"], "Report a security bug here. Prove It asks for a runnable proof before any maintainer reads it.",
            [name], users)["id"]
        triage_agents = [name] + [a for a in (state["reproducer"], state["skeptic"]) if a and args.with_agents]
        triage = agent.room_id(state["triage_room"]) or agent.create_room(
            state["triage_room"], "Maintainers and agents: tickets arrive here with proof, not opinions.",
            triage_agents, users)["id"]
        try:
            agent.link_rooms(intake, triage, TRIAGE_LINK_LABEL)
        except SwitchError as exc:
            print("note: could not link rooms (%s)" % exc)
        print("Rooms ready: %s, %s (linked as %r)" % (state["intake_room"], state["triage_room"], TRIAGE_LINK_LABEL))
    print("\nNext: python -m proveit.intake%s run" % (" --trial " + args.trial if trial else ""))


# --------------------------------------------------------------------------
# The agent
# --------------------------------------------------------------------------
def ticket_from_record(record):
    """Rebuild the parse result for a stored ticket (its payload lives in private/)."""
    return reports.Ticket(claim=record.get("claim", ""), severity=record.get("severity", "unrated"),
                          entry_point=record.get("entry_point", ""), payload=store.payload(record["id"]),
                          poc_problem=record.get("poc_problem", ""), missing=list(record.get("missing", [])),
                          out_of_scope_entry=record.get("out_of_scope_entry", ""),
                          affected_version=record.get("affected_version", ""),
                          target=record.get("target", "") or ticket_target_key(record))


def fill(record, ticket, target=None):
    """Copy only fixed fields from a parsed ticket into the agent-readable record.

    `target` (or the record's own `target`, else PyYAML) decides the out-of-scope
    names, the tag reader and the tested version. The ticket records its target.
    """
    from . import poc
    target = target or targets.for_record(record)
    record.update({
        "target": target.key,
        "claim": ticket.claim, "severity": ticket.severity, "entry_point": ticket.entry_point,
        "poc_problem": ticket.poc_problem, "missing": ticket.missing,
        "out_of_scope_entry": ticket.out_of_scope_entry if ticket.out_of_scope_entry in target.out_of_scope_names else (
            "an unsafe loader" if ticket.out_of_scope_entry else ""),
        "payload_sha256": poc.sha256(ticket.payload) if ticket.payload else None,
        "payload_bytes": len(ticket.payload.encode("utf-8", "surrogatepass")) if ticket.payload else 0,
        "tags": target.tags(ticket.payload),
        # Normalized by reports.parse_version; only the pinned builds are ever tested (decision D-016).
        "affected_version": reports.parse_version(ticket.affected_version),
        "tested_version": target.vulnerable_version,
    })
    if ticket.payload:
        store.set_payload(record["id"], ticket.payload)


def ticket_target_key(record):
    return (record or {}).get("target") or targets.DEFAULT_KEY


def target_for(ticket):
    if ticket.poc_problem:
        return "invalid_proof"
    if ticket.missing:
        return "awaiting_poc"
    return "in_triage"


class Handled:
    """Message ids Intake has already handled, so a message delivered twice is acted on once."""

    KEEP = 5000

    def __init__(self, path=None):
        self.path = Path(path) if path else None
        self.lock = threading.Lock()
        self.ids = []
        if self.path and self.path.exists():
            try:
                self.ids = json.loads(self.path.read_text(encoding="utf-8"))
            except ValueError:
                log.warning("ignoring unreadable %s", self.path)
        self.set = set(self.ids)

    def __contains__(self, message_id):
        return message_id in self.set

    def add(self, message_id):
        if not message_id or message_id in self.set:
            return
        with self.lock:
            self.ids.append(message_id)
            self.set.add(message_id)
            if len(self.ids) > self.KEEP:
                dropped = self.ids[:-self.KEEP]
                self.ids = self.ids[-self.KEEP:]
                self.set.difference_update(dropped)
            if self.path:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                tmp = self.path.with_name(self.path.name + ".tmp")
                tmp.write_text(json.dumps(self.ids), encoding="utf-8")
                os.replace(str(tmp), str(self.path))


class Intake:
    VERBS = "escalate|close|release|override|notify|concur|dispute|evidence|status|tally|clear-reporter"
    # A command is the text right after the @mention: "@prove-it-intake dispute R-001 patched_not_checked".
    COMMAND = re.compile(r"[\s:,]*(%s)\b\s*(R-\d{3,})?\s*(.*)" % VERBS, re.I | re.S)

    def __init__(self, state, auto_check=False, source="switch", state_dir=None):
        self.state = state
        # Saved next to the state file when running for real; in memory for tests and the rehearsal.
        self.state_dir = Path(state_dir) if state_dir else None
        key = state.get("agent_id", "local")
        self.handled = Handled(self.state_dir / ("handled-%s.json" % key) if self.state_dir else None)
        self.cursors = CursorStore(self.state_dir / ("cursors-%s.json" % key) if self.state_dir else None)
        self.failed_log = self.state_dir / "failed-events.jsonl" if self.state_dir else None
        self.agent = Agent(state["api_url"], state["agent_id"], state["api_key"]) if state.get("api_url") else None
        self.auto_check = auto_check
        self.source = source
        self.names = {state["agent_name"]}
        self.maintainers = {n.lower() for n in state.get("maintainers") or []}
        skeptic = state.get("skeptic", DEFAULTS["skeptic"])
        self.skeptic_names = {n.lower() for n in [skeptic, "Prove It Skeptic"] + list(state.get("skeptic_names") or [])}
        self.lock = threading.RLock()
        self.warned_fallback = False  # one warning per run when `sender` is missing
        self.intake = None   # the default (PyYAML) intake room: anything with .post(body, thread_id=None)
        self.triage = None   # the default (PyYAML) triage room
        # target key -> (intake_room, triage_room). Filled by start() (C3) or by the
        # library-2 rehearsal; the default PyYAML pair is self.intake / self.triage.
        self.pairs = {}
        self._reply = None   # the triage room the current command came from (set per command)
        self._command_id = None

    # -- helpers -------------------------------------------------------------
    def pair(self, target):
        """The (intake_room, triage_room) a target's reports and tickets use.

        Defaults to the PyYAML pair, so single-room setups and PyYAML are unchanged.
        """
        key = target.key if hasattr(target, "key") else (target or targets.DEFAULT_KEY)
        return self.pairs.get(key, (self.intake, self.triage))

    def mention(self):
        return "@" + self.state["agent_name"]

    def is_maintainer(self, name):
        return bool(name) and name.lstrip("@").lower() in self.maintainers

    def is_self(self, payload):
        return payload.get("sender_name") in self.names

    @staticmethod
    def is_system(payload):
        return payload.get("sender_kind") == "platform" and not payload.get("on_behalf_of")

    @staticmethod
    def is_agent(payload):
        return payload.get("sender_kind") == "agent" or str(payload.get("sender", "")).startswith("@switch-agent")

    def linked_room(self, conn, label):
        for link in self.agent.op("list_linked_rooms", {}, connection_id=conn.id) or []:
            if link.get("label") == label:
                return link.get("target_room_id")
        return None

    def start(self):
        detail = self.agent.op("get_agent_detail", {"agent_id": self.agent.id}) or {}
        for key in ("name", "display_name"):
            if detail.get(key):
                self.names.add(detail[key])
        intake_id = self.agent.room_id(self.state["intake_room"])
        if not intake_id:
            sys.exit("Room %s not found or %s is not in it. Deploy switch/prove-it.template.yaml in Switch Console, "
                     "or run setup with --create-rooms." % (self.state["intake_room"], self.state["agent_name"]))
        self.intake = self.agent.connect(intake_id, self.on_intake_event, cursors=self.cursors, failed_log=self.failed_log)
        if not self.intake.ready.wait(20):
            sys.exit("Could not open the event stream for room %s" % intake_id)
        # The triage room is wherever the intake room's Switch link labelled "triage" points.
        triage_id = self.linked_room(self.intake, TRIAGE_LINK_LABEL)
        if not triage_id:
            sys.exit("#%s has no Switch room link labelled %r, so Intake does not know where to send tickets. "
                     "Deploy switch/prove-it.template.yaml (it creates the link) or run setup with --create-rooms."
                     % (self.state["intake_room"], TRIAGE_LINK_LABEL))
        if self.state.get("trial") and self.agent.room_id(self.state["triage_room"]) != triage_id:
            sys.exit("The trial intake links outside its expected triage room; refusing to connect")
        self.triage = self.agent.connect(triage_id, self.on_triage_event, cursors=self.cursors, failed_log=self.failed_log)
        if not self.triage.ready.wait(20):
            sys.exit("Could not open the event stream for room %s" % triage_id)
        log.info("Intake is listening in #%s and the room it links to as %r", self.state["intake_room"], TRIAGE_LINK_LABEL)
        self.pairs[targets.DEFAULT_KEY] = (self.intake, self.triage)
        self.start_extra_targets()
        self.resume_pending()
        threading.Thread(target=self._retry_pending, name="proveit-delivery", daemon=True).start()

    def _retry_pending(self):
        while not self.agent._stop.wait(5):
            self.resume_pending()

    def resume_pending(self):
        """Recover committed reports/decisions after reconnects and process restarts."""
        with self.lock:
            for record in store.all_tickets():
                if not store.load_private_json(record["id"], "contact.json").get("intake_thread"):
                    continue  # CLI-only tickets have no reporter to notify
                try:
                    with store.ticket_lock(record["id"]):
                        record = store.load(record["id"])
                        if record["status"] == "new":
                            contact = store.load_private_json(record["id"], "contact.json")
                            self.new_report({"body": store.private_path(record["id"], "report.md").read_text(encoding="utf-8"),
                                "message_id": contact["message_id"], "sender_name": contact["reporter"]},
                                targets.for_record(record))
                            record = store.load(record["id"])
                        if record.get("intake_delivery"):
                            self.deliver_report(record)
                        if record["status"] in states.TERMINAL:
                            if record.get("decision_effects_pending"):
                                record = actions.finish_decision(record["id"])
                            if record.get("notified") is False:
                                self._reply = self.pair(targets.for_record(record))[1]
                                self.tell_reporter(record["id"], "", None)
                except Exception:
                    log.exception("pending work for %s will be retried", record["id"])

    def start_extra_targets(self):
        """Also serve any registered non-default target whose rooms exist (U4, C3).

        Each extra room pair's callbacks are bound to its target, so a report's
        target comes only from the room it arrived in. A target whose intake room
        is absent is skipped with one warning -- PyYAML keeps working (the live
        fallback): the sqlparse rooms are deployed from a separate template, so a
        Console that has only the main template serves PyYAML alone.
        """
        for target in targets.TARGETS.values():
            if target.key == targets.DEFAULT_KEY:
                continue
            from .trial import room_names
            intake_name, triage_name = room_names(self.state, target)
            extra_intake_id = self.agent.room_id(intake_name)
            if not extra_intake_id:
                log.warning("room #%s for target %s not found; not serving it (PyYAML is unaffected). Deploy "
                            "switch/prove-it.%s.rooms.template.yaml to enable it.",
                            intake_name, target.key, target.key)
                continue
            intake_conn = self.agent.connect(extra_intake_id, functools.partial(self.on_intake_event, target=target),
                                             cursors=self.cursors, failed_log=self.failed_log)
            if not intake_conn.ready.wait(20):
                sys.exit("Could not open the event stream for room %s" % extra_intake_id)
            extra_triage_id = self.linked_room(intake_conn, TRIAGE_LINK_LABEL)
            if not extra_triage_id:
                sys.exit("#%s has no Switch room link labelled %r, so Intake cannot serve target %s."
                         % (intake_name, TRIAGE_LINK_LABEL, target.key))
            if target.key in (self.state.get("target_rooms") or {}) and self.agent.room_id(triage_name) != extra_triage_id:
                sys.exit("#%s links to an unexpected triage room; expected #%s" % (intake_name, triage_name))
            triage_conn = self.agent.connect(extra_triage_id, functools.partial(self.on_triage_event, target=target),
                                             cursors=self.cursors, failed_log=self.failed_log)
            if not triage_conn.ready.wait(20):
                sys.exit("Could not open the event stream for room %s" % extra_triage_id)
            self.pairs[target.key] = (intake_conn, triage_conn)
            log.info("Also serving target %s in #%s and its linked triage room", target.key, intake_name)

    # -- #proveit-intake -----------------------------------------------------
    def on_intake_event(self, conn, kind, frame, target=None):
        """A message in an intake room. `target` is the library that room serves
        (the PyYAML default here; bound per room in start(), and set by the
        library-2 rehearsal). A report's target comes only from its room, never
        from the reporter's text."""
        if kind != "message":
            return
        lib = targets.get(target.key if hasattr(target, "key") else target)
        payload = frame["payload"]
        if self.is_self(payload) or self.is_system(payload) or not payload.get("body", "").strip():
            return
        with self.lock:
            if payload.get("message_id") in self.handled:
                log.info("message %s already handled; ignoring the repeat", payload.get("message_id"))
                return
            thread = payload.get("thread_id")
            if thread and thread != payload["message_id"]:
                record = store.find_by_thread(thread)
                if record:
                    self.followup(record, payload)
                self.handled.add(payload.get("message_id"))
                return  # a reply in a thread that is not a report is ignored
            self.new_report(payload, lib)
            self.handled.add(payload.get("message_id"))

    def new_report(self, payload, lib=None):
        lib = lib or targets.PYYAML
        intake_room, triage_room = self.pair(lib)
        text, thread = payload["body"], payload["message_id"]
        record = store.find_by_thread(thread)
        if record and record["status"] != "new":
            with store.ticket_lock(record["id"]):
                self.deliver_report(store.load(record["id"]))
            return
        if record:
            contact = store.load_private_json(record["id"], "contact.json")
            key, source = contact.get("reporter_key"), contact.get("id_source")
        else:
            key, source = self.reporter_key(payload)
        if not record and key and reputation.is_limited(key):
            open_ = reputation.open_tickets(key)
            if open_:
                # Decision D-018: one open report at a time. The new report's text is not stored anywhere.
                intake_room.post(messages.limited_reporter(open_), thread)
                triage_room.post(messages.limited_notice(reputation.short(key), reputation.get(key)["invalid"]))
                return
        result = screen.screen(text)
        ticket = reports.parse(text, lib)
        if record is None:
            record = store.create({"target": lib.key}, text, source=self.source, contact={
                "intake_thread": thread, "reporter": payload.get("sender_name", "unknown"),
                "message_id": payload.get("message_id"), "reporter_key": key, "id_source": source})
        with store.ticket_lock(record["id"]):
            store.save_private_json(record["id"], "contact.json",
                                    {"intake_thread": thread, "reporter": payload.get("sender_name", "unknown"),
                                     "message_id": payload.get("message_id"), "reporter_key": key, "id_source": source})
            fill(record, ticket, lib)
            record["last_intake_message"] = payload.get("message_id")
            if result.blocked:
                self.quarantine(record, result, thread, "receive", lib)
                return
            self.route(record, ticket, thread, "receive", lib=lib)

    def reporter_key(self, payload):
        """The reporter's HMAC key and which field it came from, or (None, None) (decision D-018)."""
        value, source = reputation.identity(payload)
        if value is None:
            return None, None
        if source == "sender_name" and not self.warned_fallback:
            self.warned_fallback = True
            log.warning("a reporter's message has no Switch participant id (`sender`); the proof record falls back "
                        "to the display name (`sender_name`) for this run")
        return reputation.key_for(value), source

    def count_invalid(self, record):
        """One strike per ticket at most, for a proof Intake rejected (decision D-018)."""
        if record.get("counted_invalid"):
            return
        contact = store.load_private_json(record["id"], "contact.json")
        if contact.get("reporter_key"):
            reputation.add(contact["reporter_key"], contact.get("id_source"), "invalid")
            record["counted_invalid"] = True

    def quarantine(self, record, result, thread, command, lib=None):
        lib = lib or targets.for_record(record)
        intake_room, triage_room = self.pair(lib)
        record["screen_rules"] = sorted({f["rule"] for f in result.findings})
        store.save_private_json(record["id"], "screen.json", result.findings)
        record["intake_delivery"] = {"status": "quarantined", "reporter": False, "triage": False}
        store.apply(record, command, "intake", "intake", target="quarantined")
        self.deliver_report(record)

    def route(self, record, ticket, thread, command, actor="intake", by="intake", lib=None):
        lib = lib or targets.for_record(record)
        intake_room, triage_room = self.pair(lib)
        state = target_for(ticket)  # the next ticket state, not the library target
        if state == "invalid_proof":
            self.count_invalid(record)  # saved by apply below
        record["intake_delivery"] = {"status": state, "reporter": False, "triage": state not in ("in_triage", "quarantined")}
        store.apply(record, command, actor, by, target=state)
        self.deliver_report(record)
        if state == "in_triage" and self.auto_check:
            threading.Thread(target=self.run_auto_check, args=(record["id"],), daemon=True).start()

    def deliver_report(self, record):
        """Send only unfinished parts of a committed routing operation.

        Receipts are saved after each successful post. An HTTP success followed by
        a lost response can still duplicate a message: the Switch operation has no
        idempotency key. This is at-least-once delivery, not exactly-once delivery.
        """
        delivery = record.get("intake_delivery")
        if not delivery or all(delivery.get(k) for k in ("reporter", "triage")):
            return
        lib = targets.for_record(record)
        intake_room, triage_room = self.pair(lib)
        ticket, thread = ticket_from_record(record), self.reporter_thread(record)
        state, errors = delivery["status"], []
        if not delivery["reporter"]:
            if state == "quarantined":
                body = messages.quarantined(record["id"])
            elif state == "invalid_proof":
                body = messages.invalid_proof(record["id"], ticket.poc_problem, record.get("out_of_scope_entry"), lib)
            elif state == "awaiting_poc":
                body = messages.ask_for_proof(record["id"], ticket, lib)
            else:
                body = messages.accepted(record["id"], ticket.claim, lib)
            try:
                intake_room.post(body, thread)
                delivery["reporter"] = True
                store.save(record)
            except Exception as exc:
                errors.append(exc)
        if not delivery["triage"]:
            try:
                body = messages.quarantine_notice(record, self.mention()) if state == "quarantined" else messages.ticket_posted(record)
                triage_room.post(body)
                delivery["triage"] = True
                store.save(record)
            except Exception as exc:
                errors.append(exc)
        if errors:
            raise errors[0]

    def followup(self, record, payload):
        with store.ticket_lock(record["id"]):
            self._followup(store.load(record["id"]), payload)

    def _followup(self, record, payload):
        lib = targets.for_record(record)
        intake_room, _ = self.pair(lib)
        contact = store.load_private_json(record["id"], "contact.json")
        thread = contact.get("intake_thread")
        sender = payload.get("sender_name", "")
        if sender.lower() != str(contact.get("reporter", "")).lower():
            self.foreign_reply(record, payload, thread)
            return
        if record.get("last_intake_message") == payload.get("message_id"):
            self.deliver_report(record)
            return
        self.deliver_report(record)  # finish an earlier reply before replacing its proof
        if record["status"] not in ("awaiting_poc", "invalid_proof"):
            intake_room.post("%s is %s. A maintainer will reply in this thread." % (
                record["id"], record["status"].replace("_", " ")), thread)
            return
        text = payload["body"]
        store.append_report(record["id"], text)
        result = screen.screen(text)
        merged = reports.merge(ticket_from_record(record), text, lib)
        fill(record, merged, lib)
        record["last_intake_message"] = payload.get("message_id")
        if result.blocked:
            self.quarantine(record, result, thread, "followup", lib)
            return
        self.route(record, merged, thread, "followup", lib=lib)

    def foreign_reply(self, record, payload, thread):
        """Decision D-008: only the original reporter completes a report. Someone else's reply in the
        thread changes nothing; it is kept privately for maintainers and counted in the ticket."""
        import hashlib
        intake_room, triage_room = self.pair(targets.for_record(record))
        text = payload.get("body", "")
        foreign = store.load_private_json(record["id"], "foreign.json") or {"replies": []}
        foreign["replies"].append({"sender": payload.get("sender_name", "unknown"), "message_id": payload.get("message_id"),
                                   "at": store.now(), "sha256": hashlib.sha256(text.encode("utf-8", "replace")).hexdigest(),
                                   "text": text})
        store.save_private_json(record["id"], "foreign.json", foreign)
        with store.ticket_lock(record["id"]):
            fresh = store.load(record["id"])
            fresh["foreign_replies"] = len(foreign["replies"])
            store.event(fresh, "foreign_reply_ignored", "intake")
            store.save(fresh)
        intake_room.post(messages.foreign_reply(record["id"]), thread)
        triage_room.post(messages.foreign_reply_notice(record["id"], len(foreign["replies"])))

    def run_auto_check(self, ticket_id):
        """Developer/test mode only: Intake runs the vulnerable-build check itself, labelled as such."""
        triage_room = self.pair(targets.for_record(store.load(ticket_id)))[1]
        try:
            record, run, _ = actions.check(ticket_id, "vulnerable", actor="intake", by="intake (auto-check)")
            triage_room.post(messages.auto_check(record, run))
        except Exception as exc:
            log.exception("auto-check failed")
            triage_room.post("Automatic check for %s failed: %s" % (ticket_id, type(exc).__name__))

    # -- #proveit-triage -----------------------------------------------------
    def on_triage_event(self, conn, kind, frame, target=None):
        if kind != "message":
            return
        payload = frame["payload"]
        if self.is_self(payload) or self.is_system(payload):
            return
        body = payload.get("body", "")
        if not any(("@" + n) in body for n in self.names):
            return
        if payload.get("message_id") in self.handled:
            log.info("message %s already handled; ignoring the repeat", payload.get("message_id"))
            return
        self.handle_command(payload, target)
        self.handled.add(payload.get("message_id"))

    def parse_command(self, body):
        """A standalone command after Intake's mention; ignore prose and Markdown examples."""
        fenced = None
        for line in (body or "").splitlines():
            fence = re.match(r"^\s*(`{3,}|~{3,})", line)
            if fence:
                marker = fence.group(1)[0]
                if fenced is None:
                    fenced = marker
                elif marker == fenced:
                    fenced = None
                continue
            if fenced is not None or line.startswith(("    ", "\t")):
                continue
            for name in sorted(self.names, key=len, reverse=True):
                mention = re.match(r"^\s*@%s\b(.*)$" % re.escape(name), line, flags=re.I)
                if not mention:
                    continue
                match = self.COMMAND.match(mention.group(1))
                if match:
                    return match
        return None

    def is_skeptic(self, payload):
        return self.is_agent(payload) and payload.get("sender_name", "").lstrip("@").lower() in self.skeptic_names

    def handle_command(self, payload, cmd_target=None):
        body, thread = payload.get("body", ""), payload.get("thread_id")
        match = self.parse_command(body)
        log.info("triage command from %r (kind %s): %s", payload.get("sender_name"), payload.get("sender_kind"),
                 match.group(1).lower() if match else "none")
        with self.lock:
            # Replies go to the triage room the command came from. A ticket is found by
            # id regardless of room, so a maintainer can decide a ticket from either
            # triage room (humans rule, decision D-022); the reporter is always told in
            # the ticket's own intake room (tell_reporter).
            self._reply = self.pair(cmd_target)[1]
            self._command_id = payload.get("message_id")
            if not match and self.is_agent(payload):
                return  # never answer an agent's chatter with help text: two agents could loop
            if not match:
                self._reply.post("Commands: `escalate R-001 [note]`, `close R-001 [reason=<code>] <note>`, "
                                 "`override R-001 [note]`, `release R-001`, `notify R-001`, `clear-reporter <key>`, "
                                 "`evidence R-001`, `status`, "
                                 "`tally`; from the Skeptic: `concur R-001`, `dispute R-001 <reason_code> [note]` "
                                 "(codes: %s)." % reasons.code_list(), thread)
                return
            verb, ticket_id, rest = match.group(1).lower(), match.group(2), match.group(3).strip()
            human_only = verb in HUMAN_ONLY
            who = payload.get("sender_name", "")
            if verb in VERDICTS and not (self.is_skeptic(payload) or (not self.is_agent(payload) and self.is_maintainer(who))):
                # Switch tells Intake who sent a message, so only the real Skeptic (or a maintainer) records a verdict.
                self._reply.post("Refused: only @%s or a maintainer records a verdict (%s), and @%s is neither."
                                 % (self.state.get("skeptic", "prove-it-skeptic"), verb, who or "?"), thread)
                return
            if human_only and self.is_agent(payload):
                # Only people decide; agents' opinions stay opinions.
                self._reply.post("Refused: only maintainers can %s a ticket, and that request came from an agent." % verb, thread)
                return
            if human_only and not self.is_maintainer(who):
                # Being in the room is not enough: only the maintainers listed in Intake's settings decide.
                if self.maintainers:
                    self._reply.post("Refused: only Prove It's maintainers can %s a ticket, and @%s is not one of them. "
                                     "A maintainer can add you on the host: `python -m proveit.intake maintainers add %s`."
                                     % (verb, who or "?", who or "<name>"), thread)
                else:
                    self._reply.post("Refused: no maintainers are configured, so nobody can %s yet. On the host run "
                                     "`python -m proveit.intake maintainers add <your Mattermost username>`." % verb, thread)
                return
            if verb == "status":
                self._reply.post(self.status_text(), thread)
                return
            if verb == "tally":
                self._reply.post(actions.tally_text(), thread)
                return
            if verb == "clear-reporter":
                self.do_clear_reporter(who, rest, thread)
                return
            if not ticket_id:
                self._reply.post("Which ticket? For example `%s %s R-001`." % (self.mention(), verb), thread)
                return
            try:
                record = store.load(ticket_id)
            except FileNotFoundError:
                self._reply.post("There is no ticket %s." % ticket_id, thread)
                return
            try:
                if verb in VERDICTS:
                    getattr(self, "do_" + verb)(record, who, rest, thread,
                                                actor="agent" if self.is_agent(payload) else "human")
                else:
                    getattr(self, "do_" + verb)(record, who, rest, thread)
            except states.IllegalTransition as exc:
                self._reply.post("Refused %s for %s: %s." % (verb, ticket_id, exc), thread)

    def do_clear_reporter(self, who, rest, thread):
        """`clear-reporter <hmac12>`: a maintainer lifts a reporter's one-open-report limit (decision D-018)."""
        try:
            key, _ = reputation.clear(rest.split()[0] if rest.split() else "")
        except ValueError as exc:
            self._reply.post("Refused clear-reporter: %s." % exc, thread)
            return
        self._reply.post("Reporter %s: limit lifted by %s (invalid count reset to 0)." % (reputation.short(key), who), thread)

    def reporter_thread(self, record):
        return store.load_private_json(record["id"], "contact.json").get("intake_thread")

    def do_concur(self, record, who, note, thread, actor="agent"):
        review, note = self.verdict_review(note, actor)
        record = actions.concur(record["id"], actor, who, review=review)
        self._reply.post("%s: %s concurs with the evidence; status %s." % (
            record["id"], who, record["status"].replace("_", " ")), thread)

    def do_dispute(self, record, who, rest, thread, actor="agent"):
        """`dispute R-001 <reason_code> [internal note]` (decision D-013). Nothing here reaches the reporter."""
        review, rest = self.verdict_review(rest, actor)
        parts = rest.split(None, 1)
        code, note = (parts + ["", ""])[:2]
        record = actions.dispute(record["id"], code, actor, who, note, review=review)
        self._reply.post(messages.dispute_recorded(record), thread)

    @staticmethod
    def verdict_review(text, actor):
        matches = list(re.finditer(r"(?:^|\s)review=([0-9a-f]{16})(?=\s|$)", text or ""))
        if actor == "agent" and len(matches) != 1:
            raise states.IllegalTransition("read evidence first and include exactly one review=<token> from that evidence pack")
        if len(matches) > 1:
            raise states.IllegalTransition("include exactly one review=<token>")
        if not matches:
            return None, text
        match = matches[0]
        return match.group(1), (text[:match.start()] + " " + text[match.end():]).strip()

    def do_evidence(self, record, who, note, thread):
        self._reply.post("```\n%s\n```" % evidence.text(evidence.pack(record)), thread)

    def do_release(self, record, who, note, thread):
        with store.ticket_lock(record["id"]):
            record = store.load(record["id"])
            ticket = ticket_from_record(record)
            self.route(record, ticket, self.reporter_thread(record), "release", actor="human", by=who)
        self._reply.post("%s released by %s; it is now %s." % (record["id"], who, store.load(record["id"])["status"].replace("_", " ")), thread)

    def do_override(self, record, who, note, thread):
        record = actions.override(record["id"], "human", who, note)
        self._reply.post(actions.override_text(record), thread)

    def do_escalate(self, record, who, note, thread):
        record = actions.decide(record["id"], "escalate", "human", who, note, request_id=self._command_id)
        try:
            self._reply.post("%s escalated by %s. Telling the reporter." % (record["id"], who), thread)
        finally:
            if not store.load(record["id"]).get("notified"):
                self.tell_reporter(record["id"], "", thread)
        if record.get("advisory_error"):
            self._reply.post("%s: decision saved; advisory generation failed (%s) and will be retried." % (
                record["id"], record["advisory_error"]), thread)
        else:
            self._reply.post(messages.advisory_note(record["id"]), thread)

    CLOSE_REASON = re.compile(r"^reason=(\S*)\s*(.*)$", re.I | re.S)

    def do_close(self, record, who, rest, thread):
        """`close R-001 [reason=<code>] <note>`: the code picks the reporter's question (decision D-014)."""
        match = self.CLOSE_REASON.match(rest)
        reason, note = (match.group(1), match.group(2)) if match else (None, rest)
        record = actions.decide(record["id"], "close", "human", who, note, reason=reason, request_id=self._command_id)
        asked = " with the question for %s" % record["decision_question"] if record.get("decision_question") else ""
        try:
            self._reply.post("%s closed by %s. Telling the reporter%s." % (record["id"], who, asked), thread)
        finally:
            if not store.load(record["id"]).get("notified"):
                self.tell_reporter(record["id"], "", thread)

    def tell_reporter(self, ticket_id, note, thread):
        """Post the decision in the reporter's thread and record whether it arrived.

        The decision is saved first; if the post fails, the ticket says so and a
        maintainer can resend it with `notify`, instead of the reporter never hearing.
        """
        with store.ticket_lock(ticket_id):
            record = store.load(ticket_id)
            if note:
                record["decision_note"] = note
            # Always the ticket's own intake room, even if the command came from the other triage room.
            reporter_intake = self.pair(targets.for_record(record))[0]
            try:
                reporter_intake.post(messages.decision(record, record.get("decision_note", "")), self.reporter_thread(record))
            except Exception as exc:
                record["notified"] = False
                store.event(record, "notify_failed", "intake", error=type(exc).__name__)
                store.save(record)
                log.exception("could not tell the reporter about %s", ticket_id)
                self._reply.post("%s: the decision is recorded, but telling the reporter failed (%s). Resend it with "
                                 "`%s notify %s`." % (ticket_id, type(exc).__name__, self.mention(), ticket_id), thread)
                return False
            record["notified"] = True
            store.event(record, "notified", "intake")
            store.save(record)
            return True

    def do_notify(self, record, who, note, thread):
        if record["status"] not in states.TERMINAL:
            raise states.IllegalTransition("%s has no decision to send yet; it is %s" % (
                record["id"], record["status"].replace("_", " ")))
        again = record.get("notified") is True
        if self.tell_reporter(record["id"], "", thread):
            self._reply.post("%s: the decision was sent to the reporter%s." % (record["id"], " again" if again else ""), thread)

    @staticmethod
    def status_text():
        tickets = store.all_tickets()
        if not tickets:
            return "No tickets yet."
        return "\n".join("- **%s** %s · %s · `%s`" % (r["id"], r["status"].replace("_", " "), r.get("claim") or "?",
                                                      r.get("entry_point") or "-") for r in tickets)


def cmd_maintainers(args):
    state = load_state()
    current = list(state.get("maintainers") or [])
    names = split_names(",".join(args.names))
    if args.action in ("add", "remove") and not names:
        sys.exit("Give one or more Mattermost usernames.")
    if args.action == "add":
        current += [n for n in names if n.lower() not in {c.lower() for c in current}]
    elif args.action == "remove":
        current = [c for c in current if c.lower() not in {n.lower() for n in names}]
    if args.action != "list":
        state["maintainers"] = current
        save_state(state)
        print("Saved. Restart `python -m proveit.intake run` for the change to apply.")
    print("Maintainers: %s" % (", ".join(current) or "none (every decision is refused)"))


def cmd_run(args):
    from . import sandbox
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    state = load_state()
    if args.auto_check:
        if not sandbox.docker_available():
            sys.exit("--auto-check needs Docker running")
        sandbox.build()
    intake = Intake(state, auto_check=args.auto_check, state_dir=STATE_FILE.parent)
    intake.start()
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        intake.agent.stop()


def main(argv=None):
    parser = argparse.ArgumentParser(prog="python -m proveit.intake", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--trial", help="use only this trial's isolated names, credentials, tickets and private files")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("setup", help="register the Intake agent with a Switch server")
    p.add_argument("--env-file", help="the server's .env (default: find Switch Console's local server)")
    p.add_argument("--api-url", help="Switch API URL (default: from the .env)")
    p.add_argument("--agent-name", default=DEFAULTS["agent_name"])
    p.add_argument("--overwrite", action="store_true", help="replace an existing agent of the same name")
    for key in ("intake_room", "triage_room", "reproducer", "skeptic"):
        p.add_argument("--" + key.replace("_", "-"), dest=key)
    p.add_argument("--create-rooms", action="store_true", help="create and link the two rooms (without the template)")
    p.add_argument("--with-agents", action="store_true", help="with --create-rooms, also add the reproducer and skeptic")
    p.add_argument("--users", help="with --create-rooms, comma-separated usernames to add")
    p.add_argument("--maintainers", help="comma-separated Mattermost usernames allowed to escalate, close, override "
                                         "and release (you, the deployer, at least)")
    p.set_defaults(fn=cmd_setup)
    p = sub.add_parser("maintainers", help="list, add or remove the people allowed to decide")
    p.add_argument("action", choices=["list", "add", "remove"], nargs="?", default="list")
    p.add_argument("names", nargs="*", help="Mattermost usernames")
    p.set_defaults(fn=cmd_maintainers)
    p = sub.add_parser("run", help="connect to the rooms and work")
    p.add_argument("--auto-check", action="store_true",
                   help="DEVELOPER/TEST ONLY: Intake runs the vulnerable-build check itself (used by scripts/e2e.py "
                        "when no Reproducer agent is in the room). Not part of the demo flow.")
    p.set_defaults(fn=cmd_run)
    args = parser.parse_args(argv)
    if args.trial:
        from .trial import activate
        global STATE_FILE
        try:
            STATE_FILE = Path(activate(args.trial)["state_file"])
        except ValueError as exc:
            parser.error(str(exc))
    args.fn(args)


if __name__ == "__main__":
    main()
