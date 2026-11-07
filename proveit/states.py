"""The ticket state machine: one table, enforced by every command.

Actors:
  intake  the Intake agent (our code) handling reporter messages
  agent   the Reproducer or Skeptic (an LLM), via the CLI with PROVEIT_ACTOR=agent
  human   a maintainer: in the triage room (Intake checks the sender is a person)
          or on the host's command line

"Code decides, agents argue, humans rule": a check's evidence sets
reproduced / not_reproduced, agents may concur or dispute, and only a human
can escalate, close, release or override.
"""

SAME = "(unchanged)"
TERMINAL = {"escalated", "closed"}
STATES = ["new", "awaiting_poc", "quarantined", "invalid_proof", "in_triage", "reproduced",
          "not_reproduced", "not_reliably_reproduced", "disputed", "escalated", "closed"]
OPEN = set(STATES) - TERMINAL - {"new"}
# A check's clean runs disagreed (decision D-012). It can be reviewed and closed, but escalated
# only after a maintainer's override on the evidence it has now (actions.review_problem).
UNRELIABLE = "not_reliably_reproduced"
CHECKED = {"reproduced", "not_reproduced", UNRELIABLE}
CHECK_RESULTS = {"reproduced", "not_reproduced", UNRELIABLE}

# (command, from states, to states, actors)
TABLE = [
    ("receive", {"new"}, {"awaiting_poc", "quarantined", "invalid_proof", "in_triage"}, {"intake", "human"}),
    ("followup", {"awaiting_poc", "invalid_proof"}, {"awaiting_poc", "quarantined", "invalid_proof", "in_triage"}, {"intake"}),
    ("release", {"quarantined"}, {"awaiting_poc", "invalid_proof", "in_triage"}, {"human"}),
    ("check", {"in_triage"}, CHECK_RESULTS | {SAME}, {"agent", "human", "intake"}),
    ("check", CHECKED, CHECK_RESULTS | {SAME}, {"agent", "human", "intake"}),
    ("check", {"disputed"}, {SAME}, {"agent", "human", "intake"}),  # new evidence never clears a dispute
    ("check_patched", CHECKED | {"disputed"}, {SAME}, {"agent", "human", "intake"}),
    ("concur", CHECKED, {SAME}, {"agent", "human"}),
    ("dispute", CHECKED, {"disputed"}, {"agent", "human"}),
    ("dispute", {"disputed"}, {SAME}, {"agent", "human"}),  # a later dispute replaces the reason code
    # After a dispute it clears it; on a checked ticket with no current concur it lets a maintainer escalate anyway.
    ("override", {"disputed"}, CHECK_RESULTS, {"human"}),
    ("override", CHECKED, {SAME}, {"human"}),
    # From not_reliably_reproduced only with a current override (checked in actions, where the evidence is known).
    ("escalate", CHECKED, {"escalated"}, {"human"}),
    ("close", OPEN, {"closed"}, {"human"}),
]
COMMANDS = sorted({row[0] for row in TABLE})


class IllegalTransition(Exception):
    pass


def transition(state, command, actor, target=None):
    """Return the state after `command`, or raise IllegalTransition with a clear reason."""
    rows = [row for row in TABLE if row[0] == command]
    if not rows:
        raise IllegalTransition("unknown command %r" % command)
    actors = set().union(*(row[3] for row in rows))
    if actor not in actors:
        raise IllegalTransition("only %s may %s a ticket" % (" or ".join(sorted(a + "s" for a in actors)), command))
    row = next((r for r in rows if state in r[1]), None)
    if row is None:
        hint = ""
        if command == "escalate" and state == "disputed":
            hint = "; the Skeptic disputed it, so a maintainer must run override first"
        elif command == "escalate" and state == "quarantined":
            hint = "; a quarantined report can never be escalated"
        elif command == "escalate" and state == "in_triage":
            hint = "; no check has run yet"
        raise IllegalTransition("cannot %s a ticket that is %s%s" % (command, state.replace("_", " "), hint))
    if actor not in row[3]:
        raise IllegalTransition("%ss may not %s a ticket that is %s" % (actor, command, state.replace("_", " ")))
    targets = row[2]
    if target is None or target == state and SAME in targets:
        if target is None and len(targets) == 1:
            only = next(iter(targets))
            return state if only == SAME else only
        if target is None:
            raise IllegalTransition("%s from %s needs a target state" % (command, state))
        return state
    if target not in targets:
        raise IllegalTransition("%s cannot move a ticket from %s to %s" % (command, state, target))
    return target
