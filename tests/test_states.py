"""W5: the state machine. Table-driven: every allowed transition, and the illegal ones that matter."""

import unittest

from proveit import states
from proveit.states import IllegalTransition, transition

ALLOWED = [
    # (state, command, actor, target, expected)
    ("new", "receive", "intake", "awaiting_poc", "awaiting_poc"),
    ("new", "receive", "intake", "quarantined", "quarantined"),
    ("new", "receive", "intake", "invalid_proof", "invalid_proof"),
    ("new", "receive", "intake", "in_triage", "in_triage"),
    ("new", "receive", "human", "in_triage", "in_triage"),
    ("awaiting_poc", "followup", "intake", "in_triage", "in_triage"),
    ("awaiting_poc", "followup", "intake", "awaiting_poc", "awaiting_poc"),
    ("awaiting_poc", "followup", "intake", "invalid_proof", "invalid_proof"),
    ("awaiting_poc", "followup", "intake", "quarantined", "quarantined"),
    ("invalid_proof", "followup", "intake", "in_triage", "in_triage"),
    ("quarantined", "release", "human", "in_triage", "in_triage"),
    ("quarantined", "release", "human", "awaiting_poc", "awaiting_poc"),
    ("quarantined", "release", "human", "invalid_proof", "invalid_proof"),
    ("in_triage", "check", "agent", "reproduced", "reproduced"),
    ("in_triage", "check", "agent", "not_reproduced", "not_reproduced"),
    ("in_triage", "check", "human", "in_triage", "in_triage"),          # inconclusive run
    ("in_triage", "check", "intake", "reproduced", "reproduced"),        # developer auto-check
    ("reproduced", "check", "agent", "not_reproduced", "not_reproduced"),
    ("not_reproduced", "check", "human", "reproduced", "reproduced"),
    ("disputed", "check", "agent", "disputed", "disputed"),
    ("reproduced", "check_patched", "agent", None, "reproduced"),
    ("not_reproduced", "check_patched", "human", None, "not_reproduced"),
    ("disputed", "check_patched", "agent", None, "disputed"),
    ("reproduced", "concur", "agent", None, "reproduced"),
    ("not_reproduced", "concur", "agent", None, "not_reproduced"),
    ("reproduced", "dispute", "agent", None, "disputed"),
    ("not_reproduced", "dispute", "human", None, "disputed"),
    ("disputed", "override", "human", "reproduced", "reproduced"),
    ("disputed", "override", "human", "not_reproduced", "not_reproduced"),
    ("reproduced", "override", "human", "reproduced", "reproduced"),  # escalate without a current concur, recorded
    ("reproduced", "escalate", "human", None, "escalated"),
    ("not_reproduced", "escalate", "human", None, "escalated"),
    # Clean runs that disagreed (U1a). Escalating it also needs a current override, checked in actions.
    ("in_triage", "check", "agent", "not_reliably_reproduced", "not_reliably_reproduced"),
    ("reproduced", "check", "agent", "not_reliably_reproduced", "not_reliably_reproduced"),
    ("not_reliably_reproduced", "check", "agent", "reproduced", "reproduced"),
    ("not_reliably_reproduced", "check_patched", "agent", None, "not_reliably_reproduced"),
    ("not_reliably_reproduced", "concur", "agent", None, "not_reliably_reproduced"),
    ("not_reliably_reproduced", "dispute", "agent", None, "disputed"),
    ("disputed", "override", "human", "not_reliably_reproduced", "not_reliably_reproduced"),
    ("not_reliably_reproduced", "override", "human", "not_reliably_reproduced", "not_reliably_reproduced"),
    ("not_reliably_reproduced", "escalate", "human", None, "escalated"),
] + [(s, "close", "human", None, "closed") for s in sorted(states.OPEN)]

ILLEGAL = [
    ("quarantined", "escalate", "human", None, "never be escalated"),
    ("disputed", "escalate", "human", None, "override first"),
    ("in_triage", "escalate", "human", None, "no check has run"),
    ("awaiting_poc", "escalate", "human", None, "cannot escalate"),
    ("invalid_proof", "escalate", "human", None, "cannot escalate"),
    ("reproduced", "escalate", "agent", None, "only humans"),
    ("reproduced", "close", "agent", None, "only humans"),
    ("disputed", "override", "agent", "reproduced", "only humans"),
    ("quarantined", "release", "agent", "in_triage", "only humans"),
    ("quarantined", "check", "agent", "reproduced", "cannot check"),
    ("awaiting_poc", "check", "human", "reproduced", "cannot check"),
    ("disputed", "check", "agent", "reproduced", "cannot move"),        # a re-run never clears a dispute
    ("in_triage", "override", "human", "in_triage", "cannot override"),
    ("in_triage", "dispute", "agent", None, "cannot dispute"),
    ("in_triage", "concur", "agent", None, "cannot concur"),
    ("disputed", "concur", "agent", None, "cannot concur"),
    ("escalated", "close", "human", None, "cannot close"),
    ("closed", "escalate", "human", None, "cannot escalate"),
    ("closed", "close", "human", None, "cannot close"),
    ("in_triage", "check_patched", "agent", None, "cannot check_patched"),
    ("not_reliably_reproduced", "escalate", "agent", None, "only humans"),
    ("not_reliably_reproduced", "override", "agent", "not_reliably_reproduced", "only humans"),
    ("new", "receive", "agent", "in_triage", "only"),
]


class TransitionTable(unittest.TestCase):
    def test_allowed(self):
        for state, command, actor, target, expected in ALLOWED:
            with self.subTest(state=state, command=command, actor=actor):
                self.assertEqual(transition(state, command, actor, target), expected)

    def test_illegal(self):
        for state, command, actor, target, message in ILLEGAL:
            with self.subTest(state=state, command=command, actor=actor):
                with self.assertRaises(IllegalTransition) as ctx:
                    transition(state, command, actor, target)
                self.assertIn(message, str(ctx.exception))

    def test_every_state_is_listed(self):
        for _, sources, targets, _ in states.TABLE:
            for s in sources | (targets - {states.SAME}):
                self.assertIn(s, states.STATES)


if __name__ == "__main__":
    unittest.main()
