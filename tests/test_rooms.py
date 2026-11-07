"""Two rooms, one Intake (U4, C3): the same Intake serves PyYAML and sqlparse.

No Docker: these exercise routing, ids, the shared reporter record and cross-room
commands at the report/command level, not the sandbox.
"""

import unittest

from proveit import intake, reputation, store, targets
from tests.helpers import FakeRoom, WorkDirTest

SQL_PROOF = ("Claimed impact: denial of service\n"
             "affected_version: 0.4.3\n"
             "entry_point: parse\n"
             "payload: |\n"
             "  '" + ("\\" * 42) + "\n"
             "expected: fast\nactual: hang\n")


class TwoRooms(WorkDirTest):
    def two_room_intake(self):
        agent = intake.Intake({"agent_name": "prove-it-intake", "maintainers": ["maintainer"]}, source="test")
        agent.intake, agent.triage = FakeRoom(), FakeRoom()          # PyYAML (default) pair
        self.sql_intake, self.sql_triage = FakeRoom(), FakeRoom()    # sqlparse pair
        agent.pairs = {"pyyaml": (agent.intake, agent.triage),
                       "sqlparse": (self.sql_intake, self.sql_triage)}
        self._n = 0
        return agent

    def post(self, agent, text, target_key=None, sender="reporter", thread=None):
        self._n = getattr(self, "_n", 0) + 1
        mid = "m%d" % self._n
        agent.on_intake_event(None, "message", {"payload": {
            "body": text, "message_id": mid, "thread_id": thread, "sender_name": sender,
            "sender": "@%s:test" % sender, "sender_kind": "user"}}, target=targets.get(target_key))
        return mid

    def say(self, agent, text, target_key=None, sender="maintainer", kind="user"):
        self._n = getattr(self, "_n", 0) + 1
        payload = {"body": text, "message_id": "t%d" % self._n, "thread_id": None,
                   "sender_name": sender, "sender_kind": kind}
        agent.on_triage_event(None, "message", {"payload": payload}, target=targets.get(target_key))

    def test_target_comes_from_the_room_not_the_text(self):
        agent = self.two_room_intake()
        # The very same proof is sqlparse in the sqlparse room (accepted) and not a
        # valid PyYAML proof in the PyYAML room (parse is not a PyYAML entry point).
        self.post(agent, SQL_PROOF, target_key="sqlparse")
        self.post(agent, SQL_PROOF, target_key="pyyaml")
        r1, r2 = store.load("R-001"), store.load("R-002")
        self.assertEqual(r1["target"], "sqlparse")
        self.assertEqual(r1["status"], "in_triage")
        self.assertEqual(r1["entry_point"], "parse")
        self.assertEqual(r2["target"], "pyyaml")
        self.assertEqual(r2["poc_problem"], "unknown_entry_point")   # "parse" is not a PyYAML loader
        # The sqlparse ticket's posts went to the sqlparse rooms, not the PyYAML ones.
        self.assertIn("R-001", self.sql_triage.text())
        self.assertNotIn("R-001", agent.triage.text())

    def test_ticket_ids_are_one_global_sequence(self):
        agent = self.two_room_intake()
        self.post(agent, SQL_PROOF, target_key="pyyaml")      # R-001 (pyyaml)
        self.post(agent, SQL_PROOF, target_key="sqlparse")    # R-002 (sqlparse)
        self.assertEqual(store.load("R-002")["target"], "sqlparse")
        self.assertEqual(sorted(r["id"] for r in store.all_tickets()), ["R-001", "R-002"])

    def test_reporter_record_is_shared_across_rooms(self):
        agent = self.two_room_intake()
        # One reporter, a rejected proof in each room: both strikes land on the same key.
        bad = "Claimed impact: denial of service\naffected_version: 0.4.3\nentry_point: nope\n```sql\nSELECT 1\n```\n"
        self.post(agent, bad, target_key="sqlparse", sender="alice")
        self.post(agent, "RCE\naffected_version: 5.3.1\nentry_point: unsafe_load\n```yaml\na: 1\n```\n",
                  target_key="pyyaml", sender="alice")
        key = reputation.key_for("@alice:test")
        self.assertEqual(reputation.get(key)["invalid"], 2)
        self.assertTrue(reputation.is_limited(key))

    def test_a_maintainer_decides_a_ticket_from_the_other_triage_room(self):
        # Humans rule (decision D-022): a command about a sqlparse ticket is accepted in the
        # PyYAML triage room; the ack lands there, the reporter is told in the sqlparse intake room.
        agent = self.two_room_intake()
        self.post(agent, SQL_PROOF, target_key="sqlparse")          # R-001, sqlparse
        self.say(agent, "@prove-it-intake close R-001 reason=not_reproduced not a real hang",
                 target_key="pyyaml", sender="maintainer")
        self.assertEqual(store.load("R-001")["status"], "closed")
        self.assertIn("R-001 closed", agent.triage.text())          # ack in the room the maintainer used
        self.assertNotIn("R-001 closed", self.sql_triage.text())
        self.assertIn("closed by a maintainer", self.sql_intake.text())   # reporter told in the ticket's room

    def test_pair_falls_back_to_default_when_a_target_is_not_wired(self):
        # Live fallback: with no sqlparse pair wired, a sqlparse lookup returns the default pair.
        agent = intake.Intake({"agent_name": "prove-it-intake"}, source="test")
        agent.intake, agent.triage = FakeRoom(), FakeRoom()
        agent.pairs = {"pyyaml": (agent.intake, agent.triage)}
        self.assertEqual(agent.pair(targets.get("sqlparse")), (agent.intake, agent.triage))


if __name__ == "__main__":
    unittest.main()
